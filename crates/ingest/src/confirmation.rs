//! EVM deposit confirmation tracking and reorg detection.
//!
//! Stellar deposits credit on sight (`crates/ingest/src/lib.rs`'s top-of-file guarantees) because
//! Stellar finality is instant. EVM blocks reorg, so an EVM deposit is recorded `pending` /
//! `detected` (via [`octo_store::Store::record_evm_deposit`], called by whatever component scans
//! for incoming transfers) and only becomes spendable once this tracker has seen `confirmation_depth`
//! confirmations without the chain reorging it away.
//!
//! Each tick, per EVM wallet, this does two things in order:
//!
//! 1. **Reorg detection**: extend the wallet's verified `evm_block_headers` chain from its saved
//!    cursor up to the current tip, checking parent-hash continuity at every step. A same-height
//!    or mid-walk hash mismatch triggers a **bounded** backward walk for the last common ancestor;
//!    deposits at or after that ancestor are marked `orphaned` (never deleted) and reported.
//! 2. **Confirmation progress**: every deposit still in `detected`/`confirming` gets its
//!    `confirmations` recomputed against the (now-verified) tip and is promoted to `confirmed`
//!    (spendable) at `confirmation_depth`, firing `deposit.confirmed`.
//!
//! Security (see `docs/threat-model.md`): the window between a deposit landing and reaching
//! `confirmation_depth` is the exploitable window this whole module exists to close — crediting
//! (i.e. counting toward a spendable balance) only ever happens at `status = 'confirmed'`, which
//! only this tracker sets for EVM rows.
#![forbid(unsafe_code)]

use crate::evm_rpc::{BlockHeader, EvmRpcClient, EvmRpcError};
use crate::LastPollTracker;
use octo_store::{Store, StoreError, Transaction, Wallet};
use octo_webhooks::{Event, WebhookSender};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Errors from a confirmation-tracker tick.
#[derive(Debug, thiserror::Error)]
pub enum ConfirmationError {
    #[error("store error")]
    Store(#[from] StoreError),
    #[error("evm rpc error")]
    Rpc(#[from] EvmRpcError),
    #[error("wallet is not an evm wallet or has no confirmation policy configured")]
    NotEvmWallet,
}

/// Outcome of the reorg-detection half of a tick.
#[derive(Debug)]
enum SyncOutcome {
    /// Cursor is caught up to (or already matches) the tip; no reorg.
    Synced,
    /// A reorg was found and handled: deposits at/after `ancestor + 1` were orphaned.
    ReorgHandled {
        orphaned: Vec<Transaction>,
        ancestor: i64,
    },
    /// A divergence was found but the common ancestor lies deeper than `reorg_rewind_bound` (or
    /// deeper than our recorded header history) — refuses to guess and alerts instead of looping.
    BoundExceeded,
}

/// Outcome of one full tracker tick for one wallet, returned for logging/metrics.
#[derive(Debug)]
pub enum TickOutcome {
    Synced { promoted: usize },
    Reorged { orphaned: usize, ancestor: i64 },
    DeepReorgAlert,
}

/// The confirmation tracker for one EVM wallet.
pub struct ConfirmationTracker {
    store: Store,
    rpc: EvmRpcClient,
    wallet_id: Uuid,
    webhooks: Option<WebhookSender>,
    tracker: Option<LastPollTracker>,
}

impl ConfirmationTracker {
    pub fn new(store: Store, rpc_url: &str, wallet_id: Uuid) -> Self {
        Self {
            store,
            rpc: EvmRpcClient::new(rpc_url),
            wallet_id,
            webhooks: None,
            tracker: None,
        }
    }

    pub fn new_with_resilience(
        store: Store,
        rpc_url: &str,
        wallet_id: Uuid,
        retry: octo_resilience::RetryPolicy,
        circuit: octo_resilience::CircuitBreaker,
    ) -> Self {
        Self {
            store,
            rpc: EvmRpcClient::with_resilience(rpc_url, retry, circuit),
            wallet_id,
            webhooks: None,
            tracker: None,
        }
    }

    pub fn with_webhooks(mut self, sender: WebhookSender) -> Self {
        self.webhooks = Some(sender);
        self
    }

    pub fn with_tracker(mut self, tracker: LastPollTracker) -> Self {
        self.tracker = Some(tracker);
        self
    }

    /// Run one tick: sync the header chain (detecting/handling any reorg), then progress
    /// confirmations for every deposit still accumulating them.
    pub async fn poll_once(&self) -> Result<TickOutcome, ConfirmationError> {
        let wallet = self.store.get_wallet(self.wallet_id).await?;
        let (depth, bound) = match (wallet.confirmation_depth, wallet.reorg_rewind_bound) {
            (Some(d), Some(b)) => (d, b),
            _ => return Err(ConfirmationError::NotEvmWallet),
        };

        let tip = self.rpc.latest_block().await?;
        let sync = self.sync_headers(&wallet, &tip, bound).await?;

        let outcome = match sync {
            SyncOutcome::BoundExceeded => {
                // Loud alert, not a panic/loop: an operator needs to intervene (the chain moved
                // further than we're willing to auto-rewind). Deposit state is left untouched —
                // safer to stall confirmation progress than to guess at an ancestor.
                tracing::error!(
                    wallet_id = %self.wallet_id,
                    reorg_rewind_bound = bound,
                    "evm reorg deeper than reorg_rewind_bound; refusing to auto-rewind, alerting instead"
                );
                return Ok(TickOutcome::DeepReorgAlert);
            }
            SyncOutcome::ReorgHandled { orphaned, ancestor } => {
                for tx in &orphaned {
                    self.fire_orphaned_webhook(tx).await;
                }
                tracing::warn!(
                    wallet_id = %self.wallet_id,
                    ancestor_block = ancestor,
                    orphaned = orphaned.len(),
                    "evm reorg detected and reversed"
                );
                Some(TickOutcome::Reorged {
                    orphaned: orphaned.len(),
                    ancestor,
                })
            }
            SyncOutcome::Synced => None,
        };

        let promoted = self.progress_confirmations(&tip, depth).await?;

        if let Some(reorged) = outcome {
            // Still report confirmation progress even on a reorg tick — the two are independent
            // (a reorg on one branch of history doesn't stop unaffected deposits confirming).
            let _ = promoted;
            self.record_poll_success();
            return Ok(reorged);
        }

        self.record_poll_success();
        Ok(TickOutcome::Synced { promoted })
    }

    fn record_poll_success(&self) {
        if let Some(ref tracker) = self.tracker {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            tracker.record_success(self.wallet_id, now);
        }
    }

    /// Recompute confirmations for every deposit still in `detected`/`confirming` and promote
    /// those that have reached `depth`, firing `deposit.confirmed` for each newly-promoted row.
    /// Returns the number promoted this tick.
    async fn progress_confirmations(
        &self,
        tip: &BlockHeader,
        depth: i32,
    ) -> Result<usize, ConfirmationError> {
        let rows = self.store.confirming_evm_transactions(self.wallet_id).await?;
        let mut promoted = 0;
        for row in rows {
            let Some(block_number) = row.block_number else {
                continue; // defensive: an EVM row always has this set at insert time
            };
            let confirmations = (tip.number - block_number).max(0);
            let confirmations = i32::try_from(confirmations).unwrap_or(i32::MAX);
            if let Some(updated) = self
                .store
                .progress_evm_confirmation(row.id, confirmations, depth)
                .await?
            {
                if updated.confirmation_state.as_deref() == Some("confirmed") {
                    promoted += 1;
                    self.fire_confirmed_webhook(&updated).await;
                }
            }
        }
        Ok(promoted)
    }

    /// Extend the verified header chain from the wallet's saved cursor to `tip`, detecting a
    /// reorg via parent-hash continuity. See the module doc for the algorithm.
    async fn sync_headers(
        &self,
        wallet: &Wallet,
        tip: &BlockHeader,
        bound: i32,
    ) -> Result<SyncOutcome, ConfirmationError> {
        let cursor = self.store.evm_cursor(wallet.id).await?;
        let Some((last_number, last_hash)) = cursor else {
            // Never scanned before: nothing to verify against yet. Adopt the tip as the starting
            // point of the verified chain.
            self.store
                .upsert_evm_block_header(wallet.id, tip.number, &tip.hash, &tip.parent_hash)
                .await?;
            self.store
                .set_evm_cursor(wallet.id, tip.number, &tip.hash)
                .await?;
            return Ok(SyncOutcome::Synced);
        };

        if tip.number < last_number {
            // The chain is shorter than our cursor. A healthy chain never loses blocks, so this
            // can only mean a reorg dropped our cursor's block (and possibly more) — go straight
            // to finding the common ancestor rather than treating it as "nothing to do".
            return self.rewind_to_common_ancestor(wallet.id, last_number, bound).await;
        }

        // Re-check the cursor height itself: if its on-chain hash no longer matches what we
        // recorded, the chain reorged at or before the cursor — a number-only cursor could not
        // see this (same height, different hash).
        let Some(onchain_at_cursor) = self.rpc.block_by_number(last_number).await? else {
            // tip.number >= last_number here, so under normal chain operation this block must
            // exist; a missing response is an RPC hiccup, not evidence of a reorg.
            return Err(ConfirmationError::Rpc(EvmRpcError::Decode));
        };
        if onchain_at_cursor.hash != last_hash {
            return self.rewind_to_common_ancestor(wallet.id, last_number, bound).await;
        }
        if tip.number == last_number {
            // Caught up and the cursor height is still canonical — nothing more to do this tick.
            return Ok(SyncOutcome::Synced);
        }

        // Walk forward one block at a time, verifying each new block's parent hash chains from
        // the previous (now-trusted) hash before trusting and storing it.
        let mut prev_hash = last_hash;
        let mut prev_number = last_number;
        for h in (last_number + 1)..=tip.number {
            let Some(block) = self.rpc.block_by_number(h).await? else {
                break; // node hasn't produced this height yet despite reporting a higher tip
            };
            if block.parent_hash != prev_hash {
                // Diverged mid-walk: treat exactly like a cursor-height mismatch, anchored at the
                // last block we still trust.
                return self
                    .rewind_to_common_ancestor(wallet.id, prev_number, bound)
                    .await;
            }
            self.store
                .upsert_evm_block_header(wallet.id, h, &block.hash, &block.parent_hash)
                .await?;
            prev_hash = block.hash;
            prev_number = h;
        }
        self.store
            .set_evm_cursor(wallet.id, prev_number, &prev_hash)
            .await?;
        // Bound header-table growth to roughly the rewind window (see migration 0022's comment).
        self.store
            .prune_evm_block_headers_before(wallet.id, prev_number - i64::from(bound))
            .await?;
        Ok(SyncOutcome::Synced)
    }

    /// Walk backward from `from_number`, comparing our recorded header hash against the current
    /// on-chain hash at each height, up to `bound` blocks, looking for the last common ancestor.
    /// On success, orphans every deposit at/after `ancestor + 1` and rewinds the cursor there.
    async fn rewind_to_common_ancestor(
        &self,
        wallet_id: Uuid,
        from_number: i64,
        bound: i32,
    ) -> Result<SyncOutcome, ConfirmationError> {
        for k in 1..=i64::from(bound) {
            let candidate = from_number - k;
            if candidate < 0 {
                break;
            }
            let Some(stored_hash) = self.store.evm_block_header_hash(wallet_id, candidate).await?
            else {
                // No recorded history this far back within the bound — cannot verify an
                // ancestor, so this counts as the bound being exceeded rather than a guess.
                break;
            };
            // A candidate height above the new chain's tip trivially can't match yet — that's
            // not "insufficient history" (we still have our own record of it), so keep walking
            // back rather than giving up.
            let Some(onchain) = self.rpc.block_by_number(candidate).await? else {
                continue;
            };
            if onchain.hash == stored_hash {
                let orphaned = self
                    .store
                    .orphan_evm_deposits_from_block(wallet_id, candidate + 1)
                    .await?;
                self.store
                    .delete_evm_block_headers_from(wallet_id, candidate + 1)
                    .await?;
                self.store
                    .set_evm_cursor(wallet_id, candidate, &stored_hash)
                    .await?;
                return Ok(SyncOutcome::ReorgHandled {
                    orphaned,
                    ancestor: candidate,
                });
            }
        }
        Ok(SyncOutcome::BoundExceeded)
    }

    async fn fire_confirmed_webhook(&self, tx: &Transaction) {
        let Some(sender) = &self.webhooks else { return };
        let event = Event {
            event_type: "deposit.confirmed".to_string(),
            data: serde_json::json!({
                "id": tx.id,
                "wallet_id": tx.wallet_id,
                "address_id": tx.address_id,
                "asset_code": tx.asset_code,
                "asset_issuer": tx.asset_issuer,
                "amount_stroops": tx.amount_stroops,
                "evm_tx_hash": tx.evm_tx_hash,
                "log_index": tx.log_index,
                "block_number": tx.block_number,
                "confirmations": tx.confirmations,
                "status": tx.status,
            }),
        };
        sender.dispatch(self.wallet_id, &event).await;
    }

    async fn fire_orphaned_webhook(&self, tx: &Transaction) {
        let Some(sender) = &self.webhooks else { return };
        let event = Event {
            event_type: "deposit.orphaned".to_string(),
            data: serde_json::json!({
                "id": tx.id,
                "wallet_id": tx.wallet_id,
                "address_id": tx.address_id,
                "asset_code": tx.asset_code,
                "asset_issuer": tx.asset_issuer,
                "amount_stroops": tx.amount_stroops,
                "evm_tx_hash": tx.evm_tx_hash,
                "log_index": tx.log_index,
                "block_number": tx.block_number,
                "orphaned_at": tx.orphaned_at,
                "status": tx.status,
            }),
        };
        sender.dispatch(self.wallet_id, &event).await;
    }
}

/// Supervises confirmation tracking across all EVM wallets on one network/RPC endpoint —
/// the EVM analogue of [`crate::Supervisor`].
pub struct EvmSupervisor {
    store: Store,
    rpc_url: String,
    webhooks: WebhookSender,
    network: &'static str,
    tracker: LastPollTracker,
    retry: octo_resilience::RetryPolicy,
    circuit: octo_resilience::CircuitBreaker,
}

impl EvmSupervisor {
    pub fn new(store: Store, rpc_url: String, webhooks: WebhookSender, network: &'static str) -> Self {
        Self::new_with_resilience(
            store,
            rpc_url,
            webhooks,
            network,
            octo_resilience::RetryPolicy::default(),
            octo_resilience::CircuitBreaker::new(5, Duration::from_secs(30)),
        )
    }

    pub fn new_with_resilience(
        store: Store,
        rpc_url: String,
        webhooks: WebhookSender,
        network: &'static str,
        retry: octo_resilience::RetryPolicy,
        circuit: octo_resilience::CircuitBreaker,
    ) -> Self {
        Self {
            store,
            rpc_url,
            webhooks,
            network,
            tracker: LastPollTracker::new(),
            retry,
            circuit,
        }
    }

    /// How many wallets to track concurrently in one [`EvmSupervisor::tick`] pass. Matches
    /// `Supervisor::MAX_CONCURRENT_POLLS`.
    const MAX_CONCURRENT_POLLS: usize = 20;
    const ACTIVE_AFTER_SECS: i64 = 60 * 60;
    const IDLE_INTERVAL_SECS: i64 = 120;
    const DORMANT_AFTER_SECS: i64 = 24 * 60 * 60;
    const DORMANT_INTERVAL_SECS: i64 = 600;

    pub async fn run(self, interval: Duration) {
        loop {
            if let Err(e) = self.tick().await {
                tracing::warn!(error = ?e, "evm confirmation supervisor tick failed; will retry");
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// One supervision pass: run a confirmation-tracker tick for every EVM wallet due, bounded
    /// concurrency (see `crate::Supervisor::tick` for why bounded-not-sequential matters).
    pub async fn tick(&self) -> Result<usize, ConfirmationError> {
        let wallets = self
            .store
            .evm_wallets_due_for_poll(
                self.network,
                Self::ACTIVE_AFTER_SECS,
                Self::IDLE_INTERVAL_SECS,
                Self::DORMANT_AFTER_SECS,
                Self::DORMANT_INTERVAL_SECS,
            )
            .await?;
        let semaphore = Arc::new(tokio::sync::Semaphore::new(Self::MAX_CONCURRENT_POLLS));
        let mut tasks = tokio::task::JoinSet::new();

        for w in wallets {
            let store = self.store.clone();
            let store_for_mark = self.store.clone();
            let rpc_url = self.rpc_url.clone();
            let webhooks = self.webhooks.clone();
            let tracker = self.tracker.clone();
            let retry = self.retry.clone();
            let circuit = self.circuit.clone();
            let semaphore = semaphore.clone();
            tasks.spawn(async move {
                let _permit = semaphore.acquire_owned().await;
                let confirmation_tracker =
                    ConfirmationTracker::new_with_resilience(store, &rpc_url, w.id, retry, circuit)
                        .with_webhooks(webhooks)
                        .with_tracker(tracker);
                let result = confirmation_tracker.poll_once().await;
                let _ = store_for_mark.mark_polled(w.id).await;
                (w.id, result)
            });
        }

        let mut total = 0;
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((_wallet_id, Ok(_))) => total += 1,
                Ok((wallet_id, Err(e))) => {
                    tracing::warn!(wallet = %wallet_id, error = ?e, "evm wallet confirmation tick failed")
                }
                Err(e) => tracing::warn!(error = ?e, "evm wallet confirmation task panicked"),
            }
        }
        Ok(total)
    }

    pub fn last_poll_tracker(&self) -> LastPollTracker {
        self.tracker.clone()
    }
}
