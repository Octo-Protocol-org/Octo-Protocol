//! Deposit detection for octo.
//!
//! Polls a master account's Horizon `/payments` (oldest-first, from a saved cursor), attributes
//! each incoming payment to a customer by **muxed id** or **transaction memo id**, and records it
//! idempotently via [`octo_store`]. Unattributable deposits are still recorded but with no
//! `address_id` (quarantine) — they are never guessed onto a customer.
//!
//! Security (see `docs/threat-model.md`):
//! - Only `transaction_successful` payments are credited (no failed/reorged double-credit).
//! - Dedup on the Horizon operation id (TOID) → replays/re-deliveries are no-ops.
//! - Amounts are integer stroops (no floats); only whitelisted incoming directions are credited.
//! - The cursor is advanced and persisted only after a record is processed, so a crash resumes
//!   without missing or double-processing.
#![forbid(unsafe_code)]

pub mod amount;
pub mod horizon;

use horizon::{HorizonPayments, PaymentRecord};
use octo_store::{NewDeposit, Store};
use octo_wallet_core::decode_muxed;
use octo_webhooks::{Event, WebhookSender};
use std::time::Duration;
use uuid::Uuid;

/// Outcome of processing a single payment record.
#[derive(Debug, PartialEq, Eq)]
pub enum Processed {
    /// A new deposit was recorded (attributed to a customer address, or quarantined if `None`).
    Recorded { attributed: bool },
    /// Already recorded (idempotent no-op).
    Duplicate,
    /// Skipped (not a credit to us, failed tx, unknown asset shape, etc.).
    Skipped,
}

/// The ingest worker for one master wallet.
pub struct Ingestor {
    store: Store,
    horizon: HorizonPayments,
    wallet_id: Uuid,
    account_g: String,
    webhooks: Option<WebhookSender>,
}

impl Ingestor {
    pub fn new(store: Store, horizon_url: &str, wallet_id: Uuid, account_g: String) -> Self {
        Self {
            store,
            horizon: HorizonPayments::new(horizon_url),
            wallet_id,
            account_g,
            webhooks: None,
        }
    }

    /// Attach a webhook sender so new deposits fire a `deposit.created` event.
    pub fn with_webhooks(mut self, sender: WebhookSender) -> Self {
        self.webhooks = Some(sender);
        self
    }

    /// Poll once: fetch the next page of payments after the saved cursor, process each, and persist
    /// the cursor. Returns the number of records processed.
    pub async fn poll_once(&self, limit: u32) -> Result<usize, IngestError> {
        let cursor = self.store.get_cursor(self.wallet_id).await?;
        let records = self
            .horizon
            .payments_after(&self.account_g, cursor.as_deref(), limit)
            .await
            .map_err(|_| IngestError::Horizon)?;

        let mut count = 0;
        for rec in &records {
            self.process(rec).await?;
            // Advance the cursor after each record so a crash resumes cleanly.
            self.store
                .set_cursor(self.wallet_id, &rec.paging_token)
                .await?;
            count += 1;
        }
        Ok(count)
    }

    /// Run forever, polling every `interval`. Errors are logged and retried (the cursor makes this
    /// safe). Intended to run as its own task/process.
    pub async fn run(self, interval: Duration, page_limit: u32) {
        loop {
            match self.poll_once(page_limit).await {
                Ok(n) if n > 0 => tracing::debug!(processed = n, "ingest poll"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = ?e, "ingest poll failed; will retry"),
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// Process one payment record into a deposit (or skip it).
    pub async fn process(&self, rec: &PaymentRecord) -> Result<Processed, IngestError> {
        // 1. Only successful credits to us.
        if !rec.transaction_successful {
            return Ok(Processed::Skipped);
        }
        if rec.kind != "payment" && rec.kind != "create_account" {
            return Ok(Processed::Skipped);
        }
        // The destination base account must be our master account.
        match rec.to.as_deref() {
            Some(to) if to == self.account_g => {}
            _ => return Ok(Processed::Skipped),
        }

        // 2. Amount → stroops (payment uses `amount`, create_account uses `starting_balance`).
        let amount_str = rec
            .amount
            .as_deref()
            .or(rec.starting_balance.as_deref())
            .unwrap_or("");
        let Some(stroops) = amount::to_stroops(amount_str) else {
            return Ok(Processed::Skipped);
        };
        if stroops <= 0 {
            return Ok(Processed::Skipped);
        }

        // 3. Attribute to a customer: muxed id first, then memo id.
        let customer_id = self.attribute(rec);
        let address_id = match customer_id {
            Some(id) => self
                .store
                .address_by_muxed_id(self.wallet_id, id)
                .await?
                .map(|a| a.id),
            None => None,
        };
        let attributed = address_id.is_some();

        // 4. Asset.
        let (asset_code, asset_issuer) = match rec.asset_type.as_deref() {
            Some("native") | None => ("native".to_string(), None),
            _ => (
                rec.asset_code.clone().unwrap_or_else(|| "unknown".into()),
                rec.asset_issuer.clone(),
            ),
        };

        let memo_id = self.memo_id(rec);
        let ledger = rec.transaction.as_ref().and_then(|t| t.ledger);
        let tx_hash = rec.transaction_hash.clone().unwrap_or_default();

        let dep = NewDeposit {
            wallet_id: self.wallet_id,
            address_id,
            asset_code,
            asset_issuer,
            amount_stroops: stroops,
            source_account: rec.from.clone(),
            destination_account: rec.to_muxed.clone().or_else(|| rec.to.clone()),
            stellar_tx_hash: tx_hash,
            operation_index: 0,
            horizon_op_id: rec.id.clone(),
            ledger,
            memo_id,
        };

        match self.store.record_deposit(&dep).await? {
            Some(tx) => {
                self.fire_deposit_webhook(&tx).await;
                Ok(Processed::Recorded { attributed })
            }
            None => Ok(Processed::Duplicate),
        }
    }

    /// Fire a `deposit.created` webhook for a newly-recorded deposit. The event echoes the
    /// customer's address `metadata` (if attributed) so the consumer can reconcile to their user.
    async fn fire_deposit_webhook(&self, tx: &octo_store::Transaction) {
        let Some(sender) = &self.webhooks else {
            return;
        };

        // Echo the customer address's metadata (Blockradar-parity reconciliation), best-effort.
        let metadata = match tx.address_id {
            Some(addr_id) => match self.store.get_address(addr_id).await {
                Ok(Some(a)) => a.metadata,
                _ => serde_json::Value::Null,
            },
            None => serde_json::Value::Null,
        };

        let event = Event {
            event_type: "deposit.created".to_string(),
            data: serde_json::json!({
                "id": tx.id,
                "wallet_id": tx.wallet_id,
                "address_id": tx.address_id,
                "asset_code": tx.asset_code,
                "asset_issuer": tx.asset_issuer,
                "amount_stroops": tx.amount_stroops,
                "source_account": tx.source_account,
                "destination_account": tx.destination_account,
                "stellar_tx_hash": tx.stellar_tx_hash,
                "memo_id": tx.memo_id,
                "status": tx.status,
                "attributed": tx.address_id.is_some(),
                "metadata": metadata,
            }),
        };
        sender.dispatch(self.wallet_id, &event).await;
    }

    /// The customer id for a record: the muxed id if the payment was sent to `M...`, else a numeric
    /// memo id, else `None` (unattributed).
    fn attribute(&self, rec: &PaymentRecord) -> Option<i64> {
        if let Some(id) = self.muxed_id(rec) {
            return Some(id);
        }
        self.memo_id(rec)
    }

    /// Extract the muxed id from a record, validating the muxed address decodes to our base account.
    fn muxed_id(&self, rec: &PaymentRecord) -> Option<i64> {
        let muxed = rec.to_muxed.as_deref()?;
        let decoded = decode_muxed(muxed).ok()?;
        if decoded.base_account() != self.account_g {
            return None;
        }
        i64::try_from(decoded.id).ok()
    }

    /// Extract a numeric memo id from the joined transaction (`memo_type == "id"`).
    fn memo_id(&self, rec: &PaymentRecord) -> Option<i64> {
        let tx = rec.transaction.as_ref()?;
        if tx.memo_type.as_deref() != Some("id") {
            return None;
        }
        tx.memo.as_deref()?.parse::<i64>().ok()
    }
}

/// Errors from the ingest worker.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("store error")]
    Store(#[from] octo_store::StoreError),
    #[error("horizon error")]
    Horizon,
}

/// Supervises deposit ingestion across all wallets.
///
/// On each tick it loads the wallet list and polls each one once (resuming from its cursor). This
/// is a simple, restart-safe fan-out for the MVP; it can later be split into per-wallet workers or
/// separate processes for scale without changing the cursor-based contract.
pub struct Supervisor {
    store: Store,
    horizon_url: String,
    webhooks: WebhookSender,
    network: &'static str,
}

impl Supervisor {
    pub fn new(
        store: Store,
        horizon_url: String,
        webhooks: WebhookSender,
        network: &'static str,
    ) -> Self {
        Self {
            store,
            horizon_url,
            webhooks,
            network,
        }
    }

    /// Run forever: every `interval`, poll all wallets on this network once.
    pub async fn run(self, interval: Duration, page_limit: u32) {
        loop {
            if let Err(e) = self.tick(page_limit).await {
                tracing::warn!(error = ?e, "ingest supervisor tick failed; will retry");
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// One supervision pass: poll every wallet on this network once.
    pub async fn tick(&self, page_limit: u32) -> Result<usize, IngestError> {
        let wallets = self.store.list_wallets().await?;
        let mut total = 0;
        for w in wallets {
            if w.network != self.network {
                continue;
            }
            let ingestor = Ingestor::new(
                self.store.clone(),
                &self.horizon_url,
                w.id,
                w.stellar_account_g.clone(),
            )
            .with_webhooks(self.webhooks.clone());
            match ingestor.poll_once(page_limit).await {
                Ok(n) => total += n,
                Err(e) => tracing::warn!(wallet = %w.id, error = ?e, "wallet poll failed"),
            }
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use horizon::{PaymentRecord, TransactionRecord};

    const BASE: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";

    // The attribution logic is pure; mirror it as free functions so these unit tests need no DB.
    // The DB-backed process()/poll_once() path is covered by the integration test.
    fn muxed_id_of(account_g: &str, rec: &PaymentRecord) -> Option<i64> {
        let muxed = rec.to_muxed.as_deref()?;
        let decoded = decode_muxed(muxed).ok()?;
        if decoded.base_account() != account_g {
            return None;
        }
        i64::try_from(decoded.id).ok()
    }

    fn memo_id_of(rec: &PaymentRecord) -> Option<i64> {
        let tx = rec.transaction.as_ref()?;
        if tx.memo_type.as_deref() != Some("id") {
            return None;
        }
        tx.memo.as_deref()?.parse::<i64>().ok()
    }

    fn rec() -> PaymentRecord {
        PaymentRecord {
            id: "op1".into(),
            paging_token: "op1".into(),
            kind: "payment".into(),
            transaction_hash: Some("hash".into()),
            transaction_successful: true,
            from: Some("Gfrom".into()),
            to: Some(BASE.into()),
            to_muxed: None,
            to_muxed_id: None,
            asset_type: Some("native".into()),
            asset_code: None,
            asset_issuer: None,
            amount: Some("5.0000000".into()),
            starting_balance: None,
            transaction: None,
        }
    }

    #[test]
    fn attributes_by_muxed_id() {
        let muxed = octo_wallet_core::encode_muxed(BASE, 77).unwrap();
        let mut r = rec();
        r.to_muxed = Some(muxed);
        assert_eq!(muxed_id_of(BASE, &r), Some(77));
    }

    #[test]
    fn muxed_for_other_base_is_ignored() {
        // A different (valid) base account — its muxed form must not attribute to ours.
        let other = "GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR";
        let muxed = octo_wallet_core::encode_muxed(other, 5).unwrap();
        let mut r = rec();
        r.to_muxed = Some(muxed);
        assert_eq!(muxed_id_of(BASE, &r), None);
    }

    #[test]
    fn attributes_by_memo_id() {
        let mut r = rec();
        r.transaction = Some(TransactionRecord {
            memo_type: Some("id".into()),
            memo: Some("42".into()),
            ledger: Some(10),
        });
        assert_eq!(memo_id_of(&r), Some(42));
    }

    #[test]
    fn non_id_memo_is_ignored() {
        let mut r = rec();
        r.transaction = Some(TransactionRecord {
            memo_type: Some("text".into()),
            memo: Some("hello".into()),
            ledger: None,
        });
        assert_eq!(memo_id_of(&r), None);
    }

    // --- i64/u64 boundary tests -------------------------------------------
    //
    // muxed_id uses i64::try_from(decoded.id).ok() where decoded.id is u64.
    // Any id above i64::MAX causes try_from to fail and the deposit becomes
    // unattributed (None) rather than erroring. These tests lock that
    // documented behavior in as an explicit regression guard.
    //
    // NOTE: if this silent-truncation behavior should change, do NOT fix it
    // here — this file is test-only per issue #60. Raise the concern in the
    // PR so a maintainer can decide (see the related backend tracking issue).

    #[test]
    fn muxed_id_at_i64_max_is_attributed() {
        // i64::MAX fits in u64 and must round-trip through i64::try_from cleanly.
        let muxed = octo_wallet_core::encode_muxed(BASE, i64::MAX as u64).unwrap();
        let mut r = rec();
        r.to_muxed = Some(muxed);
        assert_eq!(
            muxed_id_of(BASE, &r),
            Some(i64::MAX),
            "a muxed id of exactly i64::MAX must be attributed correctly"
        );
    }

    #[test]
    fn muxed_id_above_i64_max_is_unattributed_not_error() {
        // i64::MAX + 1 overflows i64::try_from → must return None, not panic.
        let above_max: u64 = i64::MAX as u64 + 1;
        let muxed = octo_wallet_core::encode_muxed(BASE, above_max).unwrap();
        let mut r = rec();
        r.to_muxed = Some(muxed);
        assert_eq!(
            muxed_id_of(BASE, &r),
            None,
            "a muxed id above i64::MAX must be silently unattributed (current documented behavior)"
        );
    }

    #[test]
    fn memo_id_at_i64_max_is_attributed() {
        // "9223372036854775807" is i64::MAX as a decimal string — must parse cleanly.
        let mut r = rec();
        r.transaction = Some(TransactionRecord {
            memo_type: Some("id".into()),
            memo: Some("9223372036854775807".into()), // i64::MAX
            ledger: Some(1),
        });
        assert_eq!(
            memo_id_of(&r),
            Some(i64::MAX),
            "memo string equal to i64::MAX must be attributed correctly"
        );
    }

    #[test]
    fn memo_id_above_i64_max_is_unattributed_not_error() {
        // "9223372036854775808" is i64::MAX + 1 — parse::<i64>() fails → must return None.
        let mut r = rec();
        r.transaction = Some(TransactionRecord {
            memo_type: Some("id".into()),
            memo: Some("9223372036854775808".into()), // i64::MAX + 1
            ledger: Some(1),
        });
        assert_eq!(
            memo_id_of(&r),
            None,
            "memo string one above i64::MAX must be silently unattributed (current documented behavior)"
        );
    }
}
