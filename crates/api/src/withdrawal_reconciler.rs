//! Background reconciler for withdrawals left `pending` by a crash or an ambiguous submit.
//!
//! A withdrawal row is written `pending` before the signed transaction reaches Horizon. If the
//! process dies (or Horizon times out) afterwards, the row is never settled. This sweep looks each
//! stale row up by transaction hash and finalises it.
//!
//! # Documented bound
//!
//! A pending row is settled within `max_time + ledger lag + interval` of its transaction's
//! timebound expiry. A transaction signed *without* a timebound can never expire on its own, so
//! it is failed once it has been pending for `abandon_after` (default 24h).
//!
//! # Safety
//!
//! Settling only touches rows still `pending` (see `Store::settle_pending_withdrawal`), so the
//! sweep is idempotent and safe to run concurrently or repeatedly. A row is failed only on proof:
//! Horizon reports the transaction failed, or it is absent and its `max_time` precedes the close
//! time of Horizon's newest ledger. Any lookup error leaves the row for the next run.

use crate::horizon::{Horizon, TxLookup};
use octo_store::{Store, StoreError, Transaction};
use std::time::Duration;

/// Tunables for the sweep.
#[derive(Debug, Clone)]
pub struct ReconcilerConfig {
    /// How often the sweep runs.
    pub interval: Duration,
    /// Minimum row age before it is looked up, so in-flight submissions are left alone.
    pub grace: Duration,
    /// Age after which a transaction without a timebound is declared abandoned.
    pub abandon_after: Duration,
    /// Maximum rows examined per run.
    pub batch: i64,
}

impl Default for ReconcilerConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(60),
            grace: Duration::from_secs(120),
            abandon_after: Duration::from_secs(24 * 60 * 60),
            batch: 100,
        }
    }
}

/// What to do with one stale row.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Confirmed { ledger: Option<i64> },
    Failed(&'static str),
    /// Not provable yet; leave `pending`.
    Wait,
}

/// Counts from one sweep.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub confirmed: u64,
    pub failed: u64,
    pub waiting: u64,
}

/// Pure decision for a looked-up row; `ledger_close` is the newest ledger's close time (unix
/// seconds), needed only when the transaction is absent and carries a timebound.
pub fn decide(
    lookup: &TxLookup,
    max_time: Option<i64>,
    ledger_close: Option<i64>,
    age: Duration,
    abandon_after: Duration,
) -> Verdict {
    match lookup {
        TxLookup::Found { successful: true, ledger } => Verdict::Confirmed { ledger: *ledger },
        TxLookup::Found { successful: false, .. } => Verdict::Failed("transaction failed on-chain"),
        TxLookup::NotFound => match (max_time, ledger_close) {
            // A ledger closed after max_time and still lacks the tx: it can never be applied.
            (Some(max), Some(close)) if close > max => {
                Verdict::Failed("transaction expired before inclusion (timebounds)")
            }
            (None, _) if age >= abandon_after => {
                Verdict::Failed("no timebound and never found on-chain; abandoned")
            }
            _ => Verdict::Wait,
        },
    }
}

/// Resolve one row; `Ok(Wait)` on any Horizon error so a flaky node never fails a live payment.
async fn resolve(horizon: &Horizon, row: &Transaction, cfg: &ReconcilerConfig) -> Verdict {
    let Some(hash) = row.stellar_tx_hash.as_deref() else {
        return Verdict::Failed("no transaction hash recorded");
    };
    let Ok(lookup) = horizon.transaction_by_hash(hash).await else {
        return Verdict::Wait;
    };
    let max_time = row.metadata.get("max_time").and_then(|v| v.as_i64());
    let ledger_close = match (&lookup, max_time) {
        (TxLookup::NotFound, Some(_)) => horizon.latest_ledger_close_time().await.ok(),
        _ => None,
    };
    let age = (chrono::Utc::now() - row.created_at).to_std().unwrap_or_default();
    decide(&lookup, max_time, ledger_close, age, cfg.abandon_after)
}

/// Run one sweep over stale pending withdrawals.
pub async fn reconcile_once(
    store: &Store,
    horizon: &Horizon,
    cfg: &ReconcilerConfig,
) -> Result<Stats, StoreError> {
    let mut stats = Stats::default();
    for row in store.list_stale_pending_withdrawals(cfg.grace, cfg.batch).await? {
        let (status, ledger, reason) = match resolve(horizon, &row, cfg).await {
            Verdict::Confirmed { ledger } => ("confirmed", ledger, None),
            Verdict::Failed(reason) => ("failed", None, Some(reason)),
            Verdict::Wait => {
                stats.waiting += 1;
                continue;
            }
        };
        // `false` means another run settled it first; nothing to count.
        if store.settle_pending_withdrawal(row.id, status, ledger, reason).await? {
            tracing::info!(withdrawal = %row.id, status, reason, "reconciled pending withdrawal");
            if status == "confirmed" {
                stats.confirmed += 1;
            } else {
                stats.failed += 1;
            }
        }
    }
    Ok(stats)
}

/// Sweep forever on `cfg.interval`; errors are logged and retried on the next tick.
pub async fn run(store: Store, horizon: Horizon, cfg: ReconcilerConfig) {
    let mut interval = tokio::time::interval(cfg.interval);
    loop {
        interval.tick().await;
        if let Err(e) = reconcile_once(&store, &horizon, &cfg).await {
            tracing::warn!(error = ?e, "withdrawal reconciliation failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: Duration = Duration::from_secs(86_400);

    fn found(successful: bool) -> TxLookup {
        TxLookup::Found { successful, ledger: Some(7) }
    }

    #[test]
    fn found_transactions_settle_to_their_on_chain_result() {
        assert_eq!(decide(&found(true), None, None, DAY, DAY), Verdict::Confirmed { ledger: Some(7) });
        assert!(matches!(decide(&found(false), None, None, DAY, DAY), Verdict::Failed(_)));
    }

    #[test]
    fn absent_transaction_fails_only_after_a_later_ledger_closed_past_max_time() {
        let nf = TxLookup::NotFound;
        let age = Duration::from_secs(600);
        assert_eq!(decide(&nf, Some(1_000), Some(999), age, DAY), Verdict::Wait);
        assert_eq!(decide(&nf, Some(1_000), Some(1_000), age, DAY), Verdict::Wait);
        assert!(matches!(decide(&nf, Some(1_000), Some(1_001), age, DAY), Verdict::Failed(_)));
        // Ledger time unavailable: never guess.
        assert_eq!(decide(&nf, Some(1_000), None, age, DAY), Verdict::Wait);
    }

    #[test]
    fn absent_transaction_without_timebound_is_abandoned_only_after_the_bound() {
        let nf = TxLookup::NotFound;
        assert_eq!(decide(&nf, None, None, DAY - Duration::from_secs(1), DAY), Verdict::Wait);
        assert!(matches!(decide(&nf, None, None, DAY, DAY), Verdict::Failed(_)));
    }
}
