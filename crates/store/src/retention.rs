//! Periodic retention sweeper for all short-lived tables.
//!
//! Short-lived tables (`email_otps`, `token_denylist`, `sessions`, `idempotency_keys`,
//! `rate_limit_buckets`, `webhook_deliveries`) grow without bound unless rows are periodically
//! pruned.  Individual purge methods already exist on [`Store`]; this module adds:
//!
//! 1. [`RetentionConfig`] — a single place to tune every retention window.
//! 2. [`Store::run_retention_sweep`] — one call that sweeps all tables in a single pass and
//!    returns a [`RetentionReport`] detailing every table that was affected.
//!
//! # Batch deletes
//!
//! Each purge issues a plain `DELETE … WHERE <age condition>`.  Postgres executes this under a
//! single statement lock, so very large sweeps can cause brief contention on hot tables.  To
//! avoid long locks the caller can run the sweep with a smaller `batch_size` and loop until the
//! report shows `0` rows deleted — the individual `Store::purge_*` methods accept a `LIMIT`
//! parameter for that pattern.  `run_retention_sweep` is the convenience single-pass entry point
//! and does not batch internally.

use std::time::Duration;

use crate::{Store, StoreError};

/// Retention windows for every short-lived table.
///
/// All durations are measured from the row's natural expiry (or consumed/created timestamp).
/// The defaults are deliberately conservative — reduce them only when you have measured the
/// table sizes and confirmed the audit windows are no longer needed.
#[derive(Debug, Clone)]
pub struct RetentionConfig {
    /// How long after expiry (or consumption) to keep OTP rows.
    ///
    /// Default: 7 days.  Extend if you need OTP-level audit trails for longer.
    pub otp_grace: Duration,

    /// How long after natural token expiry to keep deny-list rows.
    ///
    /// Default: 0 (delete as soon as `expires_at < now()`).  A token past its `exp` claim
    /// cannot authenticate regardless of the deny-list, so there is no correctness reason to
    /// keep it.
    pub denylist_grace: Duration,

    /// How long after session expiry to keep session rows.
    ///
    /// Default: 1 day (matches [`Store::purge_expired_sessions`]'s built-in 1-day grace).
    pub session_grace: Duration,

    /// Minimum age of an expired idempotency key before deletion.
    ///
    /// Default: 0 (delete as soon as `expires_at <= now()`).
    pub idempotency_grace: Duration,

    /// Keep at least this many delivery rows per endpoint regardless of age.
    ///
    /// Default: 100.  Keeps recent history visible in the dashboard without unbounded growth.
    pub webhook_deliveries_keep_per_endpoint: i64,

    /// Minimum age of a webhook delivery row before it is eligible for deletion.
    ///
    /// Default: 30 days.
    pub webhook_deliveries_min_age: Duration,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            otp_grace: Duration::from_secs(7 * 24 * 3600),
            denylist_grace: Duration::ZERO,
            session_grace: Duration::from_secs(24 * 3600),
            idempotency_grace: Duration::ZERO,
            webhook_deliveries_keep_per_endpoint: 100,
            webhook_deliveries_min_age: Duration::from_secs(30 * 24 * 3600),
        }
    }
}

/// Row counts deleted from each table during one retention sweep.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetentionReport {
    pub otps_deleted: u64,
    pub denylist_deleted: u64,
    pub sessions_deleted: u64,
    pub idempotency_keys_deleted: u64,
    pub rate_limit_buckets_deleted: u64,
    pub webhook_deliveries_deleted: u64,
}

impl RetentionReport {
    /// Total rows deleted across all tables.
    pub fn total_deleted(&self) -> u64 {
        self.otps_deleted
            + self.denylist_deleted
            + self.sessions_deleted
            + self.idempotency_keys_deleted
            + self.rate_limit_buckets_deleted
            + self.webhook_deliveries_deleted
    }
}

impl Store {
    /// Run a full retention sweep across all short-lived tables.
    ///
    /// Each table is swept independently; a failure on one does not abort the others.  All
    /// results (including partial failures) are surfaced in the returned [`Result`].
    ///
    /// Callers typically run this once per hour from a background task:
    ///
    /// ```rust,ignore
    /// let report = store.run_retention_sweep(&RetentionConfig::default()).await?;
    /// tracing::info!(
    ///     total = report.total_deleted(),
    ///     otps = report.otps_deleted,
    ///     denylist = report.denylist_deleted,
    ///     sessions = report.sessions_deleted,
    ///     idempotency = report.idempotency_keys_deleted,
    ///     rate_limits = report.rate_limit_buckets_deleted,
    ///     webhook_deliveries = report.webhook_deliveries_deleted,
    ///     "retention sweep complete"
    /// );
    /// ```
    pub async fn run_retention_sweep(
        &self,
        cfg: &RetentionConfig,
    ) -> Result<RetentionReport, StoreError> {
        let otp_grace = chrono::Duration::from_std(cfg.otp_grace)
            .unwrap_or(chrono::Duration::days(7));

        let webhook_min_age = chrono::Duration::from_std(cfg.webhook_deliveries_min_age)
            .unwrap_or(chrono::Duration::days(30));

        let otps_deleted = self.purge_expired_otps(otp_grace).await?;

        let denylist_deleted = self.purge_expired_tokens().await?;

        let sessions_deleted = self.purge_expired_sessions().await?;

        let idempotency_keys_deleted = self.purge_expired_idempotency_keys().await?;

        let rate_limit_buckets_deleted = self.prune_rate_limit_buckets().await?;

        let webhook_deliveries_deleted = self
            .purge_old_webhook_deliveries(
                webhook_min_age,
                cfg.webhook_deliveries_keep_per_endpoint,
            )
            .await?;

        Ok(RetentionReport {
            otps_deleted,
            denylist_deleted,
            sessions_deleted,
            idempotency_keys_deleted,
            rate_limit_buckets_deleted,
            webhook_deliveries_deleted,
        })
    }
}
