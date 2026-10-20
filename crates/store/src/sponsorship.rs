//! Gas-fee sponsorship: budget reservation, status tracking, and the withdrawal allowlist.

use uuid::Uuid;

use crate::error::StoreError;
use crate::models::{
    GasSponsorshipConfig, NewSponsoredTx, SponsoredTransaction, WhitelistedAddress,
    WithdrawalAllowlistConfig,
};
use crate::Store;

impl Store {
    /// List sponsored transactions for a wallet (most recent first), with
    /// optional status filter and cursor-based pagination.
    pub async fn list_sponsored_transactions(
        &self,
        wallet_id: Uuid,
        limit: i64,
        status_filter: Option<&str>,
        before_id: Option<Uuid>,
    ) -> Result<Vec<SponsoredTransaction>, StoreError> {
        let rows = sqlx::query_as::<_, SponsoredTransaction>(
            r#"
            SELECT * FROM sponsored_transactions
            WHERE wallet_id = $1
              AND ($2::text IS NULL OR status = $2)
              AND ($3::uuid IS NULL OR (created_at, id) < (SELECT created_at, id FROM sponsored_transactions WHERE id = $3))
            ORDER BY created_at DESC, id DESC
            LIMIT $4
            "#,
        )
        .bind(wallet_id)
        .bind(status_filter)
        .bind(before_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    // --- gas sponsorship config -------------------------------------------

    /// Fetch a wallet's sponsorship config, or `None` if none has been saved.
    pub async fn get_gas_sponsorship_config(
        &self,
        wallet_id: Uuid,
    ) -> Result<Option<GasSponsorshipConfig>, StoreError> {
        let row = sqlx::query_as::<_, GasSponsorshipConfig>(
            "SELECT * FROM gas_sponsorship_configs WHERE wallet_id = $1",
        )
        .bind(wallet_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Create or replace a wallet's sponsorship config.
    ///
    /// `allowed_operations`: `None` keeps the stored list, `Some(None)` resets to the global
    /// allowlist, `Some(Some(list))` stores `list`. Kept-by-default so an unrelated update can
    /// never silently widen a wallet back to the global set.
    pub async fn upsert_gas_sponsorship_config(
        &self,
        wallet_id: Uuid,
        enabled: bool,
        per_tx_fee_cap_stroops: Option<i64>,
        daily_budget_stroops: Option<i64>,
        allowed_operations: Option<Option<&[String]>>,
    ) -> Result<GasSponsorshipConfig, StoreError> {
        sqlx::query_as::<_, GasSponsorshipConfig>(
            r#"
            INSERT INTO gas_sponsorship_configs
                (wallet_id, enabled, per_tx_fee_cap_stroops, daily_budget_stroops,
                 allowed_operations)
            VALUES ($1, $2, $3, $4, $6)
            ON CONFLICT (wallet_id) DO UPDATE SET
                enabled = EXCLUDED.enabled,
                per_tx_fee_cap_stroops = EXCLUDED.per_tx_fee_cap_stroops,
                daily_budget_stroops = EXCLUDED.daily_budget_stroops,
                allowed_operations = CASE WHEN $5 THEN EXCLUDED.allowed_operations
                                          ELSE gas_sponsorship_configs.allowed_operations END,
                updated_at = now()
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(enabled)
        .bind(per_tx_fee_cap_stroops)
        .bind(daily_budget_stroops)
        .bind(allowed_operations.is_some())
        .bind(allowed_operations.flatten())
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::Database)
    }

    /// Mark sponsored transactions stuck `pending` longer than `older_than` as failed.
    pub async fn reconcile_stale_pending_sponsorships(
        &self,
        older_than: std::time::Duration,
    ) -> Result<u64, StoreError> {
        let result = sqlx::query(
            r#"
            UPDATE sponsored_transactions
            SET status = 'failed', error = COALESCE(error, 'timed out pending confirmation')
            WHERE status = 'pending'
              AND created_at < now() - make_interval(secs => $1)
            "#,
        )
        .bind(older_than.as_secs_f64())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Sum of sponsored fees reserved (pending + confirmed) for a wallet so far today (UTC).
    /// Used to enforce the rolling daily budget and to report `spent_today`.
    pub async fn sum_sponsored_fees_reserved_today(
        &self,
        wallet_id: Uuid,
    ) -> Result<i64, StoreError> {
        let total: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT COALESCE(SUM(fee_stroops), 0)::bigint
            FROM sponsored_transactions
            WHERE wallet_id = $1
              AND status IN ('pending', 'confirmed')
              AND created_at >= date_trunc('day', now() AT TIME ZONE 'UTC')
            "#,
        )
        .bind(wallet_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(total.unwrap_or(0))
    }

    /// Atomically reserve budget and record a sponsored transaction.
    ///
    /// Inserts a `pending` row **only if** doing so keeps today's reserved fees within
    /// `daily_budget_stroops` (a `NULL` budget means unlimited). The check and insert happen in one
    /// statement (a conditional CTE), so concurrent sponsorships can't oversubscribe the budget.
    /// Returns `StoreError::BudgetExceeded` if the budget would be exceeded, or
    /// `StoreError::Conflict` if this `inner_tx_hash` was already sponsored (double-submit).
    pub async fn try_reserve_sponsored_transaction(
        &self,
        wallet_id: Uuid,
        inner_tx_hash: &str,
        fee_stroops: i64,
        daily_budget_stroops: Option<i64>,
    ) -> Result<SponsoredTransaction, StoreError> {
        // The read-then-insert below must be serialized per wallet. A bare conditional CTE is NOT
        // enough: under READ COMMITTED every concurrent transaction computes `spent` from a
        // snapshot taken before the others' inserts are visible, so N requests can each see the
        // same total and all pass the budget guard (observed: 11 reservations against a 10-slot
        // budget under 20 concurrent requests).
        //
        // A transaction-scoped advisory lock keyed on the wallet id makes the check-and-insert
        // mutually exclusive for that wallet, while leaving other wallets fully parallel. The
        // lock is released automatically when the transaction commits or rolls back.
        let mut tx = self.pool.begin().await?;

        // Fold the wallet UUID into a stable i64 lock key.
        let lock_key = {
            let b = wallet_id.as_bytes();
            i64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
                ^ i64::from_be_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]])
        };
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key)
            .execute(&mut *tx)
            .await?;

        let result = sqlx::query_as::<_, SponsoredTransaction>(
            r#"
            WITH spent AS (
                SELECT COALESCE(SUM(fee_stroops), 0)::bigint AS total
                FROM sponsored_transactions
                WHERE wallet_id = $1
                  AND status IN ('pending', 'confirmed')
                  AND created_at >= date_trunc('day', now() AT TIME ZONE 'UTC')
            )
            INSERT INTO sponsored_transactions (wallet_id, inner_tx_hash, fee_stroops, status)
            SELECT $1, $2, $3, 'pending'
            FROM spent
            WHERE $4::bigint IS NULL OR spent.total + $3 <= $4
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(inner_tx_hash)
        .bind(fee_stroops)
        .bind(daily_budget_stroops)
        .fetch_optional(&mut *tx)
        .await;

        // Commit before returning so the reservation (and the lock release) are durable.
        if result.is_ok() {
            tx.commit().await?;
        }

        match result {
            // A row means the insert (and budget check) succeeded.
            Ok(Some(row)) => Ok(row),
            // No row means the WHERE budget guard rejected the insert.
            Ok(None) => Err(StoreError::BudgetExceeded),
            // Unique violation on inner_tx_hash => already sponsored.
            Err(e) => Err(StoreError::from_sqlx_conflict(e)),
        }
    }

    /// Read-only sponsorship projection for the dry-run endpoint (#463): today's spend counted
    /// exactly as [`Store::try_reserve_sponsored_transaction`] counts it, and whether
    /// `inner_tx_hash` was already sponsored. Takes no lock and writes nothing.
    pub async fn sponsorship_projection(
        &self,
        wallet_id: Uuid,
        inner_tx_hash: &str,
    ) -> Result<(i64, bool), StoreError> {
        let row: (i64, bool) = sqlx::query_as(
            r#"
            SELECT
                (SELECT COALESCE(SUM(fee_stroops), 0)::bigint
                 FROM sponsored_transactions
                 WHERE wallet_id = $1
                   AND status IN ('pending', 'confirmed')
                   AND created_at >= date_trunc('day', now() AT TIME ZONE 'UTC')),
                EXISTS (SELECT 1 FROM sponsored_transactions WHERE inner_tx_hash = $2)
            "#,
        )
        .bind(wallet_id)
        .bind(inner_tx_hash)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    /// Update a sponsored transaction's outcome after submission.
    pub async fn finalize_sponsored_transaction(
        &self,
        id: Uuid,
        status: &str,
        fee_bump_tx_hash: Option<&str>,
        error: Option<&str>,
    ) -> Result<(), StoreError> {
        self.update_sponsored_tx_status(id, status, fee_bump_tx_hash, error)
            .await
    }

    /// Insert a sponsored transaction as `pending` (no budget check — see
    /// [`Store::try_reserve_sponsored_transaction`] for the atomic budget-aware insert).
    /// Fails with [`StoreError::Conflict`] if this `inner_tx_hash` was already recorded.
    pub async fn record_sponsored_tx(
        &self,
        new: NewSponsoredTx<'_>,
    ) -> Result<SponsoredTransaction, StoreError> {
        sqlx::query_as::<_, SponsoredTransaction>(
            r#"
            INSERT INTO sponsored_transactions (wallet_id, inner_tx_hash, fee_stroops, status)
            VALUES ($1, $2, $3, 'pending')
            RETURNING *
            "#,
        )
        .bind(new.wallet_id)
        .bind(new.inner_tx_hash)
        .bind(new.fee_stroops)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)
    }

    /// Update a sponsored transaction's status, fee-bump hash, and error.
    pub async fn update_sponsored_tx_status(
        &self,
        id: Uuid,
        status: &str,
        fee_bump_tx_hash: Option<&str>,
        error: Option<&str>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE sponsored_transactions SET status = $2, fee_bump_tx_hash = $3, error = $4 WHERE id = $1",
        )
        .bind(id)
        .bind(status)
        .bind(fee_bump_tx_hash)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Sum of **confirmed** sponsored fees for a wallet so far today (UTC) — i.e. actually spent.
    /// (Pending rows are excluded; for budget *reservation* use
    /// [`Store::sum_sponsored_fees_reserved_today`].)
    pub async fn sum_sponsored_fees_today(&self, wallet_id: Uuid) -> Result<i64, StoreError> {
        let total: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT COALESCE(SUM(fee_stroops), 0)::bigint
            FROM sponsored_transactions
            WHERE wallet_id = $1
              AND status = 'confirmed'
              AND created_at >= date_trunc('day', now() AT TIME ZONE 'UTC')
            "#,
        )
        .bind(wallet_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(total.unwrap_or(0))
    }

    // --- withdrawal allowlist ----------------------------------------------

    /// Fetch a wallet's withdrawal-allowlist config, if one has ever been set. `None` means the
    /// wallet has never touched this feature — treat that the same as `enabled = false`.
    pub async fn get_withdrawal_allowlist_config(
        &self,
        wallet_id: Uuid,
    ) -> Result<Option<WithdrawalAllowlistConfig>, StoreError> {
        let row = sqlx::query_as::<_, WithdrawalAllowlistConfig>(
            "SELECT * FROM withdrawal_allowlist_configs WHERE wallet_id = $1",
        )
        .bind(wallet_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Create or replace a wallet's withdrawal-allowlist toggle.
    pub async fn upsert_withdrawal_allowlist_config(
        &self,
        wallet_id: Uuid,
        enabled: bool,
    ) -> Result<WithdrawalAllowlistConfig, StoreError> {
        sqlx::query_as::<_, WithdrawalAllowlistConfig>(
            r#"
            INSERT INTO withdrawal_allowlist_configs (wallet_id, enabled)
            VALUES ($1, $2)
            ON CONFLICT (wallet_id) DO UPDATE SET
                enabled = EXCLUDED.enabled,
                updated_at = now()
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(enabled)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::Database)
    }

    /// Add an address to a wallet's withdrawal allowlist. `Conflict` if already present.
    pub async fn add_whitelisted_address(
        &self,
        wallet_id: Uuid,
        address: &str,
        label: Option<&str>,
    ) -> Result<WhitelistedAddress, StoreError> {
        sqlx::query_as::<_, WhitelistedAddress>(
            r#"
            INSERT INTO whitelisted_addresses (wallet_id, address, label)
            VALUES ($1, $2, $3)
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(address)
        .bind(label)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)
    }

    /// List a wallet's whitelisted addresses, newest first.
    pub async fn list_whitelisted_addresses(
        &self,
        wallet_id: Uuid,
    ) -> Result<Vec<WhitelistedAddress>, StoreError> {
        let rows = sqlx::query_as::<_, WhitelistedAddress>(
            "SELECT * FROM whitelisted_addresses WHERE wallet_id = $1 ORDER BY created_at DESC",
        )
        .bind(wallet_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Remove a whitelisted address. `NotFound` if it doesn't belong to `wallet_id`.
    pub async fn remove_whitelisted_address(
        &self,
        wallet_id: Uuid,
        entry_id: Uuid,
    ) -> Result<(), StoreError> {
        let result =
            sqlx::query("DELETE FROM whitelisted_addresses WHERE id = $1 AND wallet_id = $2")
                .bind(entry_id)
                .bind(wallet_id)
                .execute(&self.pool)
                .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// `true` if `address` (already normalized to its base `G...` form by the caller) is on
    /// `wallet_id`'s allowlist. Pure existence check — callers first check whether the allowlist
    /// is even `enabled` via [`Store::get_withdrawal_allowlist_config`].
    pub async fn is_address_whitelisted(
        &self,
        wallet_id: Uuid,
        address: &str,
    ) -> Result<bool, StoreError> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM whitelisted_addresses WHERE wallet_id = $1 AND address = $2)",
        )
        .bind(wallet_id)
        .bind(address)
        .fetch_one(&self.pool)
        .await?;
        Ok(exists)
    }
}
