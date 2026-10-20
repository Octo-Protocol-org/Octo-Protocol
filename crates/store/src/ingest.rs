//! Deposit recording, transaction history, withdrawal management, and the ingest cursor/leader lock.

use uuid::Uuid;

use crate::error::StoreError;
use crate::models::{NewDeposit, Transaction, TransactionFilter, Withdrawal};
use crate::{IngestLeaderLock, NewWithdrawal, NewWithdrawalTransaction, Store, INGEST_LOCK_CLASS};

impl Store {
    /// Idempotently record a confirmed deposit.
    ///
    /// Returns `Ok(Some(tx))` on first insert and `Ok(None)` if this exact on-chain operation was
    /// already recorded (the `(tx_hash, operation_index)` unique index fired) — so replays and
    /// reorged re-deliveries never double-credit.
    pub async fn record_deposit(&self, d: &NewDeposit) -> Result<Option<Transaction>, StoreError> {
        let result = sqlx::query_as::<_, Transaction>(
            r#"
            INSERT INTO transactions
                (wallet_id, address_id, direction, asset_code, asset_issuer, amount_stroops,
                 source_account, destination_account, stellar_tx_hash, operation_index,
                 horizon_op_id, ledger, memo_id, status)
            VALUES ($1, $2, 'deposit', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'confirmed')
            RETURNING *
            "#,
        )
        .bind(d.wallet_id)
        .bind(d.address_id)
        .bind(&d.asset_code)
        .bind(&d.asset_issuer)
        .bind(d.amount_stroops)
        .bind(&d.source_account)
        .bind(&d.destination_account)
        .bind(&d.stellar_tx_hash)
        .bind(d.operation_index)
        .bind(&d.horizon_op_id)
        .bind(d.ledger)
        .bind(d.memo_id)
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(tx) => Ok(Some(tx)),
            Err(e) => match StoreError::from_sqlx_conflict(e) {
                StoreError::Conflict => Ok(None), // already recorded — benign
                other => Err(other),
            },
        }
    }

    /// List transactions for a wallet (most recent first), with optional cursor-based pagination.
    pub async fn list_transactions(
        &self,
        wallet_id: Uuid,
        limit: i64,
        before_id: Option<Uuid>,
    ) -> Result<Vec<Transaction>, StoreError> {
        let rows = sqlx::query_as::<_, Transaction>(
            r#"
            SELECT * FROM transactions
            WHERE wallet_id = $1
              AND ($2::uuid IS NULL OR (created_at, id) < (
                  SELECT created_at, id FROM transactions WHERE id = $2
              ))
            ORDER BY created_at DESC, id DESC
            LIMIT $3
            "#,
        )
        .bind(wallet_id)
        .bind(before_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Link a quarantined deposit to an address without ever replacing an existing attribution.
    pub async fn attribute_quarantined_deposit(
        &self,
        transaction_id: Uuid,
        address_id: Uuid,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE transactions SET address_id = $2 WHERE id = $1 AND address_id IS NULL",
        )
        .bind(transaction_id)
        .bind(address_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Return only deposits awaiting attribution for a wallet, newest first.
    pub async fn list_quarantined_transactions(
        &self,
        wallet_id: Uuid,
    ) -> Result<Vec<Transaction>, StoreError> {
        Ok(sqlx::query_as::<_, Transaction>(
            "SELECT * FROM transactions WHERE wallet_id = $1 AND direction = 'deposit' AND address_id IS NULL ORDER BY created_at DESC, id DESC",
        )
        .bind(wallet_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Filtered, keyset-paginated transaction history: at most `limit` rows, newest first.
    ///
    /// Pass the last page's final transaction id as `before_id` to fetch the next page. The cursor
    /// is resolved within this wallet only, and ordering is the total order `(created_at, id)`, so
    /// pages stay stable under any filter combination — filters only narrow the set. Served by
    /// `idx_tx_wallet_created` / `idx_tx_wallet_asset_created` (migration 0033).
    pub async fn list_transactions_page(
        &self,
        wallet_id: Uuid,
        filter: &TransactionFilter,
        limit: i64,
        before_id: Option<Uuid>,
    ) -> Result<Vec<Transaction>, StoreError> {
        let rows = sqlx::query_as::<_, Transaction>(
            r#"
            SELECT * FROM transactions
            WHERE wallet_id = $1
              AND ($2::uuid IS NULL OR (created_at, id) < (
                    SELECT created_at, id FROM transactions WHERE id = $2 AND wallet_id = $1
                  ))
              AND ($3::text IS NULL OR direction = $3)
              AND ($4::text IS NULL OR status = $4)
              AND ($5::text IS NULL OR asset_code = $5)
              AND ($6::text IS NULL OR asset_issuer = $6)
              AND ($7::timestamptz IS NULL OR created_at >= $7)
              AND ($8::timestamptz IS NULL OR created_at < $8)
            ORDER BY created_at DESC, id DESC
            LIMIT $9
            "#,
        )
        .bind(wallet_id)
        .bind(before_id)
        .bind(filter.direction.as_deref())
        .bind(filter.status.as_deref())
        .bind(filter.asset_code.as_deref())
        .bind(filter.asset_issuer.as_deref())
        .bind(filter.from)
        .bind(filter.to)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Fetch a single transaction by id.
    pub async fn get_transaction(&self, id: Uuid) -> Result<Option<Transaction>, StoreError> {
        let row = sqlx::query_as::<_, Transaction>("SELECT * FROM transactions WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    // --- withdrawals ------------------------------------------------------

    /// Cheap existence check on `(wallet_id, idempotency_key)`, used to short-circuit a retried
    /// request with a 409 **before** running any pre-flight Horizon checks — a key that has
    /// already been consumed doesn't need its request re-validated against the chain.
    pub async fn withdrawal_exists(
        &self,
        wallet_id: Uuid,
        idempotency_key: &str,
    ) -> Result<bool, StoreError> {
        let found: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM withdrawals WHERE wallet_id = $1 AND idempotency_key = $2",
        )
        .bind(wallet_id)
        .bind(idempotency_key)
        .fetch_optional(&self.pool)
        .await?;
        Ok(found.is_some())
    }

    /// Record an outbound transfer in the `transactions` history (the table the dashboard
    /// lists). Idempotent per `(wallet_id, tx hash)`: a repeat call only advances a row that is
    /// still `pending`, so a settled outcome is never overwritten. Returns `None` when the row
    /// already existed in a final state.
    pub async fn record_withdrawal_transaction(
        &self,
        new: NewWithdrawalTransaction<'_>,
    ) -> Result<Option<Transaction>, StoreError> {
        let row = sqlx::query_as::<_, Transaction>(
            r#"
            INSERT INTO transactions
                (wallet_id, direction, asset_code, asset_issuer, amount_stroops,
                 source_account, destination_account, stellar_tx_hash, status, ledger, metadata)
            VALUES ($1, 'withdrawal', $2, $3, $4, $5, $6, $7, $8, $9,
                    CASE WHEN $10::bigint IS NULL THEN '{}'::jsonb
                         ELSE jsonb_build_object('max_time', $10::bigint) END)
            ON CONFLICT (wallet_id, stellar_tx_hash)
                WHERE stellar_tx_hash IS NOT NULL AND direction = 'withdrawal'
            DO UPDATE SET status = EXCLUDED.status,
                          ledger = COALESCE(EXCLUDED.ledger, transactions.ledger)
                WHERE transactions.status = 'pending'
            RETURNING *
            "#,
        )
        .bind(new.wallet_id)
        .bind(new.asset_code)
        .bind(new.asset_issuer)
        .bind(new.amount_stroops)
        .bind(new.source_account)
        .bind(new.destination_account)
        .bind(new.stellar_tx_hash)
        .bind(new.status)
        .bind(new.ledger)
        .bind(new.max_time)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Withdrawal history rows still `pending` after `older_than`, oldest first.
    pub async fn list_stale_pending_withdrawals(
        &self,
        older_than: std::time::Duration,
        limit: i64,
    ) -> Result<Vec<Transaction>, StoreError> {
        let rows = sqlx::query_as::<_, Transaction>(
            r#"
            SELECT * FROM transactions
            WHERE direction = 'withdrawal' AND status = 'pending'
              AND created_at < now() - make_interval(secs => $1)
            ORDER BY created_at
            LIMIT $2
            "#,
        )
        .bind(older_than.as_secs_f64())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Move a `pending` withdrawal row to its final `status`. Returns `false` when the row was
    /// already settled, which makes concurrent or repeated reconciler runs harmless.
    pub async fn settle_pending_withdrawal(
        &self,
        id: Uuid,
        status: &str,
        ledger: Option<i64>,
        reason: Option<&str>,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            r#"
            UPDATE transactions
            SET status = $2,
                ledger = COALESCE($3, ledger),
                metadata = CASE WHEN $4::text IS NULL THEN metadata
                                ELSE metadata || jsonb_build_object('reconcile_reason', $4::text) END
            WHERE id = $1 AND direction = 'withdrawal' AND status = 'pending'
            "#,
        )
        .bind(id)
        .bind(status)
        .bind(ledger)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Create a withdrawal intent. Idempotent on `(wallet_id, idempotency_key)`: a retried request
    /// with the same key returns [`StoreError::Conflict`] instead of creating a second payout.
    pub async fn create_withdrawal(
        &self,
        new: NewWithdrawal<'_>,
    ) -> Result<Withdrawal, StoreError> {
        sqlx::query_as::<_, Withdrawal>(
            r#"
            INSERT INTO withdrawals
                (wallet_id, idempotency_key, destination_account, asset_code, asset_issuer,
                 amount_stroops, memo_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(new.wallet_id)
        .bind(new.idempotency_key)
        .bind(new.destination_account)
        .bind(new.asset_code)
        .bind(new.asset_issuer)
        .bind(new.amount_stroops)
        .bind(new.memo_id)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)
    }

    /// Update a withdrawal's status (and optional tx hash) after submission.
    pub async fn update_withdrawal_status(
        &self,
        id: Uuid,
        status: &str,
        stellar_tx_hash: Option<&str>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE withdrawals SET status = $2, stellar_tx_hash = $3, updated_at = now() WHERE id = $1",
        )
        .bind(id)
        .bind(status)
        .bind(stellar_tx_hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // --- per-address received totals ---------------------------------------

    /// Lifetime total (in stroops) of confirmed deposits credited to one generated address.
    pub async fn sum_deposits_for_address(&self, address_id: Uuid) -> Result<i64, StoreError> {
        let total: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT COALESCE(SUM(amount_stroops), 0)::bigint
            FROM transactions
            WHERE address_id = $1 AND direction = 'deposit' AND status = 'confirmed'
            "#,
        )
        .bind(address_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(total.unwrap_or(0))
    }

    /// Batched version of [`Store::sum_deposits_for_address`] for an address list page: returns
    /// `(address_id, total_stroops)` pairs in one round trip instead of N.
    pub async fn sum_deposits_for_addresses(
        &self,
        address_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, i64)>, StoreError> {
        if address_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows: Vec<(Uuid, i64)> = sqlx::query_as(
            r#"
            SELECT address_id, COALESCE(SUM(amount_stroops), 0)::bigint AS total
            FROM transactions
            WHERE address_id = ANY($1) AND direction = 'deposit' AND status = 'confirmed'
            GROUP BY address_id
            "#,
        )
        .bind(address_ids)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    // --- ingest cursor ----------------------------------------------------

    /// Read the saved Horizon paging token for a wallet, if any.
    pub async fn get_cursor(&self, wallet_id: Uuid) -> Result<Option<String>, StoreError> {
        let token: Option<String> =
            sqlx::query_scalar("SELECT paging_token FROM ingest_cursor WHERE wallet_id = $1")
                .bind(wallet_id)
                .fetch_optional(&self.pool)
                .await?
                .flatten();
        Ok(token)
    }

    /// Upsert the Horizon paging token for a wallet (durable resume point).
    pub async fn set_cursor(&self, wallet_id: Uuid, paging_token: &str) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO ingest_cursor (wallet_id, paging_token, updated_at)
            VALUES ($1, $2, now())
            ON CONFLICT (wallet_id)
            DO UPDATE SET paging_token = EXCLUDED.paging_token, updated_at = now()
            "#,
        )
        .bind(wallet_id)
        .bind(paging_token)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // --- ingest leader lock -----------------------------------------------

    /// Try once to become the ingest leader for `network`; `None` means another instance holds it.
    ///
    /// Uses a session-level `pg_try_advisory_lock`, so the lock is tied to one connection. On
    /// success that connection is detached from the pool (see [`IngestLeaderLock`]); on failure
    /// it goes straight back, holding nothing.
    pub async fn try_acquire_ingest_leader(
        &self,
        network: &str,
    ) -> Result<Option<IngestLeaderLock>, StoreError> {
        let mut conn = self.pool.acquire().await?;
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1, hashtext($2))")
            .bind(INGEST_LOCK_CLASS)
            .bind(network)
            .fetch_one(&mut *conn)
            .await?;
        Ok(acquired.then(|| IngestLeaderLock {
            conn: conn.detach(),
            network: network.to_string(),
        }))
    }
}
