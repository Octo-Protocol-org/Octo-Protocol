//! Wallet management: creation, polling backoff, streaming, and key rotation.

use uuid::Uuid;

use crate::error::StoreError;
use crate::models::Wallet;
use crate::{NewClientWallet, NewWallet, Store};

impl Store {
    /// Create a master wallet. Fails with [`StoreError::Conflict`] if the account already exists.
    pub async fn create_wallet(&self, new: NewWallet<'_>) -> Result<Wallet, StoreError> {
        sqlx::query_as::<_, Wallet>(
            r#"
            INSERT INTO wallets
                (network, stellar_account_g, sealed_ciphertext, sealed_nonce, sealed_salt,
                 sealed_scheme, label, user_id, description, custody)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'server')
            RETURNING *
            "#,
        )
        .bind(new.network)
        .bind(new.stellar_account_g)
        .bind(new.sealed_ciphertext)
        .bind(new.sealed_nonce)
        .bind(new.sealed_salt)
        .bind(new.sealed_scheme)
        .bind(new.label)
        .bind(new.user_id)
        .bind(new.description)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)
    }

    /// Attach a gas-tank fee account to a client-custody wallet: stores the tank's sealed seed
    /// and public account. The tank only ever holds fee float — never customer funds.
    ///
    /// `sealed_scheme` must be written alongside the seed: the `wallets_gas_tank_has_seed` CHECK
    /// requires it, and key rotation (`bin/migrate-keys`) needs the tag to know how to open it.
    pub async fn set_gas_tank(
        &self,
        wallet_id: Uuid,
        gas_tank_account_g: &str,
        sealed_ciphertext: &[u8],
        sealed_nonce: &[u8],
        sealed_salt: &[u8],
        sealed_scheme: i16,
    ) -> Result<Wallet, StoreError> {
        sqlx::query_as::<_, Wallet>(
            r#"
            UPDATE wallets
            SET gas_tank_account_g = $2, sealed_ciphertext = $3, sealed_nonce = $4,
                sealed_salt = $5, sealed_scheme = $6, updated_at = now()
            WHERE id = $1 AND custody = 'client' AND gas_tank_account_g IS NULL
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(gas_tank_account_g)
        .bind(sealed_ciphertext)
        .bind(sealed_nonce)
        .bind(sealed_salt)
        .bind(sealed_scheme)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::Conflict) // already has a tank, or not a client wallet
    }

    /// Create a non-custodial wallet: no seed is stored; the server can never sign for it.
    pub async fn create_client_wallet(
        &self,
        new: NewClientWallet<'_>,
    ) -> Result<Wallet, StoreError> {
        sqlx::query_as::<_, Wallet>(
            r#"
            INSERT INTO wallets
                (network, stellar_account_g, label, user_id, description, custody,
                 encrypted_backup)
            VALUES ($1, $2, $3, $4, $5, 'client', $6)
            RETURNING *
            "#,
        )
        .bind(new.network)
        .bind(new.stellar_account_g)
        .bind(new.label)
        .bind(new.user_id)
        .bind(new.description)
        .bind(new.encrypted_backup)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)
    }

    /// List a user's wallets (most recent first), with optional cursor-based pagination.
    ///
    /// Fetching `limit + 1` rows lets the caller detect whether a next page exists without a
    /// separate COUNT query — the same pattern used by `list_sponsored_transactions`.
    pub async fn list_wallets_for_user(
        &self,
        user_id: Uuid,
        limit: i64,
        before_id: Option<Uuid>,
    ) -> Result<Vec<Wallet>, StoreError> {
        let rows = sqlx::query_as::<_, Wallet>(
            r#"
            SELECT * FROM wallets
            WHERE user_id = $1
              AND ($2::uuid IS NULL OR (created_at, id) < (
                  SELECT created_at, id FROM wallets WHERE id = $2
              ))
            ORDER BY created_at DESC, id DESC
            LIMIT $3
            "#,
        )
        .bind(user_id)
        .bind(before_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Paginated version of [`list_wallets_for_user`]: returns at most `limit` rows, newest first.
    /// Pass the last page's final wallet id as `before_id` to fetch the next page.
    pub async fn list_wallets_for_user_page(
        &self,
        user_id: Uuid,
        limit: i64,
        before_id: Option<Uuid>,
    ) -> Result<Vec<Wallet>, StoreError> {
        let rows = sqlx::query_as::<_, Wallet>(
            r#"
            SELECT * FROM wallets
            WHERE user_id = $1
              AND ($2::uuid IS NULL OR (created_at, id) < (
                    SELECT created_at, id FROM wallets WHERE id = $2
                  ))
            ORDER BY created_at DESC, id DESC
            LIMIT $3
            "#,
        )
        .bind(user_id)
        .bind(before_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// List all wallets (used by the ingest supervisor to fan out poll loops).
    pub async fn list_wallets(&self) -> Result<Vec<Wallet>, StoreError> {
        let rows = sqlx::query_as::<_, Wallet>("SELECT * FROM wallets ORDER BY created_at")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows)
    }

    /// Wallets on `network` that are due for an ingest poll, given activity-based backoff.
    ///
    /// A dev/production database accumulates wallets that never see another deposit. Polling all
    /// of them on the same short cycle spends the concurrency budget on dead accounts and delays
    /// the ones that are actually transacting. Idleness is measured by `ingest_cursor.updated_at`,
    /// which is only bumped when a record is actually processed:
    ///
    /// - active (last activity < `active_after_secs`): every tick
    /// - idle: at most once per `idle_interval_secs`
    /// - dormant (last activity older than `dormant_after_secs`): at most once per
    ///   `dormant_interval_secs`
    ///
    /// A wallet with no cursor row has never been polled, so it is always due.
    ///
    /// Unbounded; prefer [`Store::wallets_due_for_poll_page`] when the wallet count can be large.
    pub async fn wallets_due_for_poll(
        &self,
        network: &str,
        active_after_secs: i64,
        idle_interval_secs: i64,
        dormant_after_secs: i64,
        dormant_interval_secs: i64,
    ) -> Result<Vec<Wallet>, StoreError> {
        // `LIMIT NULL` is "no limit" in Postgres, so this is the paged query's full result.
        self.wallets_due_for_poll_page(
            network,
            active_after_secs,
            idle_interval_secs,
            dormant_after_secs,
            dormant_interval_secs,
            None,
            None,
        )
        .await
    }

    /// One keyset page of [`Store::wallets_due_for_poll`], ordered by `id`, with the exact same
    /// backoff filter. Pass the last row's id as `after_id` for the next page; `limit = None`
    /// returns everything. Paging on the unique primary key means no wallet is skipped or
    /// returned twice across page boundaries within one pass.
    #[allow(clippy::too_many_arguments)]
    pub async fn wallets_due_for_poll_page(
        &self,
        network: &str,
        active_after_secs: i64,
        idle_interval_secs: i64,
        dormant_after_secs: i64,
        dormant_interval_secs: i64,
        limit: Option<i64>,
        after_id: Option<Uuid>,
    ) -> Result<Vec<Wallet>, StoreError> {
        let rows = sqlx::query_as::<_, Wallet>(
            r#"
            SELECT w.* FROM wallets w
            LEFT JOIN ingest_cursor c ON c.wallet_id = w.id
            WHERE w.network = $1
              -- Paused wallets are never polled; their cursor waits untouched for a resume.
              AND w.ingest_paused = false
              AND ($6::uuid IS NULL OR w.id > $6)
              -- Never polled, or never saw activity => always due.
              AND (
                c.last_polled_at IS NULL
                OR c.updated_at IS NULL
                OR c.last_polled_at < now() - make_interval(secs =>
                     CASE
                       -- Active: no extra wait, poll every tick.
                       WHEN c.updated_at > now() - make_interval(secs => $2) THEN 0
                       -- Dormant: longest wait between polls.
                       WHEN c.updated_at <= now() - make_interval(secs => $4) THEN $5
                       -- Idle: in between.
                       ELSE $3
                     END)
              )
            ORDER BY w.id
            LIMIT $7
            "#,
        )
        .bind(network)
        .bind(active_after_secs as f64)
        .bind(idle_interval_secs as f64)
        .bind(dormant_after_secs as f64)
        .bind(dormant_interval_secs as f64)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Record that a wallet was polled (whether or not anything new arrived).
    ///
    /// Distinct from [`Store::set_cursor`], which only advances on real activity — the backoff
    /// tiers need both "when did we last see money" and "when did we last look".
    pub async fn mark_polled(&self, wallet_id: Uuid) -> Result<(), StoreError> {
        // `updated_at` is deliberately backdated to the epoch on INSERT: it means "last time this
        // wallet saw activity", and merely looking at a wallet is not activity. Letting it take
        // its `DEFAULT now()` would mark every never-used wallet as freshly active and the
        // backoff tiers would never engage. `set_cursor` is the only writer that advances it.
        sqlx::query(
            r#"
            INSERT INTO ingest_cursor (wallet_id, last_polled_at, updated_at)
            VALUES ($1, now(), 'epoch')
            ON CONFLICT (wallet_id) DO UPDATE SET last_polled_at = now()
            "#,
        )
        .bind(wallet_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Update a wallet's label and/or description. `None` leaves a field unchanged; `Some(None)`
    /// clears it. Archived wallets are refused inside the same statement, so archival can't race it.
    pub async fn update_wallet_details(
        &self,
        id: Uuid,
        label: Option<Option<&str>>,
        description: Option<Option<&str>>,
    ) -> Result<Wallet, StoreError> {
        let updated = sqlx::query_as::<_, Wallet>(
            r#"
            UPDATE wallets SET
                label = CASE WHEN $2 THEN $3 ELSE label END,
                description = CASE WHEN $4 THEN $5 ELSE description END,
                updated_at = now()
            WHERE id = $1 AND archived_at IS NULL
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(label.is_some())
        .bind(label.flatten())
        .bind(description.is_some())
        .bind(description.flatten())
        .fetch_optional(&self.pool)
        .await?;
        match updated {
            Some(w) => Ok(w),
            // No row updated: tell "missing" apart from "archived".
            None => match self.get_wallet(id).await?.archived_at {
                Some(_) => Err(StoreError::WalletArchived),
                None => Err(StoreError::NotFound),
            },
        }
    }

    /// Active wallets on `network` opted into SSE ingest (issue #446), at most `limit` of them.
    pub async fn streaming_wallets(
        &self,
        network: &str,
        limit: i64,
    ) -> Result<Vec<Wallet>, StoreError> {
        let rows = sqlx::query_as::<_, Wallet>(
            "SELECT * FROM wallets
             WHERE network = $1 AND ingest_streaming AND NOT ingest_paused AND archived_at IS NULL
             ORDER BY id LIMIT $2",
        )
        .bind(network)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Opt a wallet in or out of SSE ingest; polling remains the fallback either way.
    pub async fn set_ingest_streaming(&self, wallet_id: Uuid, enabled: bool) -> Result<(), StoreError> {
        let res = sqlx::query(
            "UPDATE wallets SET ingest_streaming = $2, updated_at = now() WHERE id = $1",
        )
        .bind(wallet_id)
        .bind(enabled)
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Pause or resume ingestion for a wallet, returning the updated row.
    ///
    /// Only the flag changes — `ingest_cursor` is deliberately left alone so a resume picks up
    /// from the saved paging token with no gap. `ingest_paused_at` keeps the first pause time
    /// on a repeated pause and is cleared on resume.
    pub async fn set_ingest_paused(
        &self,
        wallet_id: Uuid,
        paused: bool,
    ) -> Result<Wallet, StoreError> {
        sqlx::query_as::<_, Wallet>(
            r#"
            UPDATE wallets SET
                ingest_paused = $2,
                ingest_paused_at = CASE
                    WHEN $2 THEN COALESCE(ingest_paused_at, now())
                    ELSE NULL
                END,
                updated_at = now()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(paused)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)
    }

    /// Fetch a wallet by id.
    pub async fn get_wallet(&self, id: Uuid) -> Result<Wallet, StoreError> {
        sqlx::query_as::<_, Wallet>("SELECT * FROM wallets WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::NotFound)
    }

    /// The newest wallet on `network` that carries a server-sealed seed, if any.
    ///
    /// Used by the startup self-test to prove the configured master key opens real data.
    pub async fn latest_sealed_wallet(&self, network: &str) -> Result<Option<Wallet>, StoreError> {
        Ok(sqlx::query_as::<_, Wallet>(
            "SELECT * FROM wallets WHERE network = $1 AND sealed_ciphertext IS NOT NULL
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(network)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Atomically swap the sealed seed material for a single wallet after a reseal/key-rotation.
    ///
    /// The caller (typically `bin/migrate-keys`) opens the old seed with the old master key,
    /// re-seals it with the new master key via `octo_crypto::reseal`, and then calls this method
    /// to persist the result. The `expected_scheme` guard ensures idempotency: if the row was
    /// already migrated (e.g. by a concurrent runner) the update is silently skipped rather than
    /// overwriting a newer record.
    ///
    /// # Atomicity Guarantee
    ///
    /// This method executes a single SQL `UPDATE` statement. Its atomicity guarantee (ensuring
    /// that a failure mid-write never leaves a wallet row half-migrated or partially updated) relies
    /// entirely on PostgreSQL's native single-statement atomicity semantics. No application-level
    /// transaction wrapper is used; Postgres guarantees that a statement either succeeds completely
    /// or rolls back its effect on the row entirely.
    ///
    /// Returns `true` if the row was updated, `false` if it was already on the target scheme.
    pub async fn reseal_wallet(
        &self,
        wallet_id: Uuid,
        new_ciphertext: &[u8],
        new_nonce: &[u8],
        new_salt: &[u8],
        new_scheme: i16,
        expected_old_scheme: i16,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            r#"
            UPDATE wallets
            SET sealed_ciphertext = $2,
                sealed_nonce       = $3,
                sealed_salt        = $4,
                sealed_scheme      = $5,
                updated_at         = now()
            WHERE id = $1
              AND sealed_scheme = $6
            "#,
        )
        .bind(wallet_id)
        .bind(new_ciphertext)
        .bind(new_nonce)
        .bind(new_salt)
        .bind(new_scheme)
        .bind(expected_old_scheme)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Fetch a page of wallets whose `sealed_scheme` does not equal `target_scheme`, for the
    /// migration backfill job. Returns at most `batch_size` rows ordered by `id` (stable for
    /// resumable cursored iteration). Pass the last returned wallet's `id` as `after_id` on
    /// subsequent calls to page through the full table without re-scanning already-migrated rows.
    pub async fn list_wallets_needing_reseal(
        &self,
        target_scheme: i16,
        batch_size: i64,
        after_id: Option<Uuid>,
    ) -> Result<Vec<Wallet>, StoreError> {
        let rows = sqlx::query_as::<_, Wallet>(
            r#"
            SELECT * FROM wallets
            WHERE sealed_scheme <> $1
              AND ($2::uuid IS NULL OR id > $2)
            ORDER BY id
            LIMIT $3
            "#,
        )
        .bind(target_scheme)
        .bind(after_id)
        .bind(batch_size)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}
