//! Login sessions: creation, validation, extension, revocation, and retention sweep.

use uuid::Uuid;

use crate::error::StoreError;
use crate::models::Session;
use crate::Store;

impl Store {
    /// Open a login session. Its id goes into the JWT's `sid` claim.
    pub async fn create_session(
        &self,
        user_id: Uuid,
        user_agent_hash: Option<&str>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Session, StoreError> {
        let row = sqlx::query_as::<_, Session>(
            "INSERT INTO sessions (user_id, user_agent_hash, expires_at)
             VALUES ($1, $2, $3) RETURNING *",
        )
        .bind(user_id)
        .bind(user_agent_hash)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    /// Push a live session's expiry out to `expires_at` (token refresh). Returns `false` when the
    /// session is not the user's, is revoked, or has already expired.
    pub async fn extend_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, StoreError> {
        let res = sqlx::query(
            "UPDATE sessions SET expires_at = $3, last_seen_at = now()
             WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > now()",
        )
        .bind(session_id)
        .bind(user_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }

    /// One-round-trip check run on every authenticated request: the user still exists at
    /// `session_epoch`, the token hash is not deny-listed, and (for tokens that carry one) the
    /// session is live. Also bumps the session's `last_seen_at`, at most once a minute.
    pub async fn is_session_valid(
        &self,
        token_hash: &str,
        user_id: Uuid,
        session_epoch: i32,
        session_id: Option<Uuid>,
    ) -> Result<bool, StoreError> {
        let valid: bool = sqlx::query_scalar(
            r#"
            WITH touched AS (
                UPDATE sessions SET last_seen_at = now()
                WHERE id = $4 AND user_id = $2 AND revoked_at IS NULL
                  AND last_seen_at < now() - interval '60 seconds'
                RETURNING 1
            )
            SELECT EXISTS (
                SELECT 1 FROM users WHERE id = $2 AND session_epoch = $3 AND deleted_at IS NULL
            )
               AND NOT EXISTS (
                   SELECT 1 FROM token_denylist WHERE token_hash = $1 AND expires_at > now()
               )
               AND ($4::uuid IS NULL OR EXISTS (
                   SELECT 1 FROM sessions
                   WHERE id = $4 AND user_id = $2 AND revoked_at IS NULL AND expires_at > now()
               ))
            "#,
        )
        .bind(token_hash)
        .bind(user_id)
        .bind(session_epoch)
        .bind(session_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(valid)
    }

    /// A user's live (unrevoked, unexpired) sessions, most recently used first. Capped at 100.
    pub async fn list_active_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, StoreError> {
        let rows = sqlx::query_as::<_, Session>(
            "SELECT * FROM sessions
             WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
             ORDER BY last_seen_at DESC, id
             LIMIT 100",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Revoke one of the user's sessions. Scoped by `user_id`, so another user's session id
    /// matches nothing; returns `false` in that case (and when already revoked).
    pub async fn revoke_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
    ) -> Result<bool, StoreError> {
        let res = sqlx::query(
            "UPDATE sessions SET revoked_at = now()
             WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
        )
        .bind(session_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }

    /// Revoke every session except `keep` (all of them when `None`), and bump `session_epoch` so
    /// tokens that predate session tracking (no `sid`) die too. Returns
    /// `(new_epoch, sessions_revoked)`; the caller must re-issue its token under the new epoch.
    pub async fn revoke_other_sessions(
        &self,
        user_id: Uuid,
        keep: Option<Uuid>,
    ) -> Result<(i32, u64), StoreError> {
        let mut tx = self.pool.begin().await?;
        let epoch: i32 = sqlx::query_scalar(
            "UPDATE users SET session_epoch = session_epoch + 1, updated_at = now()
             WHERE id = $1 RETURNING session_epoch",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::NotFound)?;
        let revoked = revoke_sessions_except(&mut tx, user_id, keep).await?;
        tx.commit().await?;
        Ok((epoch, revoked))
    }

    /// Delete sessions that expired more than a day ago (kept briefly for incident review).
    pub async fn purge_expired_sessions(&self) -> Result<u64, StoreError> {
        let res = sqlx::query("DELETE FROM sessions WHERE expires_at < now() - interval '1 day'")
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }
}

/// Revoke all of a user's live sessions except `keep`, inside the caller's transaction.
///
/// `pub(crate)` so that [`crate::users`] (which calls this inside `change_password`) can use it.
pub(crate) async fn revoke_sessions_except(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    keep: Option<Uuid>,
) -> Result<u64, StoreError> {
    let res = sqlx::query(
        "UPDATE sessions SET revoked_at = now()
         WHERE user_id = $1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR id <> $2)",
    )
    .bind(user_id)
    .bind(keep)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected())
}
