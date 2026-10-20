//! JWT token deny-list: revocation, lookup, and expired-entry pruning.

use uuid::Uuid;

use crate::error::StoreError;
use crate::Store;

impl Store {
    /// Add a token to the deny-list so it cannot be replayed after logout.
    ///
    /// `token_hash` must be the **SHA-256 hex** of the raw JWT (never the token itself).
    /// `expires_at` should mirror the token's own `exp` claim so that rows can be pruned once
    /// they are past their natural expiry and cannot match any valid token anyway.
    ///
    /// Inserting the same hash twice is harmless (ON CONFLICT DO NOTHING).
    pub async fn denylist_token(
        &self,
        token_hash: &str,
        user_id: Uuid,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO token_denylist (token_hash, user_id, expires_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (token_hash) DO NOTHING
            "#,
        )
        .bind(token_hash)
        .bind(user_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Returns `true` if the token hash is present in the deny-list **and** has not yet expired.
    ///
    /// Expired rows are logically irrelevant (the token itself would fail `verify_token`'s expiry
    /// check), but this query skips them so a slow pruning job doesn't affect correctness.
    pub async fn is_token_denylisted(&self, token_hash: &str) -> Result<bool, StoreError> {
        let found: Option<bool> = sqlx::query_scalar(
            "SELECT true FROM token_denylist WHERE token_hash = $1 AND expires_at > now() LIMIT 1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(found.is_some())
    }

    /// Revoke a JWT by inserting it into the deny-list.
    ///
    /// `expires_at` should match the token's `exp` claim (converted from Unix seconds). Duplicate
    /// revocations (same token) are silently ignored via `ON CONFLICT DO NOTHING`.
    pub async fn revoke_token(
        &self,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO token_denylist (token, expires_at)
            VALUES ($1, $2)
            ON CONFLICT (token) DO NOTHING
            "#,
        )
        .bind(token)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Return `true` if the token has been revoked (is in the deny-list).
    pub async fn is_token_revoked(&self, token: &str) -> Result<bool, StoreError> {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM token_denylist WHERE token = $1)")
                .bind(token)
                .fetch_one(&self.pool)
                .await?;
        Ok(exists)
    }

    /// Delete expired deny-list entries (those whose `expires_at` is in the past).
    ///
    /// Intended to be called periodically (e.g. once per hour in a background task) to prevent
    /// unbounded table growth. Safe to skip — expired tokens are rejected by `verify_token()`
    /// regardless of the deny-list.
    pub async fn purge_expired_tokens(&self) -> Result<u64, StoreError> {
        let result = sqlx::query("DELETE FROM token_denylist WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}
