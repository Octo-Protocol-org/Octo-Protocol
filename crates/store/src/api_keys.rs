//! Per-wallet API keys: creation, validation, and deletion.

use uuid::Uuid;

use crate::error::StoreError;
use crate::models::ApiKey;
use crate::Store;

impl Store {
    /// Create or replace the wallet's API key (regenerate). Stores only the hash + display prefix.
    pub async fn upsert_api_key(
        &self,
        wallet_id: Uuid,
        prefix: &str,
        key_hash: &str,
        scopes: &[String],
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<ApiKey, StoreError> {
        sqlx::query_as::<_, ApiKey>(
            r#"
            INSERT INTO api_keys (wallet_id, prefix, key_hash, scopes, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (wallet_id)
            DO UPDATE SET prefix = EXCLUDED.prefix, key_hash = EXCLUDED.key_hash,
                          scopes = EXCLUDED.scopes, expires_at = EXCLUDED.expires_at,
                          last_used_at = NULL, created_at = now()
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(prefix)
        .bind(key_hash)
        .bind(scopes)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::Database)
    }

    /// Insert a new API key (no replace). Returns [`StoreError::Conflict`] if one already exists.
    pub async fn create_api_key(
        &self,
        wallet_id: Uuid,
        prefix: &str,
        key_hash: &str,
        scopes: &[String],
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<ApiKey, StoreError> {
        sqlx::query_as::<_, ApiKey>(
            "INSERT INTO api_keys (wallet_id, prefix, key_hash, scopes, expires_at) \
             VALUES ($1, $2, $3, $4, $5) RETURNING *",
        )
        .bind(wallet_id)
        .bind(prefix)
        .bind(key_hash)
        .bind(scopes)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::Database)
    }

    /// Get the wallet's API key metadata (prefix only — never the secret), if one exists.
    pub async fn get_api_key(&self, wallet_id: Uuid) -> Result<Option<ApiKey>, StoreError> {
        let row = sqlx::query_as::<_, ApiKey>("SELECT * FROM api_keys WHERE wallet_id = $1")
            .bind(wallet_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    /// Validate an unexpired API key and atomically record its latest use.
    pub async fn use_api_key(&self, key_hash: &str) -> Result<Option<ApiKey>, StoreError> {
        let row = sqlx::query_as::<_, ApiKey>(
            "UPDATE api_keys SET last_used_at = now() WHERE key_hash = $1 \
             AND (expires_at IS NULL OR expires_at > now()) RETURNING *",
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Delete (revoke) the API key for a wallet. Returns `Ok(())` even if no key existed.
    pub async fn delete_api_key(&self, wallet_id: Uuid) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM api_keys WHERE wallet_id = $1")
            .bind(wallet_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
