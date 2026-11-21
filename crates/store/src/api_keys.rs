//! Per-wallet API key storage.
//!
//! Only the SHA-256 hash and a short display prefix are persisted; the plaintext key is shown
//! once at creation and never stored. Queries select an explicit column list so new columns
//! (including secret-adjacent ones) are never silently pulled into the `ApiKey` model.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::ApiKey;

/// Columns mapped by [`ApiKey`] — keep in sync with `crates/store/src/models.rs`.
const API_KEY_COLUMNS: &str =
    "id, wallet_id, prefix, key_hash, created_at, scopes, last_used_at, expires_at";

/// Insert a freshly minted key (hash + prefix only) and return the stored row.
pub async fn create(
    pool: &PgPool,
    wallet_id: Uuid,
    prefix: &str,
    key_hash: &str,
    scopes: &[String],
    expires_at: Option<DateTime<Utc>>,
) -> sqlx::Result<ApiKey> {
    let sql = format!(
        "INSERT INTO api_keys (wallet_id, prefix, key_hash, scopes, expires_at) \
         VALUES ($1, $2, $3, $4, $5) RETURNING {API_KEY_COLUMNS}"
    );
    sqlx::query_as::<_, ApiKey>(&sql)
        .bind(wallet_id)
        .bind(prefix)
        .bind(key_hash)
        .bind(scopes)
        .bind(expires_at)
        .fetch_one(pool)
        .await
}

/// Look up a key by its hash, ignoring revoked/expired rows.
pub async fn find_by_hash(pool: &PgPool, key_hash: &str) -> sqlx::Result<Option<ApiKey>> {
    let sql = format!(
        "SELECT {API_KEY_COLUMNS} FROM api_keys \
         WHERE key_hash = $1 AND revoked_at IS NULL \
         AND (expires_at IS NULL OR expires_at > now())"
    );
    sqlx::query_as::<_, ApiKey>(&sql)
        .bind(key_hash)
        .fetch_optional(pool)
        .await
}

/// List every key for a wallet, newest first.
pub async fn list_for_wallet(pool: &PgPool, wallet_id: Uuid) -> sqlx::Result<Vec<ApiKey>> {
    let sql = format!(
        "SELECT {API_KEY_COLUMNS} FROM api_keys WHERE wallet_id = $1 ORDER BY created_at DESC"
    );
    sqlx::query_as::<_, ApiKey>(&sql)
        .bind(wallet_id)
        .fetch_all(pool)
        .await
}

/// Record a successful use of the key.
pub async fn touch_last_used(pool: &PgPool, id: Uuid) -> sqlx::Result<ApiKey> {
    let sql = format!(
        "UPDATE api_keys SET last_used_at = now() WHERE id = $1 RETURNING {API_KEY_COLUMNS}"
    );
    sqlx::query_as::<_, ApiKey>(&sql)
        .bind(id)
        .fetch_one(pool)
        .await
}
