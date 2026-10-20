//! Request idempotency keys: claim, complete, release, and retention sweep.

use uuid::Uuid;

use crate::error::StoreError;
use crate::models::IdempotencyClaim;
use crate::{Store, IDEMPOTENCY_KEY_TTL_SECS};

impl Store {
    /// Claim `key` for one `scope` of `wallet_id` before running a non-idempotent create.
    ///
    /// The insert is atomic, so two concurrent requests with one key can't both win the claim.
    /// An expired row is taken over as a fresh claim. Otherwise the existing row decides: a
    /// different `request_hash` is a [`IdempotencyClaim::Mismatch`], a stored response is a
    /// [`IdempotencyClaim::Replay`], and no response yet is [`IdempotencyClaim::InProgress`].
    pub async fn claim_idempotency_key(
        &self,
        wallet_id: Uuid,
        scope: &str,
        key: &str,
        request_hash: &str,
    ) -> Result<IdempotencyClaim, StoreError> {
        let claimed: Option<i32> = sqlx::query_scalar(
            r#"
            INSERT INTO idempotency_keys (wallet_id, scope, key, request_hash, expires_at)
            VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))
            ON CONFLICT (wallet_id, scope, key) DO UPDATE SET
                request_hash = EXCLUDED.request_hash,
                status_code = NULL,
                response = NULL,
                created_at = now(),
                expires_at = EXCLUDED.expires_at
            WHERE idempotency_keys.expires_at <= now()
            RETURNING 1
            "#,
        )
        .bind(wallet_id)
        .bind(scope)
        .bind(key)
        .bind(request_hash)
        .bind(IDEMPOTENCY_KEY_TTL_SECS as f64)
        .fetch_optional(&self.pool)
        .await?;
        if claimed.is_some() {
            return Ok(IdempotencyClaim::Claimed);
        }

        let (stored_hash, status_code, response): (String, Option<i16>, Option<serde_json::Value>) =
            sqlx::query_as(
                "SELECT request_hash, status_code, response FROM idempotency_keys
                 WHERE wallet_id = $1 AND scope = $2 AND key = $3",
            )
            .bind(wallet_id)
            .bind(scope)
            .bind(key)
            .fetch_one(&self.pool)
            .await?;
        Ok(if stored_hash != request_hash {
            IdempotencyClaim::Mismatch
        } else {
            match (status_code, response) {
                (Some(code), Some(response)) => IdempotencyClaim::Replay {
                    status_code: u16::try_from(code).unwrap_or(500),
                    response,
                },
                _ => IdempotencyClaim::InProgress,
            }
        })
    }

    /// Store the finished response for a claimed key so later retries replay it.
    pub async fn complete_idempotency_key(
        &self,
        wallet_id: Uuid,
        scope: &str,
        key: &str,
        status_code: u16,
        response: &serde_json::Value,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE idempotency_keys SET status_code = $4, response = $5
             WHERE wallet_id = $1 AND scope = $2 AND key = $3 AND response IS NULL",
        )
        .bind(wallet_id)
        .bind(scope)
        .bind(key)
        .bind(i16::try_from(status_code).unwrap_or(500))
        .bind(response)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Release an unfinished claim after the operation failed, so the client can retry the key.
    pub async fn release_idempotency_key(
        &self,
        wallet_id: Uuid,
        scope: &str,
        key: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM idempotency_keys
             WHERE wallet_id = $1 AND scope = $2 AND key = $3 AND response IS NULL",
        )
        .bind(wallet_id)
        .bind(scope)
        .bind(key)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete expired idempotency keys; called by the hourly maintenance loop.
    pub async fn purge_expired_idempotency_keys(&self) -> Result<u64, StoreError> {
        let res = sqlx::query("DELETE FROM idempotency_keys WHERE expires_at <= now()")
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }
}
