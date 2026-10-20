//! Webhook endpoints and delivery tracking, including the dead-delivery auto-disable sweep.

use uuid::Uuid;

use crate::error::StoreError;
use crate::models::{WebhookDelivery, WebhookEndpoint};
use crate::Store;

impl Store {
    /// Register a webhook endpoint for a wallet.
    pub async fn create_webhook_endpoint(
        &self,
        wallet_id: Uuid,
        url: &str,
        secret: &str,
    ) -> Result<WebhookEndpoint, StoreError> {
        sqlx::query_as::<_, WebhookEndpoint>(
            r#"
            INSERT INTO webhook_endpoints (wallet_id, url, secret)
            VALUES ($1, $2, $3)
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(url)
        .bind(secret)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)
    }

    /// List the active webhook endpoints for a wallet (active and not soft-deleted).
    pub async fn active_webhook_endpoints(
        &self,
        wallet_id: Uuid,
    ) -> Result<Vec<WebhookEndpoint>, StoreError> {
        let rows = sqlx::query_as::<_, WebhookEndpoint>(
            "SELECT * FROM webhook_endpoints WHERE wallet_id = $1 AND active = true AND deleted_at IS NULL",
        )
        .bind(wallet_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Soft delete a webhook endpoint by setting its deleted_at timestamp and deactivating it.
    pub async fn delete_webhook(&self, id: Uuid) -> Result<(), StoreError> {
        sqlx::query("UPDATE webhook_endpoints SET deleted_at = now(), active = false WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Soft delete a webhook endpoint (alias for delete_webhook).
    pub async fn delete_webhook_endpoint(&self, id: Uuid) -> Result<(), StoreError> {
        self.delete_webhook(id).await
    }

    /// List webhook endpoints for a wallet, optionally including soft-deleted ones.
    pub async fn list_webhooks(
        &self,
        wallet_id: Uuid,
        include_deleted: bool,
    ) -> Result<Vec<WebhookEndpoint>, StoreError> {
        let query = if include_deleted {
            "SELECT * FROM webhook_endpoints WHERE wallet_id = $1 ORDER BY created_at ASC"
        } else {
            "SELECT * FROM webhook_endpoints WHERE wallet_id = $1 AND deleted_at IS NULL ORDER BY created_at ASC"
        };
        let rows = sqlx::query_as::<_, WebhookEndpoint>(query)
            .bind(wallet_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows)
    }

    /// List webhook endpoints for a wallet (alias for list_webhooks).
    pub async fn list_webhook_endpoints(
        &self,
        wallet_id: Uuid,
        include_deleted: bool,
    ) -> Result<Vec<WebhookEndpoint>, StoreError> {
        self.list_webhooks(wallet_id, include_deleted).await
    }

    /// Deactivate a webhook endpoint by setting its active status to false.
    pub async fn deactivate_webhook_endpoint(&self, id: Uuid) -> Result<(), StoreError> {
        sqlx::query("UPDATE webhook_endpoints SET active = false WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Fetch a single webhook endpoint by id. `NotFound` if it does not exist.
    ///
    /// Callers must still check `wallet_id` before returning data, so that an endpoint belonging
    /// to another wallet is reported as 404 rather than 403 (no existence leak).
    pub async fn get_webhook_endpoint(&self, id: Uuid) -> Result<WebhookEndpoint, StoreError> {
        sqlx::query_as::<_, WebhookEndpoint>("SELECT * FROM webhook_endpoints WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::NotFound)
    }

    /// An endpoint's delivery history, newest first, capped at `limit` rows.
    pub async fn list_webhook_deliveries(
        &self,
        endpoint_id: Uuid,
        limit: i64,
    ) -> Result<Vec<WebhookDelivery>, StoreError> {
        let rows = sqlx::query_as::<_, WebhookDelivery>(
            r#"
            SELECT * FROM webhook_deliveries
            WHERE endpoint_id = $1
            ORDER BY created_at DESC, id DESC
            LIMIT $2
            "#,
        )
        .bind(endpoint_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// An endpoint's delivery history filtered to one `status` (e.g. `dead`), newest first.
    pub async fn list_webhook_deliveries_with_status(
        &self,
        endpoint_id: Uuid,
        status: &str,
        limit: i64,
    ) -> Result<Vec<WebhookDelivery>, StoreError> {
        let rows = sqlx::query_as::<_, WebhookDelivery>(
            r#"
            SELECT * FROM webhook_deliveries
            WHERE endpoint_id = $1 AND status = $2
            ORDER BY created_at DESC, id DESC
            LIMIT $3
            "#,
        )
        .bind(endpoint_id)
        .bind(status)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Fetch one delivery scoped to its endpoint, so a delivery id can't be used across endpoints.
    pub async fn get_webhook_delivery(
        &self,
        endpoint_id: Uuid,
        id: Uuid,
    ) -> Result<WebhookDelivery, StoreError> {
        sqlx::query_as::<_, WebhookDelivery>(
            "SELECT * FROM webhook_deliveries WHERE id = $1 AND endpoint_id = $2",
        )
        .bind(id)
        .bind(endpoint_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)
    }

    /// Track an endpoint's dead-delivery streak and deactivate it at `auto_disable_after` (#458).
    ///
    /// A delivered event resets the streak. Returns true only on the call that disabled it.
    pub async fn record_webhook_endpoint_outcome(
        &self,
        endpoint_id: Uuid,
        dead: bool,
        auto_disable_after: Option<i32>,
    ) -> Result<bool, StoreError> {
        if !dead {
            sqlx::query(
                "UPDATE webhook_endpoints SET consecutive_dead_deliveries = 0 \
                 WHERE id = $1 AND consecutive_dead_deliveries <> 0",
            )
            .bind(endpoint_id)
            .execute(&self.pool)
            .await?;
            return Ok(false);
        }

        // SET expressions read pre-update values, so `consecutive_dead_deliveries + 1` is the new streak.
        let disabled: Option<bool> = sqlx::query_scalar(
            r#"
            WITH hit AS (
                SELECT id, active AS was_active,
                       ($2::int IS NOT NULL AND consecutive_dead_deliveries + 1 >= $2) AS trips
                FROM webhook_endpoints WHERE id = $1 FOR UPDATE
            )
            UPDATE webhook_endpoints e SET
                consecutive_dead_deliveries = e.consecutive_dead_deliveries + 1,
                active = CASE WHEN hit.trips THEN false ELSE e.active END,
                auto_disabled_at = CASE WHEN hit.trips AND hit.was_active THEN now()
                                        ELSE e.auto_disabled_at END
            FROM hit WHERE e.id = hit.id
            RETURNING (hit.trips AND hit.was_active)
            "#,
        )
        .bind(endpoint_id)
        .bind(auto_disable_after)
        .fetch_optional(&self.pool)
        .await?;
        Ok(disabled.unwrap_or(false))
    }

    /// Record a webhook delivery attempt (audit log). Returns the delivery id.
    pub async fn log_webhook_delivery(
        &self,
        endpoint_id: Uuid,
        event_type: &str,
        payload: &serde_json::Value,
        status: &str,
        attempts: i32,
        response_code: Option<i32>,
    ) -> Result<Uuid, StoreError> {
        let id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO webhook_deliveries
                (endpoint_id, event_type, payload, status, attempts, response_code)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
        )
        .bind(endpoint_id)
        .bind(event_type)
        .bind(payload)
        .bind(status)
        .bind(attempts)
        .bind(response_code)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    /// Delete old webhook delivery rows to keep the table bounded.
    ///
    /// Retains the most recent `keep_per_endpoint` deliveries per endpoint and hard-deletes
    /// anything older than `older_than`. Both conditions must hold — rows are only deleted when
    /// they are both old enough *and* beyond the per-endpoint keep window.
    ///
    /// Returns the number of rows deleted.
    pub async fn purge_old_webhook_deliveries(
        &self,
        older_than: chrono::Duration,
        keep_per_endpoint: i64,
    ) -> Result<u64, StoreError> {
        let result = sqlx::query(
            r#"
            DELETE FROM webhook_deliveries
            WHERE id IN (
                SELECT id FROM (
                    SELECT id,
                           row_number() OVER (
                               PARTITION BY endpoint_id
                               ORDER BY created_at DESC, id DESC
                           ) AS rn,
                           created_at
                    FROM webhook_deliveries
                ) ranked
                WHERE rn > $2
                  AND created_at < now() - $1
            )
            "#,
        )
        .bind(older_than)
        .bind(keep_per_endpoint)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}
