//! Audit log queries (append and list). The append-only hash-chain logic lives in `audit_chain.rs`.

use uuid::Uuid;

use crate::error::StoreError;
use crate::models::AuditLog;
use crate::Store;

impl Store {
    /// List a user's audit logs (most recent first), optionally filtered by `category` and a
    /// case-insensitive `search` over the action/target. Capped at `limit` rows.
    pub async fn list_audit_logs(
        &self,
        user_id: Uuid,
        category: Option<&str>,
        search: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AuditLog>, StoreError> {
        // Build with optional filters; `$2`/`$3` are NULL when not provided.
        let rows = sqlx::query_as::<_, AuditLog>(
            r#"
            SELECT * FROM audit_logs
            WHERE user_id = $1
              AND ($2::text IS NULL OR category = $2)
              AND ($3::text IS NULL OR action ILIKE '%' || $3 || '%'
                                    OR coalesce(target, '') ILIKE '%' || $3 || '%')
            ORDER BY created_at DESC
            LIMIT $4
            "#,
        )
        .bind(user_id)
        .bind(category)
        .bind(search)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}
