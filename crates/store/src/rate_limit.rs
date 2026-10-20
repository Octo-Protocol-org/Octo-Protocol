//! Per-key rate-limit buckets (fixed-window, database-clock, shared across replicas).

use crate::error::StoreError;
use crate::Store;

impl Store {
    /// Count one hit against the fixed window for `(key, class)` and return the hits so far.
    ///
    /// A single `INSERT .. ON CONFLICT DO UPDATE` is atomic under concurrency (the conflicting
    /// row is locked), so replicas sharing this database share one counter. An expired window is
    /// restarted in place. Uses the database clock, so replica clock skew cannot stretch windows.
    pub async fn rate_limit_hit(
        &self,
        key: &str,
        class: &str,
        window: std::time::Duration,
    ) -> Result<i64, StoreError> {
        let hits: i64 = sqlx::query_scalar(
            r#"
            INSERT INTO rate_limit_buckets (key, class, hits, expires_at)
            VALUES ($1, $2, 1, now() + make_interval(secs => $3))
            ON CONFLICT (key, class) DO UPDATE SET
                hits = CASE WHEN rate_limit_buckets.expires_at <= now() THEN 1
                            ELSE rate_limit_buckets.hits + 1 END,
                expires_at = CASE WHEN rate_limit_buckets.expires_at <= now()
                                  THEN EXCLUDED.expires_at
                                  ELSE rate_limit_buckets.expires_at END
            RETURNING hits
            "#,
        )
        .bind(key)
        .bind(class)
        .bind(window.as_secs_f64())
        .fetch_one(&self.pool)
        .await?;
        Ok(hits)
    }

    /// Delete expired rate-limit windows. Returns the number of rows removed.
    pub async fn prune_rate_limit_buckets(&self) -> Result<u64, StoreError> {
        let result = sqlx::query("DELETE FROM rate_limit_buckets WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}
