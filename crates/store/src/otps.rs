//! Email one-time passwords (OTPs): issuance, verification, and retention sweep.

use uuid::Uuid;

use crate::error::StoreError;
use crate::Store;

impl Store {
    /// Issue a fresh OTP row. Callers hash the code themselves before calling this.
    pub async fn create_otp(
        &self,
        user_id: Uuid,
        purpose: &str,
        code_hash: &str,
        tx_hash_bound: Option<&str>,
        ttl: chrono::Duration,
    ) -> Result<Uuid, StoreError> {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO email_otps (user_id, purpose, code_hash, tx_hash_bound, expires_at)
             VALUES ($1, $2, $3, $4, now() + $5) RETURNING id",
        )
        .bind(user_id)
        .bind(purpose)
        .bind(code_hash)
        .bind(tx_hash_bound)
        .bind(ttl)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    /// Verify an already-hashed code against the most recent OTP for `(user_id, purpose)` and
    /// consume it. Every attempt is counted atomically *before* the comparison, so concurrent
    /// guesses can't all slip under the attempt cap, and the consume is conditional, so one code
    /// can't be redeemed twice. Callers should surface a generic "invalid or expired code" either
    /// way, so guessing can't distinguish "wrong code" from "no such code exists".
    pub async fn verify_and_consume_otp(
        &self,
        user_id: Uuid,
        purpose: &str,
        code_hash: &str,
        tx_hash_bound: Option<&str>,
    ) -> Result<(), StoreError> {
        const MAX_ATTEMPTS: i16 = 5;

        // Claim one attempt on the latest live code; no row back means none is redeemable.
        let claimed: Option<(Uuid, String, Option<String>)> = sqlx::query_as(
            r#"
            UPDATE email_otps SET attempts = attempts + 1
            WHERE id = (
                SELECT id FROM email_otps WHERE user_id = $1 AND purpose = $2
                ORDER BY created_at DESC LIMIT 1
            )
              AND consumed_at IS NULL AND attempts < $3 AND expires_at > now()
            RETURNING id, code_hash, tx_hash_bound
            "#,
        )
        .bind(user_id)
        .bind(purpose)
        .bind(MAX_ATTEMPTS)
        .fetch_optional(&self.pool)
        .await?;
        let (otp_id, stored_hash, bound) = claimed.ok_or(StoreError::InvalidOtp)?;

        let hash_ok: bool =
            subtle::ConstantTimeEq::ct_eq(stored_hash.as_bytes(), code_hash.as_bytes()).into();
        if !hash_ok || bound.as_deref() != tx_hash_bound {
            return Err(StoreError::InvalidOtp);
        }

        let consumed = sqlx::query(
            "UPDATE email_otps SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL",
        )
        .bind(otp_id)
        .execute(&self.pool)
        .await?;
        if consumed.rows_affected() != 1 {
            return Err(StoreError::InvalidOtp);
        }
        Ok(())
    }

    /// Delete OTP rows that are expired or already consumed and older than `retain_for`.
    ///
    /// Expired rows can never be redeemed. Consumed rows are kept briefly for audit purposes
    /// (e.g. double-consume detection in incident review), after which they serve no purpose.
    ///
    /// Returns the number of rows deleted.
    pub async fn purge_expired_otps(
        &self,
        retain_for: chrono::Duration,
    ) -> Result<u64, StoreError> {
        let result = sqlx::query(
            r#"
            DELETE FROM email_otps
            WHERE
                -- Hard-expired and past the grace window: can never be redeemed.
                (expires_at < now() - $1)
                OR
                -- Already consumed and past the grace window: audit window closed.
                (consumed_at IS NOT NULL AND consumed_at < now() - $1)
            "#,
        )
        .bind(retain_for)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}
