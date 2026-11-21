//! User accounts, authentication lockouts, and password management.

use uuid::Uuid;

use crate::error::StoreError;
use crate::models::User;
use crate::Store;

impl Store {
    /// Create a user. `email` should already be lowercased by the caller. Returns
    /// [`StoreError::Conflict`] if the email is already registered.
    pub async fn create_user(&self, email: &str, password_hash: &str) -> Result<User, StoreError> {
        sqlx::query_as::<_, User>(
            "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *",
        )
        .bind(email)
        .bind(password_hash)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)
    }

    /// Set a user's display username. Returns [`StoreError::Conflict`] if another user already
    /// has it (compared case-insensitively, per the `users_username_unique_idx` index).
    pub async fn update_username(&self, user_id: Uuid, username: &str) -> Result<User, StoreError> {
        sqlx::query_as::<_, User>(
            "UPDATE users SET username = $2, updated_at = now() WHERE id = $1 RETURNING *",
        )
        .bind(user_id)
        .bind(username)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)
    }

    /// Delete a user outright. Only safe pre-verification — used to roll back a signup whose
    /// OTP email never went out, so the email isn't stuck as "already registered" forever.
    pub async fn delete_unverified_user(&self, user_id: Uuid) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM users WHERE id = $1 AND email_verified_at IS NULL")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Look up a user by email (caller lowercases).
    pub async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, StoreError> {
        let row = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    /// Fetch a user by id.
    pub async fn get_user(&self, id: Uuid) -> Result<Option<User>, StoreError> {
        let row = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    /// Return the active per-email authentication lock, if any.
    pub async fn auth_locked_until(
        &self,
        email: &str,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, StoreError> {
        Ok(sqlx::query_scalar(
            "SELECT locked_until FROM auth_lockouts WHERE email = lower($1) AND locked_until > now()",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?
        .flatten())
    }

    /// Record a failed login. Five failures in fifteen minutes trigger an exponentially longer lock.
    pub async fn record_auth_failure(&self, email: &str) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO auth_lockouts (email, failed_attempts) VALUES (lower($1), 1)
            ON CONFLICT (email) DO UPDATE SET
                failed_attempts = CASE WHEN auth_lockouts.window_started < now() - interval '15 minutes' THEN 1 ELSE auth_lockouts.failed_attempts + 1 END,
                window_started = CASE WHEN auth_lockouts.window_started < now() - interval '15 minutes' THEN now() ELSE auth_lockouts.window_started END,
                lockout_count = CASE WHEN auth_lockouts.failed_attempts + 1 >= 5 THEN auth_lockouts.lockout_count + 1 ELSE auth_lockouts.lockout_count END,
                locked_until = CASE WHEN auth_lockouts.failed_attempts + 1 >= 5 THEN now() + make_interval(secs => 60 * (1 << LEAST(auth_lockouts.lockout_count, 6))) ELSE auth_lockouts.locked_until END,
                updated_at = now()
            "#,
        )
        .bind(email)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Clear failed-attempt state after successful authentication or an administrative unlock.
    pub async fn reset_auth_failures(&self, email: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM auth_lockouts WHERE email = lower($1)")
            .bind(email)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Mark a user's email as verified.
    pub async fn mark_email_verified(&self, user_id: Uuid) -> Result<(), StoreError> {
        sqlx::query("UPDATE users SET email_verified_at = now() WHERE id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Replace a user's password hash, bump `session_epoch` (revoking every issued token) and
    /// revoke every session row except `keep_session`. Returns the new epoch for the caller's
    /// replacement token.
    pub async fn change_password(
        &self,
        user_id: Uuid,
        new_password_hash: &str,
        keep_session: Option<Uuid>,
    ) -> Result<i32, StoreError> {
        let mut tx = self.pool.begin().await?;
        let epoch: i32 = sqlx::query_scalar(
            r#"
            UPDATE users
            SET password_hash = $2, session_epoch = session_epoch + 1, updated_at = now()
            WHERE id = $1
            RETURNING session_epoch
            "#,
        )
        .bind(user_id)
        .bind(new_password_hash)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::NotFound)?;
        crate::sessions::revoke_sessions_except(&mut tx, user_id, keep_session).await?;
        tx.commit().await?;
        Ok(epoch)
    }

    /// Set a new password after a verified reset and revoke **every** session (no token is issued
    /// by the reset flow, so nothing is kept).
    pub async fn reset_password(
        &self,
        user_id: Uuid,
        new_password_hash: &str,
    ) -> Result<(), StoreError> {
        self.change_password(user_id, new_password_hash, None)
            .await
            .map(|_| ())
    }

    /// Change a user's login email (caller lowercases). Returns [`StoreError::Conflict`] if the
    /// address is already registered.
    pub async fn update_email(&self, user_id: Uuid, email: &str) -> Result<User, StoreError> {
        sqlx::query_as::<_, User>(
            "UPDATE users SET email = $2, updated_at = now() WHERE id = $1 RETURNING *",
        )
        .bind(user_id)
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)?
        .ok_or(StoreError::NotFound)
    }

    /// Update only the password hash, without bumping the session epoch. Used when the caller
    /// upgrades (re-hashes) a correct but outdated hash on successful login.
    pub async fn rehash_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
            .bind(user_id)
            .bind(password_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
