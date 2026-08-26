//! Store error type.

use thiserror::Error;

/// Errors from the persistence layer.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Underlying database error.
    #[error("database error")]
    Database(#[from] sqlx::Error),

    /// A migration failed to apply.
    #[error("migration error")]
    Migration(#[from] sqlx::migrate::MigrateError),

    /// A uniqueness constraint was violated (e.g. duplicate on-chain tx, or idempotency key).
    /// Callers use this to make inserts idempotent without leaking DB internals.
    #[error("conflict: record already exists")]
    Conflict,

    /// A requested row was not found.
    #[error("not found")]
    NotFound,

    /// The daily sponsorship budget would be exceeded by this request.
    #[error("daily sponsorship budget exceeded")]
    BudgetExceeded,

    /// An OTP was wrong, expired, already used, over the attempt limit, or tx-hash mismatched.
    #[error("invalid or expired code")]
    InvalidOtp,

    /// An `amount_stroops` value could not be represented as an [`octo_chain::Amount`] (e.g.
    /// negative). This should be unreachable in practice — `amount_stroops` columns already carry
    /// a `> 0` check constraint — but the conversion is fallible on principle: an amount
    /// conversion must never silently truncate or wrap.
    #[error("invalid amount: {0}")]
    InvalidAmount(#[from] octo_chain::AmountError),
}

impl StoreError {
    /// Map a raw sqlx error to [`StoreError::Conflict`] when it is a unique-violation, otherwise
    /// pass it through. Lets callers treat "already inserted" as a benign no-op.
    pub(crate) fn from_sqlx_conflict(err: sqlx::Error) -> Self {
        if let sqlx::Error::Database(ref dbe) = err {
            // Postgres unique_violation = SQLSTATE 23505.
            if dbe.code().as_deref() == Some("23505") {
                return StoreError::Conflict;
            }
        }
        StoreError::Database(err)
    }
}
