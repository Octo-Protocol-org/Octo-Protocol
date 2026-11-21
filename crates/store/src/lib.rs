//! Postgres persistence for octo (sqlx).
//!
//! Tables: `wallets`, `addresses`, `transactions`, `withdrawals`, `webhook_endpoints`,
//! `webhook_deliveries`, `ingest_cursor` — see `migrations/0001_init.sql`.
//!
//! Security-relevant guarantees implemented here (see `docs/threat-model.md`):
//! - All queries are parameterized (no string-built SQL) → no SQL injection.
//! - [`Store::allocate_address`] / [`Store::allocate_addresses`] increment the per-wallet muxed-id
//!   counter **atomically** inside a transaction, so concurrent address creation (single or batch)
//!   can't collide or reuse an id, and a batch is all-or-nothing.
//! - [`Store::record_deposit`] is **idempotent** on the immutable `horizon_op_id` unique index,
//!   so a replayed/reorged Horizon event cannot double-credit.
//! - [`Store::create_withdrawal`] is idempotent on `(wallet_id, idempotency_key)`.
//!
//! # Module structure
//!
//! Each domain has its own module with an `impl Store` block:
//!
//! | Module | Domain |
//! |---|---|
//! | [`users`] | User accounts, auth lockouts, password management |
//! | [`otps`] | Email OTPs (issuance, verification, sweep) |
//! | [`audit_logs`] | Audit log queries |
//! | [`audit_chain`] | HMAC hash-chain over audit rows |
//! | [`api_keys`] | Per-wallet API keys |
//! | [`wallets`] | Wallet CRUD, ingest backoff, key rotation |
//! | [`addresses`] | Address allocation (atomic counter) |
//! | [`ingest`] | Deposits, transaction history, withdrawals, cursor/leader lock |
//! | [`sponsorship`] | Gas-fee sponsorship and withdrawal allowlist |
//! | [`payment_links`] | Payment links and intents |
//! | [`denylist`] | JWT token deny-list |
//! | [`sessions`] | Login sessions |
//! | [`idempotency`] | Idempotency keys |
//! | [`rate_limit`] | Rate-limit buckets |
//! | [`webhooks`] | Webhook endpoints and deliveries |
//! | [`retention`] | Periodic sweeper for all short-lived tables |
#![forbid(unsafe_code)]

mod account;
mod addresses;
mod api_keys;
mod audit_chain;
mod audit_logs;
mod config;
mod denylist;
mod error;
mod idempotency;
mod ingest;
mod models;
mod otps;
mod payment_links;
mod rate_limit;
pub mod retention;
mod sessions;
mod sponsorship;
mod users;
mod wallets;
mod webhooks;

pub use account::{AccountData, AccountDeletion, EXPORT_SECTION_LIMIT};
pub use audit_chain::{AuditChainKey, AuditChainReport, AuditChainStatus, AUDIT_CHAIN_KEY_LEN};
pub use config::{StoreConfig, StoreConfigError};
pub use error::StoreError;
pub use models::{
    Address, ApiKey, AuditLog, DenylistedToken, EmailOtp, GasSponsorshipConfig, IdempotencyClaim,
    NewDeposit, NewPaymentLink, NewSponsoredTx, PaymentLink, PaymentLinkPayment, PaymentLinkUpdate,
    Session, SponsoredTransaction, Transaction, TransactionFilter, User, Wallet, WebhookDelivery,
    WebhookEndpoint, WhitelistedAddress, Withdrawal, WithdrawalAllowlistConfig,
};

use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

/// How long a stored idempotency key (and its replayable response) lives.
pub const IDEMPOTENCY_KEY_TTL_SECS: i64 = 24 * 60 * 60;

/// Embedded migrations, applied by [`Store::migrate`].
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// A handle to the database (cloneable; wraps a connection pool).
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}

/// Parameters for creating a server-custody wallet (legacy wallets and gas-tank fee accounts —
/// the only rows that carry a server-held sealed seed).
pub struct NewWallet<'a> {
    pub network: &'a str,
    pub stellar_account_g: &'a str,
    pub sealed_ciphertext: &'a [u8],
    pub sealed_nonce: &'a [u8],
    pub sealed_salt: &'a [u8],
    /// Scheme version tag for the sealed seed. Use `octo_crypto::SCHEME_V1`.
    pub sealed_scheme: i16,
    pub label: Option<&'a str>,
    pub user_id: Option<Uuid>,
    pub description: Option<&'a str>,
}

/// Parameters for creating a non-custodial (client-custody) wallet: the client generated the
/// keypair and sends only the public account plus an opaque password-encrypted backup blob the
/// server cannot decrypt.
pub struct NewClientWallet<'a> {
    pub network: &'a str,
    pub stellar_account_g: &'a str,
    pub encrypted_backup: Option<&'a str>,
    pub label: Option<&'a str>,
    pub user_id: Option<Uuid>,
    pub description: Option<&'a str>,
}

/// One address to allocate in [`Store::allocate_addresses`].
pub struct NewAddress<'a> {
    pub customer_ref: Option<&'a str>,
    pub metadata: serde_json::Value,
}

/// Parameters for creating a withdrawal intent.
pub struct NewWithdrawal<'a> {
    pub wallet_id: Uuid,
    pub idempotency_key: &'a str,
    pub destination_account: &'a str,
    pub asset_code: &'a str,
    pub asset_issuer: Option<&'a str>,
    pub amount_stroops: i64,
    pub memo_id: Option<i64>,
}

/// An outbound transfer to record in the `transactions` history.
pub struct NewWithdrawalTransaction<'a> {
    pub wallet_id: Uuid,
    pub asset_code: &'a str,
    pub asset_issuer: Option<&'a str>,
    pub amount_stroops: i64,
    pub source_account: &'a str,
    pub destination_account: &'a str,
    pub stellar_tx_hash: Option<&'a str>,
    /// `pending` before submission, then `confirmed` / `failed` once the outcome is known.
    pub status: &'a str,
    pub ledger: Option<i64>,
    /// The transaction's timebound upper limit (unix seconds), kept so the reconciler can tell
    /// an expired transaction from one that may still land.
    pub max_time: Option<i64>,
}

/// Advisory-lock class id for ingest leadership (ASCII "OCTI"); the network is the second key.
const INGEST_LOCK_CLASS: i32 = 0x4F43_5449;

/// A held session-level advisory lock electing this process as ingest leader for one network.
///
/// The lock lives on a dedicated connection detached from the pool: left in the pool, unrelated
/// queries would share it and it could never be released deliberately. Postgres frees the lock
/// when this connection ends, so a crashed or partitioned leader releases it with no cleanup.
pub struct IngestLeaderLock {
    conn: sqlx::PgConnection,
    network: String,
}

impl IngestLeaderLock {
    /// Whether this session still holds the lock (false if the connection died or it was freed).
    pub async fn still_held(&mut self) -> bool {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND granted
               AND pid = pg_backend_pid() AND classid = $1::oid AND objid = hashtext($2)::oid)",
        )
        .bind(INGEST_LOCK_CLASS)
        .bind(&self.network)
        .fetch_one(&mut self.conn)
        .await
        .unwrap_or(false)
    }

    /// Unlock and close the connection so a standby can take over on its next retry.
    pub async fn release(mut self) {
        let _ = sqlx::query("SELECT pg_advisory_unlock($1, hashtext($2))")
            .bind(INGEST_LOCK_CLASS)
            .bind(&self.network)
            .execute(&mut self.conn)
            .await;
        let _ = sqlx::Connection::close(self.conn).await;
    }
}

impl Store {
    /// Connect to Postgres at `database_url` with [`StoreConfig::default`].
    pub async fn connect(database_url: &str) -> Result<Self, StoreError> {
        Self::connect_with(database_url, &StoreConfig::default()).await
    }

    /// Connect with explicit pool sizing and timeouts (see [`StoreConfig::from_env`]).
    pub async fn connect_with(database_url: &str, cfg: &StoreConfig) -> Result<Self, StoreError> {
        let statement_timeout_ms = cfg.statement_timeout.as_millis().to_string();
        let pool = PgPoolOptions::new()
            .max_connections(cfg.max_connections)
            .acquire_timeout(cfg.acquire_timeout)
            .idle_timeout(cfg.idle_timeout)
            // Session-level, so it applies to every statement on every pooled connection.
            .after_connect(move |conn, _meta| {
                let ms = statement_timeout_ms.clone();
                Box::pin(async move {
                    sqlx::query("SELECT set_config('statement_timeout', $1, false)")
                        .bind(ms)
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    /// Build a store from an existing pool (useful in tests).
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Apply all pending migrations.
    ///
    /// Runs on a connection detached from the pool with `statement_timeout` disabled, so a slow
    /// index build is not killed by the request-path timeout and the override never leaks back.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        let mut conn = self.pool.acquire().await?.detach();
        sqlx::query("SET statement_timeout = 0")
            .execute(&mut conn)
            .await?;
        let result = MIGRATOR.run(&mut conn).await;
        let _ = sqlx::Connection::close(conn).await;
        result?;
        Ok(())
    }

    /// Borrow the underlying pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// One `SELECT 1` round trip: readiness probes and `octo-server --check-config`.
    pub async fn ping(&self) -> Result<(), StoreError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    /// How many embedded migrations this database has not successfully applied yet.
    pub async fn pending_migrations(&self) -> Result<usize, StoreError> {
        let applied: Vec<i64> =
            match sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success")
                .fetch_all(&self.pool)
                .await
            {
                Ok(versions) => versions,
                // undefined_table: a fresh database that has never been migrated.
                Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("42P01") => Vec::new(),
                Err(e) => return Err(e.into()),
            };
        Ok(MIGRATOR
            .iter()
            .filter(|m| !applied.contains(&m.version))
            .count())
    }
}
