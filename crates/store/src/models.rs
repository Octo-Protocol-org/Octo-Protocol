//! Typed row models mirroring the schema in `migrations/0001_init.sql`.
//!
//! Amounts are `i64` stroops throughout (never floating point). Sealed-seed bytes are stored as
//! `Vec<u8>` and only ever decrypted inside `octo-wallet-core`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A master wallet (one per network), holding the sealed HD seed.
#[derive(Debug, Clone, FromRow)]
pub struct Wallet {
    pub id: Uuid,
    pub network: String,
    pub stellar_account_g: String,
    pub sealed_ciphertext: Vec<u8>,
    pub sealed_nonce: Vec<u8>,
    pub sealed_salt: Vec<u8>,
    /// Scheme version tag for the sealed HD seed. See `octo_crypto::SCHEME_V1`.
    pub sealed_scheme: i16,
    pub next_muxed_id: i64,
    pub label: Option<String>,
    pub user_id: Option<Uuid>,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A per-customer deposit address (off-chain row).
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Address {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub muxed_id: i64,
    pub muxed_address: String,
    pub customer_ref: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// A deposit or withdrawal ledger entry.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Transaction {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub address_id: Option<Uuid>,
    pub direction: String,
    pub asset_code: String,
    pub asset_issuer: Option<String>,
    pub amount_stroops: i64,
    pub source_account: Option<String>,
    pub destination_account: Option<String>,
    pub stellar_tx_hash: Option<String>,
    pub operation_index: Option<i32>,
    pub horizon_op_id: Option<String>,
    pub ledger: Option<i64>,
    pub memo_id: Option<i64>,
    pub status: String,
    pub reference: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// A withdrawal (payout) intent.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Withdrawal {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub idempotency_key: String,
    pub destination_account: String,
    pub asset_code: String,
    pub asset_issuer: Option<String>,
    pub amount_stroops: i64,
    pub memo_id: Option<i64>,
    pub status: String,
    pub stellar_tx_hash: Option<String>,
    pub error: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A dashboard user.
#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    /// argon2id PHC hash — never returned to clients.
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A registered webhook endpoint.
#[derive(Debug, Clone, FromRow)]
pub struct WebhookEndpoint {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub url: String,
    pub secret: String,
    pub active: bool,
    pub created_at: DateTime<Utc>,
}

/// A single webhook delivery attempt (append-only log).
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct WebhookDelivery {
    pub id: Uuid,
    pub endpoint_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub status: String,
    pub attempts: i32,
    pub response_code: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// An audit-log entry (append-only record of account activity).
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct AuditLog {
    pub id: Uuid,
    pub user_id: Uuid,
    pub action: String,
    pub category: String,
    pub target: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A per-wallet API key (only the hash + display prefix are stored).
#[derive(Debug, Clone, FromRow)]
pub struct ApiKey {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub prefix: String,
    pub key_hash: String,
    pub created_at: DateTime<Utc>,
}

/// A sponsored (fee-bump) transaction record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SponsoredTransaction {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub inner_tx_hash: String,
    /// Hash of the outer fee-bump tx; `None` until/unless submission succeeds.
    pub fee_bump_tx_hash: Option<String>,
    pub fee_stroops: i64,
    pub status: String,
    /// Horizon error detail on failure; ops-only, never returned to callers.
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A new sponsored transaction to record (inserted as `pending`).
#[derive(Debug, Clone)]
pub struct NewSponsoredTx<'a> {
    pub wallet_id: Uuid,
    pub inner_tx_hash: &'a str,
    pub fee_stroops: i64,
}

/// The gas-sponsorship config for a wallet (one row per wallet).
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GasSponsorshipConfig {
    pub wallet_id: Uuid,
    pub enabled: bool,
    /// Max fee (stroops) the sponsor pays per transaction; `None` = no cap.
    pub per_tx_fee_cap_stroops: Option<i64>,
    /// Rolling UTC-day budget (stroops); `None` = no budget limit.
    pub daily_budget_stroops: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A new deposit to record (input to the idempotent insert).
#[derive(Debug, Clone)]
pub struct NewDeposit {
    pub wallet_id: Uuid,
    pub address_id: Option<Uuid>,
    pub asset_code: String,
    pub asset_issuer: Option<String>,
    pub amount_stroops: i64,
    pub source_account: Option<String>,
    pub destination_account: Option<String>,
    pub stellar_tx_hash: String,
    pub operation_index: i32,
    /// Horizon operation id (TOID) — the unique dedup key for this deposit.
    pub horizon_op_id: String,
    pub ledger: Option<i64>,
    pub memo_id: Option<i64>,
}
