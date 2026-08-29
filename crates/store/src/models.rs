//! Typed row models mirroring the schema in `migrations/0001_init.sql`.
//!
//! Amounts are `i64` stroops throughout (never floating point), plus (since `migrations/
//! 0021_numeric_amounts.sql`) an arbitrary-precision `amount_base_units` `NUMERIC(78,0)` column on
//! `transactions` and `withdrawals` for EVM compatibility (see `octo_chain::Amount`). The two
//! columns are dual-written; `amount_stroops` remains the column of record for at least one
//! release (see the migration for the rollback rationale). Sealed-seed bytes are stored as
//! `Vec<u8>` and only ever decrypted inside `octo-wallet-core`.

use bigdecimal::BigDecimal;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A master wallet.
///
/// Custody models (see `migrations/0008_client_custody.sql`):
/// - `custody == "client"`: non-custodial — the USER's private key exists only client-side and
///   the server can never sign for `stellar_account_g`. If `sealed_*` are set on such a row,
///   they hold the seed of the separate **gas-tank** fee account (`gas_tank_account_g`), which
///   only ever carries fee float for sponsorship. `encrypted_backup` is an opaque
///   client-encrypted blob the server cannot decrypt.
/// - `custody == "server"`: legacy — the sealed seed is the user account's own seed.
#[derive(Debug, Clone, FromRow)]
pub struct Wallet {
    pub id: Uuid,
    pub network: String,
    /// CAIP-2-shaped chain slug (see `migrations/0021_chains_registry.sql`), e.g.
    /// `stellar:pubnet`. Derived from `network` at write time until every caller passes a chain id
    /// directly (see `octo_store::stellar_chain_id_for_network`); kept in lockstep with `network`
    /// by every `Store` write path, so the two never disagree in practice.
    pub chain_id: String,
    pub stellar_account_g: String,
    pub sealed_ciphertext: Option<Vec<u8>>,
    pub sealed_nonce: Option<Vec<u8>>,
    pub sealed_salt: Option<Vec<u8>>,
    /// Scheme version tag for the sealed seed (see `octo_crypto::SCHEME_V1`). `None` on
    /// client-custody rows that carry no sealed seed at all.
    pub sealed_scheme: Option<i16>,
    pub next_muxed_id: i64,
    pub label: Option<String>,
    pub user_id: Option<Uuid>,
    pub description: Option<String>,
    pub custody: String,
    pub encrypted_backup: Option<String>,
    pub gas_tank_account_g: Option<String>,
    /// `"stellar"` or `"evm"` (see `migrations/0021_evm_deposit_addresses.sql`). Determines which
    /// half of `Store::allocate_address` / `allocate_evm_address` this wallet uses.
    pub chain_kind: String,
    /// CAIP-2 chain id (e.g. `"eip155:11155111"`). `None` for Stellar wallets; always `Some` for
    /// `chain_kind == "evm"` (enforced by `wallets_evm_has_chain_id`).
    pub chain_id: Option<String>,
    /// Next non-hardened BIP-44 index to hand out at `m/44'/60'/0'/0/{index}`. The EVM analogue
    /// of `next_muxed_id`; meaningless for Stellar wallets.
    pub next_derivation_index: i64,
    /// Confirmations required before an EVM deposit becomes spendable (see
    /// `migrations/0022_evm_confirmation_and_reorg.sql`). Deliberately per-wallet, not hard-coded —
    /// an L1 and an L2 with a centralised sequencer carry very different reorg risk. `None` for
    /// Stellar wallets, always `Some` for `chain_kind == "evm"`.
    pub confirmation_depth: Option<i32>,
    /// How many blocks the reorg detector may walk back looking for a common ancestor before
    /// giving up and alerting, rather than looping unbounded against a malicious/misbehaving RPC.
    /// Always `>= confirmation_depth`. `None` for Stellar wallets.
    pub reorg_rewind_bound: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Wallet {
    /// True when the private key lives only client-side (server cannot sign).
    pub fn is_client_custody(&self) -> bool {
        self.custody == "client"
    }

    /// True for an EVM (HD-derived-EOA) wallet, false for Stellar (muxed-address) wallets.
    pub fn is_evm(&self) -> bool {
        self.chain_kind == "evm"
    }
}

/// A per-customer deposit address (off-chain row).
///
/// Exactly one of the two shapes below is populated, never both and never neither — enforced by
/// the `addresses_chain_shape` CHECK constraint:
/// - Stellar: `muxed_id` + `muxed_address` (see `docs/deposit-model.md`'s muxed model).
/// - EVM: `derivation_index` + `evm_address` (+ generated `evm_address_lower`) — a real HD-derived
///   EOA (see `docs/deposit-model.md`'s EVM model).
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Address {
    pub id: Uuid,
    pub wallet_id: Uuid,
    /// CAIP-2-shaped chain slug; always equal to the parent wallet's `chain_id`.
    pub chain_id: String,
    pub muxed_id: i64,
    pub muxed_address: String,
    /// Generic on-chain deposit address, unique within `chain_id`
    /// (`uq_addresses_chain_deposit`). Mirrors `muxed_address` for Stellar rows; for a future EVM
    /// adapter this is the actual HD-derived `0x...` address.
    pub deposit_address: String,
    /// BIP-44-style HD derivation index, for chains (EVM) that derive one address per index.
    /// Always `None` for Stellar, which routes by `muxed_id` instead — that's an off-chain id,
    /// not a key-derivation index.
    pub derivation_index: Option<i64>,
    pub customer_ref: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// A deposit or withdrawal ledger entry.
///
/// `status` is the coarse spendability gate every balance/aggregate query already filters on
/// (`status = 'confirmed'`) — see `Store::sum_deposits_for_address(es)`. An EVM deposit is
/// inserted `status = 'pending'` and stays that way until the confirmation tracker promotes it,
/// so those existing queries are correct for EVM with no changes: an unconfirmed or orphaned
/// row simply never matches `status = 'confirmed'`.
///
/// `confirmation_state` is the finer-grained EVM-only progression the tracker operates on
/// (`detected -> confirming -> confirmed`, or `-> orphaned` on reorg). `None` for Stellar deposits
/// and all withdrawals — those chains/directions don't go through this state machine at all.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Transaction {
    pub id: Uuid,
    pub wallet_id: Uuid,
    /// CAIP-2-shaped chain slug; always equal to the parent wallet's `chain_id`.
    pub chain_id: String,
    pub address_id: Option<Uuid>,
    pub direction: String,
    pub asset_code: String,
    pub asset_issuer: Option<String>,
    pub amount_stroops: i64,
    /// Arbitrary-precision base-unit amount (see `octo_chain::Amount`). `None` only for rows
    /// written before `migrations/0021_numeric_amounts.sql`'s backfill ran; the store always
    /// populates this on new writes going forward.
    pub amount_base_units: Option<BigDecimal>,
    pub source_account: Option<String>,
    pub destination_account: Option<String>,
    pub stellar_tx_hash: Option<String>,
    /// Generic on-chain tx hash, mirroring `stellar_tx_hash`. Together with `chain_id` and
    /// `operation_index` this is the anti-double-credit dedup key (`uq_tx_onchain_chain`).
    pub tx_hash: Option<String>,
    /// Operation index within the transaction (Stellar) or log index within the tx receipt
    /// (EVM) — the concept generalizes without needing a new column.
    pub operation_index: Option<i32>,
    pub horizon_op_id: Option<String>,
    pub ledger: Option<i64>,
    pub memo_id: Option<i64>,
    pub status: String,
    pub reference: Option<String>,
    pub metadata: serde_json::Value,
    /// `detected` | `confirming` | `confirmed` | `orphaned`. `None` for non-EVM rows.
    pub confirmation_state: Option<String>,
    /// The EVM transaction hash. `None` for non-EVM rows.
    pub evm_tx_hash: Option<String>,
    /// The `Transfer` event's log index within its transaction — the EVM analogue of
    /// `operation_index`, and (with `evm_tx_hash`) the anti-double-credit dedup key.
    pub log_index: Option<i32>,
    /// The block this deposit was seen in. Distinct from `ledger` (Stellar's ledger sequence) —
    /// kept as its own column since only EVM rows are read/written by the confirmation tracker.
    pub block_number: Option<i64>,
    /// The hash of `block_number` at the time this row was recorded/last verified. Compared
    /// against the chain's current hash at that height to detect a reorg.
    pub block_hash: Option<String>,
    /// Running confirmation count (`chain tip - block_number`), updated each tracker tick.
    pub confirmations: Option<i32>,
    /// When a reorg reversed this deposit. Implies `confirmation_state = 'orphaned'` and vice
    /// versa (`transactions_orphaned_at_matches_state` CHECK). The row is never deleted — this is
    /// the audit trail of the reversal.
    pub orphaned_at: Option<DateTime<Utc>>,
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
    /// Arbitrary-precision base-unit amount (see `octo_chain::Amount`). `None` only for rows
    /// written before `migrations/0021_numeric_amounts.sql`'s backfill ran; the store always
    /// populates this on new writes going forward.
    pub amount_base_units: Option<BigDecimal>,
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
    /// Optional display name, set by the user. Null until they choose one.
    pub username: Option<String>,
    /// argon2id PHC hash — never returned to clients.
    pub password_hash: String,
    /// Null until the signup/login OTP is verified.
    pub email_verified_at: Option<DateTime<Utc>>,
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

/// A row in the token deny-list (JWT revocation record).
///
/// Only the SHA-256 hash of the token is stored — never the raw token itself.
#[derive(Debug, Clone, FromRow)]
pub struct DenylistedToken {
    /// SHA-256 hex of the raw JWT.
    pub token_hash: String,
    /// Mirrors the token's `exp` claim; used for safe pruning.
    pub expires_at: DateTime<Utc>,
    /// The user who revoked the token.
    pub user_id: Uuid,
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

/// The withdrawal-allowlist config for a wallet (one row per wallet).
///
/// `enabled = false` by default: a wallet must opt in before the allowlist is enforced, so
/// turning this feature on can never retroactively lock a wallet out of an address it already
/// used.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WithdrawalAllowlistConfig {
    pub wallet_id: Uuid,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// An approved withdrawal destination for a wallet.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WhitelistedAddress {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub address: String,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
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

/// Parameters for recording a newly-detected (not yet confirmed) EVM deposit.
///
/// Inserted with `status = 'pending'` and `confirmation_state = 'detected'` — it only becomes
/// spendable once `Store::promote_or_progress_evm_confirmation` advances it to `confirmed` at
/// `wallets.confirmation_depth`.
pub struct NewEvmDeposit {
    pub wallet_id: Uuid,
    pub address_id: Option<Uuid>,
    pub asset_code: String,
    pub asset_issuer: Option<String>,
    pub amount_stroops: i64,
    pub source_account: Option<String>,
    pub destination_account: Option<String>,
    pub evm_tx_hash: String,
    pub log_index: i32,
    pub block_number: i64,
    pub block_hash: String,
}

/// A shareable payment link, backed by a dedicated deposit address.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct PaymentLink {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub address_id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub image_url: Option<String>,
    pub redirect_url: Option<String>,
    pub amount_usdc_stroops: Option<i64>,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Input to create a new payment link.
#[derive(Debug, Clone)]
pub struct NewPaymentLink<'a> {
    pub wallet_id: Uuid,
    pub address_id: Uuid,
    pub slug: &'a str,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub image_url: Option<&'a str>,
    pub redirect_url: Option<&'a str>,
    pub amount_usdc_stroops: Option<i64>,
}

/// One payment attempt against a payment link.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct PaymentLinkPayment {
    pub id: Uuid,
    pub payment_link_id: Uuid,
    pub transaction_id: Option<Uuid>,
    /// Dedicated muxed deposit address for this intent — how ingest matches a landing deposit to
    /// exactly one payment. `None` on rows created before migration 0015.
    pub address_id: Option<Uuid>,
    pub payer_name: Option<String>,
    pub payer_email: Option<String>,
    pub amount_usdc_stroops: i64,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

/// A one-time email code, for signup verification or withdrawal confirmation.
#[derive(Debug, Clone, FromRow)]
pub struct EmailOtp {
    pub id: Uuid,
    pub user_id: Uuid,
    pub purpose: String,
    pub code_hash: String,
    /// Withdrawal OTPs bind to the exact transaction hash they gate; null for signup.
    pub tx_hash_bound: Option<String>,
    pub attempts: i16,
    pub consumed_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
