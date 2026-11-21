//! Account data export and deletion (issue #466).
//!
//! Both are two-step and require a dashboard login (API keys are rejected):
//! 1. `.../request-otp` re-checks the password and emails a one-time code.
//! 2. The confirm call re-checks the password and redeems the code.
//!
//! Export and delete use separate OTP purposes, so an export code can never delete an account.
//! The export is built from explicit views below, never from raw rows, so no secret (password
//! hash, sealed seed, encrypted backup, webhook secret, API key hash) can leak into it.
//!
//! Deletion is refused while any wallet's Stellar account (or its gas tank) still holds a balance,
//! and fails closed if Horizon can't confirm that. See `octo_store::Store::delete_account`.

use crate::auth::{check_auth_rate_limit, issue_otp, require_login, verify_password};
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::Json;
use chrono::{DateTime, Utc};
use octo_store::{
    Address, AuditLog, PaymentLink, PaymentLinkPayment, StoreError, Transaction, User, Wallet,
    WhitelistedAddress,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

const EXPORT_PURPOSE: &str = "account_export";
const DELETE_PURPOSE: &str = "account_delete";

/// Export/delete attempts (OTP requests and confirms together) per user per hour.
const ACCOUNT_ACTION_LIMIT: u32 = 5;
const ACCOUNT_ACTION_WINDOW: std::time::Duration = std::time::Duration::from_secs(60 * 60);

#[derive(Debug, Deserialize, Default)]
pub struct AccountOtpRequest {
    pub password: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AccountConfirmRequest {
    pub password: Option<String>,
    pub code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OtpSentResponse {
    pub sent: bool,
}

#[derive(Debug, Serialize)]
pub struct DeletedResponse {
    pub deleted: bool,
}

// --- export views (secret-free by construction) ------------------------------------------------

#[derive(Debug, Serialize)]
pub struct AccountExport {
    pub exported_at: DateTime<Utc>,
    pub user: UserExport,
    pub wallets: Vec<WalletExport>,
    pub addresses: Vec<Address>,
    pub transactions: Vec<Transaction>,
    pub withdrawals: Vec<WithdrawalExport>,
    pub sponsored_transactions: Vec<SponsoredTransactionExport>,
    pub api_keys: Vec<ApiKeyExport>,
    pub webhook_endpoints: Vec<WebhookEndpointExport>,
    pub whitelisted_addresses: Vec<WhitelistedAddress>,
    pub payment_links: Vec<PaymentLink>,
    pub payment_link_payments: Vec<PaymentLinkPayment>,
    pub sessions: Vec<SessionExport>,
    pub audit_logs: Vec<AuditLog>,
    /// Sections cut off at `section_limit` rows; empty when the export is complete.
    pub truncated: Vec<&'static str>,
    pub section_limit: i64,
}

#[derive(Debug, Serialize)]
pub struct UserExport {
    pub id: Uuid,
    pub email: String,
    pub username: Option<String>,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct WalletExport {
    pub id: Uuid,
    pub network: String,
    pub address: String,
    pub custody: String,
    pub label: Option<String>,
    pub description: Option<String>,
    pub gas_tank_address: Option<String>,
    /// Whether an encrypted seed backup is stored; the blob itself is fetched via `/backup`.
    pub has_encrypted_backup: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub archived_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct WithdrawalExport {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub destination_account: String,
    pub asset_code: String,
    pub asset_issuer: Option<String>,
    pub amount_stroops: i64,
    pub memo_id: Option<i64>,
    pub status: String,
    pub stellar_tx_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct SponsoredTransactionExport {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub inner_tx_hash: String,
    pub fee_bump_tx_hash: Option<String>,
    pub fee_stroops: i64,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyExport {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub prefix: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct WebhookEndpointExport {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub url: String,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub auto_disabled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct SessionExport {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl From<octo_store::AccountData> for AccountExport {
    fn from(d: octo_store::AccountData) -> Self {
        Self {
            exported_at: Utc::now(),
            user: UserExport {
                id: d.user.id,
                email: d.user.email,
                username: d.user.username,
                email_verified_at: d.user.email_verified_at,
                created_at: d.user.created_at,
                updated_at: d.user.updated_at,
            },
            wallets: d
                .wallets
                .into_iter()
                .map(|w| WalletExport {
                    id: w.id,
                    network: w.network,
                    address: w.stellar_account_g,
                    custody: w.custody,
                    label: w.label,
                    description: w.description,
                    gas_tank_address: w.gas_tank_account_g,
                    has_encrypted_backup: w.encrypted_backup.is_some(),
                    created_at: w.created_at,
                    updated_at: w.updated_at,
                    archived_at: w.archived_at,
                })
                .collect(),
            addresses: d.addresses,
            transactions: d.transactions,
            // `error` is Horizon detail for operators only.
            withdrawals: d
                .withdrawals
                .into_iter()
                .map(|w| WithdrawalExport {
                    id: w.id,
                    wallet_id: w.wallet_id,
                    destination_account: w.destination_account,
                    asset_code: w.asset_code,
                    asset_issuer: w.asset_issuer,
                    amount_stroops: w.amount_stroops,
                    memo_id: w.memo_id,
                    status: w.status,
                    stellar_tx_hash: w.stellar_tx_hash,
                    created_at: w.created_at,
                    updated_at: w.updated_at,
                })
                .collect(),
            sponsored_transactions: d
                .sponsored_transactions
                .into_iter()
                .map(|s| SponsoredTransactionExport {
                    id: s.id,
                    wallet_id: s.wallet_id,
                    inner_tx_hash: s.inner_tx_hash,
                    fee_bump_tx_hash: s.fee_bump_tx_hash,
                    fee_stroops: s.fee_stroops,
                    status: s.status,
                    created_at: s.created_at,
                })
                .collect(),
            api_keys: d
                .api_keys
                .into_iter()
                .map(|k| ApiKeyExport {
                    id: k.id,
                    wallet_id: k.wallet_id,
                    prefix: k.prefix,
                    scopes: k.scopes,
                    created_at: k.created_at,
                    last_used_at: k.last_used_at,
                    expires_at: k.expires_at,
                })
                .collect(),
            webhook_endpoints: d
                .webhook_endpoints
                .into_iter()
                .map(|e| WebhookEndpointExport {
                    id: e.id,
                    wallet_id: e.wallet_id,
                    url: e.url,
                    active: e.active,
                    created_at: e.created_at,
                    deleted_at: e.deleted_at,
                    auto_disabled_at: e.auto_disabled_at,
                })
                .collect(),
            whitelisted_addresses: d.whitelisted_addresses,
            payment_links: d.payment_links,
            payment_link_payments: d.payment_link_payments,
            sessions: d
                .sessions
                .into_iter()
                .map(|s| SessionExport {
                    id: s.id,
                    created_at: s.created_at,
                    last_seen_at: s.last_seen_at,
                    expires_at: s.expires_at,
                    revoked_at: s.revoked_at,
                })
                .collect(),
            audit_logs: d.audit_logs,
            truncated: d.truncated,
            section_limit: octo_store::EXPORT_SECTION_LIMIT,
        }
    }
}

// --- handlers ------------------------------------------------------------------------------------

/// `POST /v1/auth/account/export/request-otp` — email a code that authorizes one data export.
pub async fn export_request_otp(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<OtpSentResponse>>> {
    let user = authorize(&state, &headers, peer, &body).await?;
    issue_otp(&state, user.id, EXPORT_PURPOSE, &user.email, None).await?;
    Ok(Envelope::ok(OtpSentResponse { sent: true }))
}

/// `POST /v1/auth/account/export` — redeem the code and return everything stored about you.
pub async fn export_account(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<AccountExport>>> {
    let user = authorize(&state, &headers, peer, &body).await?;
    redeem_otp(&state, user.id, EXPORT_PURPOSE, &body).await?;
    // Fail closed: personal data never leaves without a trace.
    crate::audit::record_strict(
        &state,
        user.id,
        "exported account data",
        crate::audit::category::AUTH,
        None,
        &headers,
    )
    .await?;
    let data = state.store().export_account(user.id).await?;
    Ok(Envelope::ok(AccountExport::from(data)))
}

/// `POST /v1/auth/account/delete/request-otp` — email a deletion code, if no wallet holds funds.
pub async fn delete_request_otp(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<OtpSentResponse>>> {
    let user = authorize(&state, &headers, peer, &body).await?;
    // Checked here too, so a user with funds is told before any code is sent.
    ensure_no_funds(&state, &owned_wallets(&state, user.id).await?).await?;
    issue_otp(&state, user.id, DELETE_PURPOSE, &user.email, None).await?;
    Ok(Envelope::ok(OtpSentResponse { sent: true }))
}

/// `POST /v1/auth/account/delete` — redeem the code and permanently delete the caller's account.
pub async fn delete_account(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<DeletedResponse>>> {
    let user = authorize(&state, &headers, peer, &body).await?;
    let wallets = owned_wallets(&state, user.id).await?;
    // Before redeeming, so a refusal doesn't burn the code.
    ensure_no_funds(&state, &wallets).await?;
    redeem_otp(&state, user.id, DELETE_PURPOSE, &body).await?;

    let checked: Vec<Uuid> = wallets.iter().map(|w| w.id).collect();
    let deletion = state
        .store()
        .delete_account(state.audit_chain_key(), user.id, &checked)
        .await
        .map_err(|e| match e {
            StoreError::Conflict => {
                ApiError::ConflictWith("your wallets changed during deletion; try again".into())
            }
            StoreError::AuditChainCorrupt => {
                tracing::error!(user_id = %user.id, "account deletion refused: audit chain bad");
                ApiError::ConflictWith("account deletion is unavailable; contact support".into())
            }
            other => ApiError::from(other),
        })?;
    tracing::info!(
        user_id = %user.id,
        wallets_archived = deletion.wallets_archived,
        audit_rows_anonymised = deletion.audit_rows_anonymised,
        "account deleted"
    );

    let notice = octo_email::templates::account_deleted_email();
    let _ = state
        .email()
        .send(&user.email, "Your Octo account was deleted", &notice)
        .await;
    Ok(Envelope::ok(DeletedResponse { deleted: true }))
}

// --- helpers -------------------------------------------------------------------------------------

/// Login session + rate limits + password re-check, shared by all four routes.
async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    body: &Bytes,
) -> Result<User, ApiError> {
    check_auth_rate_limit(state, headers, peer.map(|c| c.0)).await?;
    let user_id = require_login(headers, state).await?;
    // Per-user cap, so a stolen token can't guess the password by rotating IPs.
    if !state
        .rate_limiter()
        .check(
            &format!("account:{user_id}"),
            "account_action",
            ACCOUNT_ACTION_LIMIT,
            ACCOUNT_ACTION_WINDOW,
        )
        .await
    {
        return Err(ApiError::TooManyRequests(
            "too many attempts — wait a while and try again".into(),
        ));
    }

    let req: AccountOtpRequest = parse_optional(body)?;
    let password = req
        .password
        .filter(|p| !p.is_empty() && p.len() <= 128)
        .ok_or_else(|| ApiError::BadRequest("password is required".into()))?;
    let user = state
        .store()
        .get_user(user_id)
        .await
        .map_err(crate::error::internal)?
        .filter(|u| u.deleted_at.is_none())
        .ok_or(ApiError::Unauthorized)?;
    verify_password(&password, &user.password_hash)
        .map_err(|_| ApiError::BadRequest("incorrect password".into()))?;
    Ok(user)
}

/// Consume the emailed code for `purpose`; one generic error for every failure.
async fn redeem_otp(
    state: &AppState,
    user_id: Uuid,
    purpose: &str,
    body: &Bytes,
) -> Result<(), ApiError> {
    let req: AccountConfirmRequest = parse_optional(body)?;
    let code = req
        .code
        .filter(|c| !c.is_empty())
        .ok_or_else(|| ApiError::BadRequest("code is required".into()))?;
    state
        .store()
        .verify_and_consume_otp(user_id, purpose, &octo_email::hash_otp(&code), None)
        .await
        .map_err(|_| ApiError::BadRequest("invalid or expired code".into()))
}

/// Every wallet the user owns, archived ones included (they can still hold funds).
async fn owned_wallets(state: &AppState, user_id: Uuid) -> Result<Vec<Wallet>, ApiError> {
    let mut wallets = Vec::new();
    let mut before = None;
    loop {
        let page = state
            .store()
            .list_wallets_for_user_page(user_id, 100, before)
            .await
            .map_err(crate::error::internal)?;
        let done = page.len() < 100;
        before = page.last().map(|w| w.id);
        wallets.extend(page);
        if done {
            return Ok(wallets);
        }
    }
}

/// Refuse while any wallet (or its gas tank) holds a balance. Fails closed when Horizon can't
/// answer, or when a wallet lives on a network this server can't query.
async fn ensure_no_funds(state: &AppState, wallets: &[Wallet]) -> Result<(), ApiError> {
    let unavailable = || {
        ApiError::ServiceUnavailable("could not confirm wallet balances; try again later".into())
    };
    let mut funded = Vec::new();
    for wallet in wallets {
        if wallet.network != state.network().as_str() {
            return Err(unavailable());
        }
        let accounts = std::iter::once(&wallet.stellar_account_g).chain(&wallet.gas_tank_account_g);
        for account in accounts {
            match state.horizon().balances(account).await {
                Ok(lines) if lines.iter().any(|l| is_nonzero(&l.balance)) => {
                    funded.push(wallet.id.to_string());
                    break;
                }
                // An account that doesn't exist on-chain holds nothing.
                Ok(_) | Err(ApiError::NotFound) => {}
                Err(_) => return Err(unavailable()),
            }
        }
    }
    if funded.is_empty() {
        return Ok(());
    }
    Err(ApiError::ConflictWith(format!(
        "account still holds funds; withdraw or merge these wallets first: {}",
        funded.join(", ")
    )))
}

/// Horizon balances are decimal strings ("0.0000000"); any non-zero digit means funds.
fn is_nonzero(balance: &str) -> bool {
    balance.bytes().any(|b| (b'1'..=b'9').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_balances_are_not_funds() {
        assert!(!is_nonzero("0.0000000"));
        assert!(!is_nonzero("0"));
        assert!(is_nonzero("0.0000001"));
        assert!(is_nonzero("100.0000000"));
    }
}
