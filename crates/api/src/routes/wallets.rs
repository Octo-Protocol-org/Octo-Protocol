//! Wallet endpoints: create a master wallet, fetch one, list with pagination.

use crate::auth::{authenticate, authorize_wallet};
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use octo_store::NewWallet;
use octo_wallet_core::provision_wallet;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Shared pagination query parameters used by list_wallets, list_transactions,
/// and list_addresses. Mirrors `SponsoredTxnQuery`'s limit/before convention.
#[derive(Debug, Default, Deserialize)]
pub struct ListParams {
    /// Maximum rows to return (default 50, max 200).
    pub limit: Option<i64>,
    /// Cursor: return rows created before this id (exclusive).
    pub before: Option<Uuid>,
}

/// Optional body for wallet creation.
#[derive(Debug, Default, Deserialize)]
pub struct CreateWalletRequest {
    /// Optional human label / name for the wallet.
    #[serde(default)]
    pub label: Option<String>,
    /// Optional longer description.
    #[serde(default)]
    pub description: Option<String>,
}

/// What we return after creating a wallet. The mnemonic is returned **once** here so the operator
/// can back it up; it is never stored in plaintext and never returned again.
#[derive(Debug, Serialize)]
pub struct CreateWalletResponse {
    pub id: Uuid,
    pub network: String,
    pub address: String,
    /// One-time recovery mnemonic — store this securely; it will not be shown again.
    pub recovery_mnemonic: String,
    /// Whether the account was funded on-chain (testnet friendbot). False on mainnet.
    pub funded: bool,
}

/// Public wallet view (no secrets).
#[derive(Debug, Serialize)]
pub struct WalletView {
    pub id: Uuid,
    pub network: String,
    pub address: String,
    pub label: Option<String>,
    pub description: Option<String>,
}

/// Paginated list response for wallets.
#[derive(Debug, Serialize)]
pub struct WalletListResponse {
    pub data: Vec<WalletView>,
    /// UUID of the last row in this page, or null if there are no more rows.
    pub next_cursor: Option<Uuid>,
}

/// Paginated list response for transactions.
#[derive(Debug, Serialize)]
pub struct TransactionListResponse {
    pub data: Vec<octo_store::Transaction>,
    /// UUID of the last row in this page, or null if there are no more rows.
    pub next_cursor: Option<Uuid>,
}

/// Validate a `limit` query param using the same bounds as `SponsoredTxnQuery`:
/// default 50, min 1, max 200.
pub fn validated_limit(limit: Option<i64>) -> Result<i64, ApiError> {
    let l = limit.unwrap_or(50);
    if l > 200 {
        return Err(ApiError::BadRequest("limit must not exceed 200".into()));
    }
    if l < 1 {
        return Err(ApiError::BadRequest("limit must be at least 1".into()));
    }
    Ok(l)
}

/// `POST /v1/wallets` — create a master wallet for the authenticated user.
pub async fn create_wallet(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<CreateWalletResponse>>)> {
    let user_id = authenticate(&headers, &state).await?;
    let req: CreateWalletRequest = parse_optional(&body)?;
    let label = req.label;
    let description = req.description;

    // Generate + seal in wallet-core; the raw seed never reaches this layer.
    let provisioned = provision_wallet(state.master_key(), state.network())?;

    let wallet = state
        .store()
        .create_wallet(NewWallet {
            network: state.network().as_str(),
            stellar_account_g: &provisioned.account_g,
            sealed_ciphertext: &provisioned.sealed.ciphertext,
            sealed_nonce: &provisioned.sealed.nonce,
            sealed_salt: &provisioned.sealed.salt,
            sealed_scheme: i16::from(provisioned.sealed.scheme),
            label: label.as_deref(),
            user_id: Some(user_id),
            description: description.as_deref(),
        })
        .await?;

    crate::audit::record(
        &state,
        user_id,
        "created master wallet",
        crate::audit::category::WALLET,
        wallet.label.as_deref(),
        &headers,
    )
    .await;

    // On testnet, fund the new account via friendbot so it exists on-chain. Best-effort: a
    // funding failure does not roll back wallet creation (the account can be funded later), but we
    // record whether it succeeded so the caller knows.
    let funded = match state.friendbot_url() {
        Some(fb) => crate::horizon::friendbot_fund(fb, &wallet.stellar_account_g)
            .await
            .is_ok(),
        None => false,
    };

    let resp = CreateWalletResponse {
        id: wallet.id,
        network: wallet.network,
        address: wallet.stellar_account_g,
        recovery_mnemonic: provisioned.mnemonic.to_string(),
        funded,
    };
    let (status, json) = Envelope::created(resp);
    Ok((status, json))
}

/// `GET /v1/wallets/{id}/balances` — live on-chain balances from Horizon.
pub async fn get_balances(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<Vec<crate::horizon::Balance>>>> {
    authorize_wallet(&headers, &state, id).await?;
    let wallet = state.store().get_wallet(id).await?;
    let balances = state.horizon().balances(&wallet.stellar_account_g).await?;
    Ok(Envelope::ok(balances))
}

/// `GET /v1/wallets/{id}/transactions` — recorded deposits/withdrawals for a wallet,
/// with optional `?limit=` and `?before=` cursor pagination.
pub async fn list_transactions(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Query(q): Query<ListParams>,
) -> ApiResult<Json<Envelope<TransactionListResponse>>> {
    authorize_wallet(&headers, &state, id).await?;
    let _ = state.store().get_wallet(id).await?;

    let limit = validated_limit(q.limit)?;

    // Fetch limit+1 to detect whether a next page exists.
    let rows = state
        .store()
        .list_transactions(id, limit + 1, q.before)
        .await
        .map_err(|_| ApiError::Internal)?;

    let has_more = rows.len() > limit as usize;
    let mut data = rows;
    if has_more {
        data.truncate(limit as usize);
    }
    let next_cursor = if has_more { data.last().map(|r| r.id) } else { None };

    Ok(Envelope::ok(TransactionListResponse { data, next_cursor }))
}

fn to_view(w: octo_store::Wallet) -> WalletView {
    WalletView {
        id: w.id,
        network: w.network,
        address: w.stellar_account_g,
        label: w.label,
        description: w.description,
    }
}

/// `GET /v1/wallets/{id}`
pub async fn get_wallet(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<WalletView>>> {
    authorize_wallet(&headers, &state, id).await?;
    let w = state.store().get_wallet(id).await.map_err(|e| match e {
        octo_store::StoreError::NotFound => ApiError::NotFound,
        _ => ApiError::Internal,
    })?;
    Ok(Envelope::ok(to_view(w)))
}

/// `GET /v1/wallets` — list the authenticated user's wallets, with optional
/// `?limit=` and `?before=` cursor pagination.
pub async fn list_wallets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListParams>,
) -> ApiResult<Json<Envelope<WalletListResponse>>> {
    let user_id = authenticate(&headers, &state).await?;

    let limit = validated_limit(q.limit)?;

    // Fetch limit+1 to detect whether a next page exists.
    let rows = state
        .store()
        .list_wallets_for_user(user_id, limit + 1, q.before)
        .await
        .map_err(|_| ApiError::Internal)?;

    let has_more = rows.len() > limit as usize;
    let mut wallets = rows;
    if has_more {
        wallets.truncate(limit as usize);
    }
    let next_cursor = if has_more { wallets.last().map(|w| w.id) } else { None };

    Ok(Envelope::ok(WalletListResponse {
        data: wallets.into_iter().map(to_view).collect(),
        next_cursor,
    }))
}
