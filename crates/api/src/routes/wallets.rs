//! Wallet endpoints: create a master wallet, fetch one.

use crate::auth::{authenticate, authorize_wallet};
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use octo_store::NewWallet;
use octo_wallet_core::provision_wallet;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

/// `POST /v1/wallets` — create a master wallet for the authenticated user.
pub async fn create_wallet(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<CreateWalletResponse>>)> {
    let user_id = authenticate(&headers, &state)?;
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

/// `GET /v1/wallets/{id}/transactions` — recorded deposits/withdrawals for a wallet.
pub async fn list_transactions(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<Vec<octo_store::Transaction>>>> {
    authorize_wallet(&headers, &state, id).await?;
    // Confirm the wallet exists (404 otherwise).
    let _ = state.store().get_wallet(id).await?;
    let txns = state
        .store()
        .list_transactions(id)
        .await
        .map_err(|_| ApiError::Internal)?;
    Ok(Envelope::ok(txns))
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

/// `GET /v1/wallets` — list the authenticated user's wallets.
pub async fn list_wallets(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<Vec<WalletView>>>> {
    let user_id = authenticate(&headers, &state)?;
    let wallets = state
        .store()
        .list_wallets_for_user(user_id)
        .await
        .map_err(|_| ApiError::Internal)?;
    Ok(Envelope::ok(wallets.into_iter().map(to_view).collect()))
}
