//! Wallet endpoints: create a master wallet, fetch one, list with pagination.

use crate::auth::{authenticate, authorize_wallet};
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use octo_store::NewClientWallet;
use octo_wallet_core::is_valid_account;
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

/// Body for wallet creation. Non-custodial: the client generates the keypair and sends only the
/// public account — the private key and mnemonic never reach the server.
#[derive(Debug, Default, Deserialize)]
pub struct CreateWalletRequest {
    /// The client-derived Stellar account (`G...`).
    pub public_key: Option<String>,
    /// Opaque client-encrypted seed backup (encrypted under a password-derived key in the
    /// browser/SDK; the server stores it verbatim and cannot decrypt it).
    #[serde(default)]
    pub encrypted_backup: Option<String>,
    /// Optional human label / name for the wallet.
    #[serde(default)]
    pub label: Option<String>,
    /// Optional longer description.
    #[serde(default)]
    pub description: Option<String>,
}

/// What we return after creating a wallet. No secret material — the key was generated client-side
/// and the recovery mnemonic was shown there; the server never saw either.
#[derive(Debug, Serialize)]
pub struct CreateWalletResponse {
    pub id: Uuid,
    pub network: String,
    pub address: String,
    pub custody: String,
    /// Whether the account was funded on-chain (testnet friendbot). False on mainnet.
    pub funded: bool,
}

/// Public wallet view (no secrets).
#[derive(Debug, Serialize)]
pub struct WalletView {
    pub id: Uuid,
    pub network: String,
    pub address: String,
    pub custody: String,
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

    // Non-custodial: the client did the keygen; we only accept the public account.
    let public_key = req
        .public_key
        .filter(|k| !k.is_empty())
        .ok_or_else(|| ApiError::BadRequest("public_key is required (G...)".into()))?;
    if !is_valid_account(&public_key) {
        return Err(ApiError::BadRequest(
            "public_key must be a valid Stellar account (G...)".into(),
        ));
    }

    let wallet = state
        .store()
        .create_client_wallet(NewClientWallet {
            network: state.network().as_str(),
            stellar_account_g: &public_key,
            encrypted_backup: req.encrypted_backup.as_deref(),
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
        custody: wallet.custody,
        funded,
    };
    let (status, json) = Envelope::created(resp);
    Ok((status, json))
}

/// `GET /v1/wallets/{id}/backup` — the opaque client-encrypted seed backup, for new-device
/// recovery. Login-only: this blob is ciphertext under the user's password; the server cannot
/// decrypt it and neither can anyone who steals it without the password.
pub async fn get_backup(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<BackupView>>> {
    let user_id = crate::auth::require_login(&headers, &state).await?;
    let wallet = state.store().get_wallet(id).await?;
    if wallet.user_id != Some(user_id) {
        return Err(ApiError::NotFound);
    }
    Ok(Envelope::ok(BackupView {
        wallet_id: wallet.id,
        encrypted_backup: wallet.encrypted_backup,
    }))
}

/// The stored client-encrypted backup blob (may be absent if the user opted out).
#[derive(Debug, Serialize)]
pub struct BackupView {
    pub wallet_id: Uuid,
    pub encrypted_backup: Option<String>,
}

/// `POST /v1/wallets/{id}/gas-tank` — provision the server-held gas-tank fee account that pays
/// for sponsored transactions. The tank is the ONLY server-held key for a client wallet and only
/// ever carries fee float, so worst-case exposure is the gas budget — never customer funds.
/// Idempotent-ish: a second call returns the existing tank.
pub async fn create_gas_tank(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<(StatusCode, Json<Envelope<GasTankView>>)> {
    let user_id = crate::auth::require_login(&headers, &state).await?;
    let wallet = state.store().get_wallet(id).await?;
    if wallet.user_id != Some(user_id) {
        return Err(ApiError::NotFound);
    }

    if let Some(existing) = wallet.gas_tank_account_g {
        return Ok((
            StatusCode::OK,
            Envelope::ok(GasTankView {
                wallet_id: wallet.id,
                gas_tank_address: existing,
                funded: false,
            }),
        ));
    }
    if !wallet.is_client_custody() {
        return Err(ApiError::BadRequest(
            "legacy server-custody wallets pay fees from their own account; no gas tank needed"
                .into(),
        ));
    }

    // Provision a fresh keypair inside wallet-core. The mnemonic is deliberately dropped: the
    // tank is a disposable fee account, recoverable only by re-provisioning.
    let provisioned = octo_wallet_core::provision_wallet(state.master_key(), state.network())?;
    let wallet = state
        .store()
        .set_gas_tank(
            id,
            &provisioned.account_g,
            &provisioned.sealed.ciphertext,
            &provisioned.sealed.nonce,
            &provisioned.sealed.salt,
            i16::from(provisioned.sealed.scheme),
        )
        .await?;

    // Best-effort testnet funding so the tank account exists on-chain.
    let funded = match state.friendbot_url() {
        Some(fb) => crate::horizon::friendbot_fund(fb, &provisioned.account_g)
            .await
            .is_ok(),
        None => false,
    };

    crate::audit::record(
        &state,
        user_id,
        "provisioned a gas tank",
        crate::audit::category::WALLET,
        Some(&provisioned.account_g),
        &headers,
    )
    .await;

    let resp = GasTankView {
        wallet_id: wallet.id,
        gas_tank_address: provisioned.account_g,
        funded,
    };
    let (status, json) = Envelope::created(resp);
    Ok((status, json))
}

/// The gas tank attached to a wallet. Fund `gas_tank_address` with XLM to cover sponsored fees.
#[derive(Debug, Serialize)]
pub struct GasTankView {
    pub wallet_id: Uuid,
    pub gas_tank_address: String,
    pub funded: bool,
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
    let next_cursor = if has_more {
        data.last().map(|r| r.id)
    } else {
        None
    };

    Ok(Envelope::ok(TransactionListResponse { data, next_cursor }))
}

fn to_view(w: octo_store::Wallet) -> WalletView {
    WalletView {
        id: w.id,
        network: w.network,
        address: w.stellar_account_g,
        custody: w.custody,
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
    let next_cursor = if has_more {
        wallets.last().map(|w| w.id)
    } else {
        None
    };

    Ok(Envelope::ok(WalletListResponse {
        data: wallets.into_iter().map(to_view).collect(),
        next_cursor,
    }))
}
