//! Per-wallet API keys for developer integration.
//!
//! A key is `octo_sk_<network>_<random>`. Only its SHA-256 hash and a short display prefix are
//! stored — the full key is returned **once**, on generation/regeneration. Ownership is enforced:
//! the authenticated user must own the wallet.

use crate::auth::authenticate;
use crate::error::{ApiError, ApiResult, Envelope};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Returned once when a key is generated — includes the full secret.
#[derive(Debug, Serialize)]
pub struct GeneratedKey {
    pub wallet_id: Uuid,
    /// The full API key. Shown once; store it securely.
    pub api_key: String,
    pub prefix: String,
}

/// Returned on GET — metadata only, never the secret.
#[derive(Debug, Serialize)]
pub struct ApiKeyInfo {
    pub wallet_id: Uuid,
    pub configured: bool,
    /// Non-secret display prefix, e.g. "octo_sk_test_ab12".
    pub prefix: Option<String>,
}

/// Confirm the authenticated user owns the wallet; returns the wallet network.
async fn owned_wallet(
    state: &AppState,
    headers: &HeaderMap,
    wallet_id: Uuid,
) -> Result<octo_store::Wallet, ApiError> {
    let user_id = authenticate(headers, state).await?;
    let wallet = state.store().get_wallet(wallet_id).await?;
    if wallet.user_id != Some(user_id) {
        // Don't reveal existence of someone else's wallet.
        return Err(ApiError::NotFound);
    }
    Ok(wallet)
}

fn hash_key(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    hex::encode(h.finalize())
}

/// `POST /v1/wallets/:id/api-key` — generate (or regenerate) the wallet's API key.
pub async fn generate_key(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<(StatusCode, Json<Envelope<GeneratedKey>>)> {
    let wallet = owned_wallet(&state, &headers, id).await?;

    // octo_sk_<network>_<32 hex chars>
    let mut raw = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let net = if wallet.network == "mainnet" {
        "live"
    } else {
        "test"
    };
    let api_key = format!("octo_sk_{net}_{}", hex::encode(raw));
    // Display prefix: scheme + first 4 random chars.
    let prefix = format!("octo_sk_{net}_{}", &hex::encode(raw)[..4]);

    state
        .store()
        .upsert_api_key(id, &prefix, &hash_key(&api_key))
        .await
        .map_err(|_| ApiError::Internal)?;

    if let Some(uid) = wallet.user_id {
        crate::audit::record(
            &state,
            uid,
            "generated an API key",
            crate::audit::category::CREDENTIALS,
            wallet.label.as_deref(),
            &headers,
        )
        .await;
    }

    let (code, json) = Envelope::created(GeneratedKey {
        wallet_id: id,
        api_key,
        prefix,
    });
    Ok((code, json))
}

/// `DELETE /v1/wallets/:id/api-key` — revoke the wallet's API key without regenerating.
///
/// Dashboard JWT only (not an API key). A no-op if no key exists.
pub async fn delete_key(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<&'static str>>> {
    let wallet = owned_wallet(&state, &headers, id).await?;

    state
        .store()
        .delete_api_key(id)
        .await
        .map_err(|_| ApiError::Internal)?;

    if let Some(uid) = wallet.user_id {
        crate::audit::record(
            &state,
            uid,
            "revoked API key",
            crate::audit::category::CREDENTIALS,
            wallet.label.as_deref(),
            &headers,
        )
        .await;
    }

    Ok(Envelope::ok("api key revoked"))
}

/// `GET /v1/wallets/:id/api-key` — key metadata (prefix + whether configured). Never the secret.
pub async fn get_key(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<ApiKeyInfo>>> {
    owned_wallet(&state, &headers, id).await?;
    let key = state
        .store()
        .get_api_key(id)
        .await
        .map_err(|_| ApiError::Internal)?;
    Ok(Envelope::ok(ApiKeyInfo {
        wallet_id: id,
        configured: key.is_some(),
        prefix: key.map(|k| k.prefix),
    }))
}
