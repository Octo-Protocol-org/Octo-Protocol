//! Webhook endpoint registration.

use crate::auth::authorize_wallet;
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use octo_store::WebhookDelivery;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Default, Deserialize)]
pub struct CreateWebhookRequest {
    pub url: Option<String>,
    /// Optional shared secret; one is generated if omitted.
    pub secret: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WebhookView {
    pub id: Uuid,
    pub url: String,
    /// Returned once on creation so the caller can verify signatures.
    pub secret: String,
    pub active: bool,
}

/// `POST /v1/wallets/:id/webhooks`
pub async fn create_webhook(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<WebhookView>>)> {
    authorize_wallet(&headers, &state, wallet_id).await?;
    let req: CreateWebhookRequest = parse_optional(&body)?;
    let url = req
        .url
        .filter(|u| !u.is_empty())
        .ok_or_else(|| ApiError::BadRequest("url is required".into()))?;

    if !octo_webhooks::is_safe_url(&url) {
        return Err(ApiError::BadRequest(
            "url must be a public http(s) endpoint".into(),
        ));
    }

    // Confirm the wallet exists (404 otherwise).
    let _ = state.store().get_wallet(wallet_id).await?;

    // Generate a secret if none supplied.
    let secret = req.secret.unwrap_or_else(generate_secret);

    let ep = state
        .store()
        .create_webhook_endpoint(wallet_id, &url, &secret)
        .await?;

    let view = WebhookView {
        id: ep.id,
        url: ep.url,
        secret: ep.secret,
        active: ep.active,
    };
    let (status, json) = Envelope::created(view);
    Ok((status, json))
}

#[derive(Debug, Deserialize)]
pub struct DeliveriesQuery {
    /// Maximum rows to return (default 50, max 200).
    pub limit: Option<i64>,
}

/// `GET /v1/wallets/:id/webhooks/:endpoint_id/deliveries` — an endpoint's delivery history,
/// newest first.
pub async fn list_deliveries(
    State(state): State<AppState>,
    Path((wallet_id, endpoint_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Query(q): Query<DeliveriesQuery>,
) -> ApiResult<Json<Envelope<Vec<WebhookDelivery>>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;

    let limit = q.limit.unwrap_or(50);
    if limit > 200 {
        return Err(ApiError::BadRequest("limit must not exceed 200".into()));
    }
    if limit < 1 {
        return Err(ApiError::BadRequest("limit must be at least 1".into()));
    }

    // Don't leak whether the endpoint exists under a different wallet.
    let endpoint = state.store().get_webhook_endpoint(endpoint_id).await?;
    if endpoint.wallet_id != wallet_id {
        return Err(ApiError::NotFound);
    }

    let rows = state
        .store()
        .list_webhook_deliveries(endpoint_id, limit)
        .await?;
    Ok(Envelope::ok(rows))
}

/// Generate a random hex secret for HMAC signing.
fn generate_secret() -> String {
    // A v4 UUID (122 bits of randomness) rendered without dashes is a fine webhook secret.
    let a = Uuid::new_v4().simple().to_string();
    let b = Uuid::new_v4().simple().to_string();
    format!("{a}{b}")
}

/// `GET /v1/wallets/:id/webhooks`
pub async fn list_webhooks(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<Vec<WebhookView>>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;

    // Confirm the wallet exists (404 otherwise).
    let _ = state.store().get_wallet(wallet_id).await?;

    let eps = state.store().active_webhook_endpoints(wallet_id).await?;
    let views: Vec<WebhookView> = eps
        .into_iter()
        .map(|ep| WebhookView {
            id: ep.id,
            url: ep.url,
            secret: ep.secret,
            active: ep.active,
        })
        .collect();

    Ok(Envelope::ok(views))
}

/// `DELETE /v1/wallets/:id/webhooks/:endpoint_id` — deactivate an endpoint so it stops receiving
/// deliveries. Idempotent: deactivating an already-inactive endpoint still returns 200.
pub async fn delete_webhook(
    State(state): State<AppState>,
    Path((wallet_id, endpoint_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    authorize_wallet(&headers, &state, wallet_id).await?;

    // Don't leak whether the endpoint exists under a different wallet.
    let endpoint = state.store().get_webhook_endpoint(endpoint_id).await?;
    if endpoint.wallet_id != wallet_id {
        return Err(ApiError::NotFound);
    }

    state.store().deactivate_webhook_endpoint(endpoint_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

