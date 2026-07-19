//! Webhook endpoint registration.

use crate::auth::authorize_wallet;
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
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

/// `DELETE /v1/wallets/:id/webhooks/:endpoint_id`
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

    state
        .store()
        .deactivate_webhook_endpoint(endpoint_id)
        .await?;

    // Best-effort audit entry; only recorded when the wallet has a login-owning user (API-key
    // authorized requests may not).
    let wallet = state.store().get_wallet(wallet_id).await?;
    if let Some(uid) = wallet.user_id {
        crate::audit::record(
            &state,
            uid,
            "deactivated a webhook endpoint",
            crate::audit::category::WEBHOOK,
            wallet.label.as_deref(),
            &headers,
        )
        .await;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Generate a random hex secret for HMAC signing.
fn generate_secret() -> String {
    // A v4 UUID (122 bits of randomness) rendered without dashes is a fine webhook secret.
    let a = Uuid::new_v4().simple().to_string();
    let b = Uuid::new_v4().simple().to_string();
    format!("{a}{b}")
}

#[derive(Debug, Serialize)]
pub struct WebhookDeliveryView {
    pub id: Uuid,
    pub endpoint_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub status: String,
    pub attempts: i32,
    pub response_code: Option<i32>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
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

/// `GET /v1/wallets/:id/webhooks/:endpoint_id/deliveries`
pub async fn list_deliveries(
    State(state): State<AppState>,
    Path((wallet_id, endpoint_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<Vec<WebhookDeliveryView>>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;

    // Confirm the wallet exists (404 otherwise).
    let _ = state.store().get_wallet(wallet_id).await?;

    // Confirm the endpoint exists and belongs to the wallet.
    let endpoint = state.store().get_webhook_endpoint(endpoint_id).await?;
    if endpoint.wallet_id != wallet_id {
        return Err(ApiError::NotFound);
    }

    // Retrieve deliveries (limit to last 50).
    let deliveries = state.store().list_webhook_deliveries(endpoint_id, 50).await?;

    let views: Vec<WebhookDeliveryView> = deliveries
        .into_iter()
        .map(|d| WebhookDeliveryView {
            id: d.id,
            endpoint_id: d.endpoint_id,
            event_type: d.event_type,
            payload: d.payload,
            status: d.status,
            attempts: d.attempts,
            response_code: d.response_code,
            created_at: d.created_at,
            updated_at: d.updated_at,
        })
        .collect();

    Ok(Envelope::ok(views))
}

