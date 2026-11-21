//! axum REST API for octo: wallets, addresses (and withdrawals/webhooks in later steps).
//!
//! All responses use the `{ statusCode, message, data }` envelope (see [`error`]). State and
//! secret handling live in [`state`]; routes never touch raw seed material.
#![forbid(unsafe_code)]

pub mod audit;
pub mod auth;
mod error;
pub mod horizon;
mod json;
pub mod rate_limit;
pub mod routes;
pub mod self_test;
pub mod signing_policy;
pub mod sponsor_validation;
mod state;
pub mod submit_validation;
pub mod validation;
pub mod withdrawal_estimate;
pub mod withdrawal_reconciler;

pub use error::{code_for_status, ApiError, ApiResult, Envelope, ERROR_CODES};
pub use signing_policy::SigningPolicy;
pub use state::AppState;

use axum::extract::{DefaultBodyLimit, MatchedPath, Request, State};
use axum::http::header::{self, HeaderName};
use axum::http::{Method, StatusCode};
use axum::http::HeaderValue;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use std::time::Duration;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::Instrument;

/// Canonical header name for request correlation IDs.
pub static REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Longest caller-supplied request ID accepted; longer values are replaced with a fresh UUID.
pub const MAX_REQUEST_ID_LEN: usize = 64;

/// Extracted or generated request ID stored in request extensions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestId(pub String);

/// Middleware that extracts or generates a request ID, enters an info span, and echoes it in responses.
///
/// A caller-supplied `X-Request-Id` is reused only when, after trimming, it is non-empty, at most
/// [`MAX_REQUEST_ID_LEN`] bytes, and made up solely of ASCII alphanumerics, `-` and `_`; anything
/// else is replaced with a fresh UUIDv4 so untrusted input can't bloat or confuse logs.
pub async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    // Reuse caller-supplied X-Request-Id if it passes validation, else generate UUIDv4.
    let request_id = req
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| {
            !s.is_empty()
                && s.len() <= MAX_REQUEST_ID_LEN
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Record request ID in request extensions for handlers.
    req.extensions_mut().insert(RequestId(request_id.clone()));

    // Open tracing span carrying the request ID for cross-service log correlation.
    let span = tracing::info_span!("request", request_id = %request_id);

    // Run downstream middleware and routes within the span context.
    let mut response = next.run(req).instrument(span).await;

    // Attach request ID header to response.
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER.clone(), val);
    }

    response
}

/// Record request latency for `/metrics`. Labels use the matched route *template*, never the raw
/// path, and fixed method/status buckets, so cardinality stays bounded whatever clients send.
async fn http_metrics_middleware(req: Request, next: Next) -> Response {
    let method = match *req.method() {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::OPTIONS => "OPTIONS",
        Method::HEAD => "HEAD",
        _ => "other",
    };
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_string(), |p| p.as_str().to_string());
    let started = std::time::Instant::now();
    let response = next.run(req).await;
    let status_class = match response.status().as_u16() {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    };
    octo_metrics::HTTP_REQUEST_DURATION.observe(
        &[method, &route, status_class],
        started.elapsed().as_secs_f64(),
    );
    response
}

async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    if std::env::var("ENABLE_HSTS").as_deref() == Ok("1") {
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    response
}

/// Longest framework rejection text carried over as the envelope `message`.
const REJECTION_MESSAGE_LIMIT: usize = 512;

/// Wrap framework-generated errors (extractor rejections, unknown routes, 405, oversized bodies)
/// in the standard error envelope with a `code`, so every error a client sees is machine-readable.
async fn error_envelope_middleware(req: Request, next: Next) -> Response {
    let response = next.run(req).await;
    let status = response.status();
    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/json"));
    if !(status.is_client_error() || status.is_server_error()) || is_json {
        return response;
    }

    let (parts, body) = response.into_parts();
    let detail = axum::body::to_bytes(body, REJECTION_MESSAGE_LIMIT)
        .await
        .ok()
        .and_then(|b| String::from_utf8(b.to_vec()).ok())
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty());
    let message = detail.unwrap_or_else(|| {
        status
            .canonical_reason()
            .unwrap_or("error")
            .to_ascii_lowercase()
    });
    let mut wrapped = error::error_response(status, code_for_status(status), message);
    // A 405 must keep advertising the methods the route does accept.
    if let Some(allow) = parts.headers.get(header::ALLOW) {
        wrapped.headers_mut().insert(header::ALLOW, allow.clone());
    }
    wrapped
}

async fn secret_response_cache_middleware(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let sensitive = path.starts_with("/v1/auth/")
        || path.ends_with("/api-key")
        || path.ends_with("/backup")
        || (path == "/v1/wallets" && method == axum::http::Method::POST);
    let mut response = next.run(req).await;
    if sensitive {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
    response
}

/// Keep API request payloads bounded to a deliberate, documented ceiling.
///
/// These routes deserialize JSON from raw `Bytes`; a `Bytes` extractor alone would otherwise
/// rely on axum's implicit body limit (currently 2 MiB in this workspace's version). Making the
/// limit explicit here keeps the behavior intentional and version-stable.
pub const REQUEST_BODY_LIMIT: usize = 64 * 1024;

/// Caller-facing wall-clock ceiling for routes that make a synchronous outbound call (Horizon).
///
/// Independent of the per-attempt client timeout and retry policy in [`horizon`]: those bound
/// each attempt, this bounds the whole request so a slow-but-responding upstream can't pin a
/// client connection open across several retries.
pub const OUTBOUND_ROUTE_TIMEOUT: Duration = Duration::from_secs(10);

/// Build the API router with shared state.
pub fn build_router(state: AppState) -> Router {
    let allowed_origins: Vec<HeaderValue> = std::env::var("ALLOWED_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|origin| origin.trim().parse().ok())
        .collect();
    auth::initialize_dummy_password_hash();
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            REQUEST_ID_HEADER.clone(),
            HeaderName::from_static("idempotency-key"),
        ]);

    // NOTE: the body-limit layer used to be applied here, to an *empty* router — layers only
    // affect routes added before them, so it covered nothing. It is now applied at the end,
    // together with the error handler that turns an oversized body into a 413 envelope.
    Router::new()
        .route("/health", get(health))
        .route("/health/ready", get(health_ready))
        .route("/v1/auth/signup", post(auth::signup))
        .route("/v1/auth/verify-email", post(auth::verify_email))
        .route("/v1/auth/resend-otp", post(auth::resend_otp))
        .route(
            "/v1/auth/request-password-reset",
            post(auth::request_password_reset),
        )
        .route(
            "/v1/auth/confirm-password-reset",
            post(auth::confirm_password_reset),
        )
        .route("/v1/auth/change-email", post(auth::request_email_change))
        .route(
            "/v1/auth/change-email/confirm",
            post(auth::confirm_email_change),
        )
        .route("/v1/auth/login", post(auth::login))
        .route("/v1/auth/refresh", post(auth::refresh))
        .route("/v1/auth/me", get(auth::me).patch(auth::update_username))
        .route("/v1/auth/logout", post(auth::logout))
        .route("/v1/auth/change-password", post(auth::change_password))
        // Account export/deletion (password + emailed OTP); under /v1/auth/ for no-store.
        .route(
            "/v1/auth/account/export/request-otp",
            post(routes::account::export_request_otp),
        )
        .route("/v1/auth/account/export", post(routes::account::export_account))
        .route(
            "/v1/auth/account/delete/request-otp",
            post(routes::account::delete_request_otp)
                .layer(middleware::from_fn(outbound_route_timeout)),
        )
        .route(
            "/v1/auth/account/delete",
            post(routes::account::delete_account)
                .layer(middleware::from_fn(outbound_route_timeout)),
        )
        .route("/v1/auth/sessions", get(routes::sessions::list_sessions))
        // Static segment takes priority over the :id capture below (matchit routing).
        .route(
            "/v1/auth/sessions/revoke-others",
            post(routes::sessions::revoke_other_sessions),
        )
        .route(
            "/v1/auth/sessions/:id",
            delete(routes::sessions::revoke_session),
        )
        .route("/v1/audit-logs", get(routes::audit::list_audit_logs))
        .route(
            "/v1/uploads/signature",
            get(routes::uploads::upload_signature),
        )
        .route(
            "/v1/wallets",
            post(routes::wallets::create_wallet).get(routes::wallets::list_wallets),
        )
        // Static segment takes priority over the :id capture below (matchit routing).
        .route(
            "/v1/wallets/challenge",
            get(routes::wallets::wallet_challenge),
        )
        .route(
            "/v1/wallets/:id",
            get(routes::wallets::get_wallet).patch(routes::wallets::update_wallet),
        )
        .route("/v1/wallets/:id/archive", patch(routes::wallets::archive_wallet))
        .route("/v1/wallets/:id/unarchive", patch(routes::wallets::unarchive_wallet))
        .route("/v1/wallets/:id/ingest/pause", patch(routes::wallets::pause_ingest))
        .route("/v1/wallets/:id/ingest/resume", patch(routes::wallets::resume_ingest))
        .route(
            "/v1/wallets/:id/balances",
            get(routes::wallets::get_balances)
                .layer(middleware::from_fn(outbound_route_timeout)),
        )
        .route(
            "/v1/wallets/:id/transactions",
            get(routes::wallets::list_transactions),
        )
        .route(
            "/v1/wallets/:id/transactions.csv",
            get(routes::transactions_csv::export_transactions_csv),
        )
        .route(
            "/v1/wallets/:id/addresses",
            post(routes::addresses::create_address).get(routes::addresses::list_addresses),
        )
        .route(
            "/v1/wallets/:id/addresses/batch",
            post(routes::addresses::create_addresses_batch),
        )
        .route(
            "/v1/wallets/:id/webhooks",
            post(routes::webhooks::create_webhook).get(routes::webhooks::list_webhooks),
        )
        // NOTE: this deliveries route was registered twice by the merge; axum panics at startup
        // on a duplicate path, so the second registration was removed.
        .route(
            "/v1/wallets/:id/webhooks/:endpoint_id/deliveries",
            get(routes::webhooks::list_deliveries),
        )
        .route(
            "/v1/wallets/:id/webhooks/:endpoint_id",
            delete(routes::webhooks::delete_webhook),
        )
        .route(
            "/v1/wallets/:id/webhooks/:endpoint_id/test",
            post(routes::webhooks::test_webhook),
        )
        .route(
            "/v1/wallets/:id/webhooks/:endpoint_id/deliveries/:delivery_id/redeliver",
            post(routes::webhooks::redeliver_webhook),
        )
        .route(
            "/v1/wallets/:id/api-key",
            post(routes::apikeys::generate_key)
                .get(routes::apikeys::get_key)
                .delete(routes::apikeys::delete_key),
        )
        // Custodial signing tombstone (410 Gone since the non-custodial cutover).
        .route(
            "/v1/wallets/:id/withdraw",
            post(routes::withdrawals::withdraw),
        )
        // Non-custodial path: clients sign locally and relay through these.
        .route(
            "/v1/wallets/:id/trustlines",
            post(routes::trustlines::add_trustline),
        )
        .route(
            "/v1/wallets/:id/submit-signed",
            post(routes::submit::submit_signed),
        )
        .route(
            "/v1/wallets/:id/withdraw/request-otp",
            post(routes::submit::withdraw_request_otp),
        )
        .route(
            "/v1/wallets/:id/withdraw/confirm",
            post(routes::submit::withdraw_confirm),
        )
        .route(
            "/v1/wallets/:id/withdraw/estimate",
            get(routes::submit::withdraw_estimate)
                .layer(middleware::from_fn(outbound_route_timeout)),
        )
        .route(
            "/v1/wallets/:id/signing-info",
            get(routes::submit::signing_info),
        )
        .route("/v1/wallets/:id/backup", get(routes::wallets::get_backup))
        .route(
            "/v1/wallets/:id/gas-tank",
            post(routes::wallets::create_gas_tank).get(routes::wallets::get_gas_tank),
        )
        .route(
            "/v1/wallets/:id/sponsorship",
            get(routes::sponsorship::get_config).put(routes::sponsorship::put_config),
        )
        .route("/v1/wallets/:id/sponsor", post(routes::sponsor::sponsor))
        // Dry run: same validation as /sponsor, no signing and no budget reservation.
        .route(
            "/v1/wallets/:id/sponsor/validate",
            post(routes::sponsor::validate_sponsor)
                .layer(middleware::from_fn(outbound_route_timeout)),
        )
        .route(
            "/v1/wallets/:id/sponsored-transactions",
            get(routes::sponsor::list_sponsored_transactions),
        )
        .route(
            "/v1/wallets/:id/whitelist/config",
            get(routes::whitelist::get_config).put(routes::whitelist::put_config),
        )
        .route(
            "/v1/wallets/:id/whitelist",
            get(routes::whitelist::list_addresses).post(routes::whitelist::add_address),
        )
        .route(
            "/v1/wallets/:id/whitelist/:entry_id",
            delete(routes::whitelist::remove_address),
        )
        .route(
            "/v1/wallets/:id/payment-links",
            post(routes::payment_links::create_payment_link)
                .get(routes::payment_links::list_payment_links),
        )
        .route(
            "/v1/wallets/:id/payment-links/:link_id",
            get(routes::payment_links::get_payment_link)
                .put(routes::payment_links::set_payment_link_active)
                .patch(routes::payment_links::update_payment_link),
        )
        .route(
            "/v1/wallets/:id/payment-links/:link_id/payments",
            get(routes::payment_links::list_payment_link_payments),
        )
        .route(
            "/v1/wallets/:id/payment-links/:link_id/cancel",
            post(routes::payment_links::cancel_payment_link),
        )
        // Public: no auth, reachable by anyone with the link.
        .route(
            "/v1/pay/:slug",
            get(routes::payment_links::get_public_payment_link),
        )
        .route(
            "/v1/pay/:slug/intent",
            post(routes::payment_links::create_payment_intent),
        )
        .route(
            "/v1/pay/:slug/payments/:payment_id",
            get(routes::payment_links::get_payment_status),
        )
        .route(
            "/v1/pay/:slug/signing-info",
            get(routes::payment_links::public_signing_info),
        )
        .route(
            "/v1/pay/:slug/submit-signed",
            post(routes::payment_links::submit_payment),
        )
        // axum's own body limit: it produces a real `LengthLimitError`-backed rejection that the
        // framework renders as 413, so no fallible tower layer (and no HandleErrorLayer) is
        // needed. tower_http's RequestBodyLimitLayer would require one and does not compose
        // cleanly with `Router::layer` here.
        .layer(DefaultBodyLimit::max(REQUEST_BODY_LIMIT))
        .layer(middleware::from_fn(error_envelope_middleware))
        // Innermost of the middleware below, so it sees the MatchedPath set by routing.
        .layer(middleware::from_fn(http_metrics_middleware))
        .layer(cors)
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(middleware::from_fn(secret_response_cache_middleware))
        .layer(middleware::from_fn(request_id_middleware))
        .with_state(state)
}

/// Cap a route at [`OUTBOUND_ROUTE_TIMEOUT`], answering `504` in the standard envelope on expiry.
async fn outbound_route_timeout(req: Request, next: Next) -> Response {
    match tokio::time::timeout(OUTBOUND_ROUTE_TIMEOUT, next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => {
            tracing::warn!(timeout_secs = OUTBOUND_ROUTE_TIMEOUT.as_secs(), "route timed out");
            ApiError::GatewayTimeout("upstream did not respond in time; please retry".into())
                .into_response()
        }
    }
}

/// Liveness probe.
async fn health() -> &'static str {
    "ok"
}

// Readiness probe checking database and Horizon reachability.
async fn health_ready(State(state): State<AppState>) -> impl IntoResponse {
    let mut db_ok = false;
    let mut horizon_ok = false;
    let mut db_err = None;
    let mut horizon_err = None;

    match state.store().ping().await {
        Ok(_) => db_ok = true,
        Err(e) => db_err = Some(e.to_string()),
    }

    match state.horizon().check_reachability().await {
        Ok(_) => horizon_ok = true,
        Err(e) => horizon_err = Some(e),
    }

    if db_ok && horizon_ok {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "ready",
                "database": "ok",
                "horizon": "ok"
            })),
        )
    } else {
        let mut failed = Vec::new();
        if !db_ok {
            failed.push("database");
        }
        if !horizon_ok {
            failed.push("horizon");
        }
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "not_ready",
                "database": if db_ok { "ok".to_string() } else { db_err.unwrap_or_else(|| "unreachable".into()) },
                "horizon": if horizon_ok { "ok".to_string() } else { horizon_err.unwrap_or_else(|| "unreachable".into()) },
                "failed": failed,
                "error": format!("unreachable dependencies: {}", failed.join(", "))
            })),
        )
    }
}

// NOTE: a `handle_errors` HandleErrorLayer helper lived here to convert oversized-body errors
// into a 413 envelope. It is unnecessary with `DefaultBodyLimit` (axum renders that rejection as
// 413 itself) and did not satisfy `Router::layer`'s Service bounds, so it was removed.
