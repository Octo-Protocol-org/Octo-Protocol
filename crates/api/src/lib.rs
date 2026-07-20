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
pub mod routes;
pub mod sponsor_validation;
mod state;

pub use error::{ApiError, ApiResult, Envelope};
pub use state::AppState;

use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post};
use axum::Router;
use tower_http::cors::{Any, CorsLayer};

/// Keep API request payloads bounded to a deliberate, documented ceiling.
///
/// These routes deserialize JSON from raw `Bytes`; a `Bytes` extractor alone would otherwise
/// rely on axum's implicit body limit (currently 2 MiB in this workspace's version). Making the
/// limit explicit here keeps the behavior intentional and version-stable.
const REQUEST_BODY_LIMIT: usize = 64 * 1024;

/// Build the API router with shared state.
pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // NOTE: the body-limit layer used to be applied here, to an *empty* router — layers only
    // affect routes added before them, so it covered nothing. It is now applied at the end,
    // together with the error handler that turns an oversized body into a 413 envelope.
    Router::new()
        .route("/health", get(health))
        .route("/v1/auth/signup", post(auth::signup))
        .route("/v1/auth/login", post(auth::login))
        .route("/v1/auth/refresh", post(auth::refresh))
        .route("/v1/auth/me", get(auth::me))
        .route("/v1/auth/logout", post(auth::logout))
        .route("/v1/audit-logs", get(routes::audit::list_audit_logs))
        .route(
            "/v1/wallets",
            post(routes::wallets::create_wallet).get(routes::wallets::list_wallets),
        )
        .route("/v1/wallets/:id", get(routes::wallets::get_wallet))
        .route(
            "/v1/wallets/:id/balances",
            get(routes::wallets::get_balances),
        )
        .route(
            "/v1/wallets/:id/transactions",
            get(routes::wallets::list_transactions),
        )
        .route(
            "/v1/wallets/:id/addresses",
            post(routes::addresses::create_address).get(routes::addresses::list_addresses),
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
            "/v1/wallets/:id/api-key",
            post(routes::apikeys::generate_key)
                .get(routes::apikeys::get_key)
                .delete(routes::apikeys::delete_key),
        )
        .route(
            "/v1/wallets/:id/withdraw",
            post(routes::withdrawals::withdraw),
        )
        .route(
            "/v1/wallets/:id/sponsorship",
            get(routes::sponsorship::get_config).put(routes::sponsorship::put_config),
        )
        .route("/v1/wallets/:id/sponsor", post(routes::sponsor::sponsor))
        .route(
            "/v1/wallets/:id/sponsored-transactions",
            get(routes::sponsor::list_sponsored_transactions),
        )
        // axum's own body limit: it produces a real `LengthLimitError`-backed rejection that the
        // framework renders as 413, so no fallible tower layer (and no HandleErrorLayer) is
        // needed. tower_http's RequestBodyLimitLayer would require one and does not compose
        // cleanly with `Router::layer` here.
        .layer(DefaultBodyLimit::max(REQUEST_BODY_LIMIT))
        .layer(cors)
        .with_state(state)
}

/// Liveness probe.
async fn health() -> &'static str {
    "ok"
}

// NOTE: a `handle_errors` HandleErrorLayer helper lived here to convert oversized-body errors
// into a 413 envelope. It is unnecessary with `DefaultBodyLimit` (axum renders that rejection as
// 413 itself) and did not satisfy `Router::layer`'s Service bounds, so it was removed.
