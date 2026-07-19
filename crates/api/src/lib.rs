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

use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;

/// Keep API request payloads bounded to a deliberate, documented ceiling.
///
/// These routes deserialize JSON from raw `Bytes`; a `Bytes` extractor alone would otherwise
/// rely on axum's implicit body limit (currently 2 MiB in this workspace's version). Making the
/// limit explicit here keeps the behavior intentional and version-stable.
const REQUEST_BODY_LIMIT: usize = 64 * 1024;

/// Build the API router with shared state.
pub fn build_router(state: AppState) -> Router {
    // The browser dashboard calls this API cross-origin. Allow any origin for the JSON API
    // (auth is via bearer tokens, not cookies, so this is not a CSRF vector).
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .layer(RequestBodyLimitLayer::new(REQUEST_BODY_LIMIT))
        .route("/health", get(health))
        .route("/v1/auth/signup", post(auth::signup))
        .route("/v1/auth/login", post(auth::login))
        .route("/v1/auth/me", get(auth::me))
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
            post(routes::webhooks::create_webhook),
        )
        .route(
            "/v1/wallets/:id/api-key",
            post(routes::apikeys::generate_key).get(routes::apikeys::get_key),
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
        .layer(cors)
        .with_state(state)
}

/// Liveness probe.
async fn health() -> &'static str {
    "ok"
}
