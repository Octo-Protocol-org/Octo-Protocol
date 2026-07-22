//! Integration tests for JWT session revocation and rotation.
//!
//! Requires Postgres via `DATABASE_URL`. Skips gracefully if absent.
//!
//! Covers:
//! - refresh revokes the previous token so it can no longer authenticate
//! - logout revokes the current token
//! - a request in-flight at the moment of refresh: documents the accepted race window

use axum::body::Body;
use axum::http::{Request, StatusCode};
use octo_api::{build_router, AppState};
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use std::sync::Once;
use tower::ServiceExt;

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| { let _ = dotenvy::dotenv(); });
    std::env::var("DATABASE_URL").ok()
}

async fn test_state() -> Option<AppState> {
    let url = database_url()?;
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    Some(
        AppState::new(
            store,
            [42u8; 32],
            StellarNetwork::Testnet,
            "https://horizon-testnet.stellar.org".into(),
            None,
        )
        .with_jwt_secret(b"test-jwt-secret-at-least-16-bytes".to_vec()),
    )
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let b = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&b).unwrap()
}

fn post_json(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn authed(method: &str, uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn unique_email() -> String {
    format!("revoke-{}@octo.test", uuid::Uuid::new_v4().simple())
}

// ---------------------------------------------------------------------------
// Helper: signup and return the initial token
// ---------------------------------------------------------------------------
async fn signup_and_get_token(app: axum::Router, email: &str) -> String {
    let resp = app
        .oneshot(post_json(
            "/v1/auth/signup",
            &format!(r#"{{"email":"{email}","password":"supersecret"}}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    body_json(resp).await["data"]["token"]
        .as_str()
        .unwrap()
        .to_string()
}

// ---------------------------------------------------------------------------
// Test 1: refresh revokes the previous token
// ---------------------------------------------------------------------------
#[tokio::test]
async fn refresh_revokes_the_previous_token_so_it_can_no_longer_authenticate() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state);
    let email = unique_email();
    let token1 = signup_and_get_token(app.clone(), &email).await;

    // Refresh using token1 — should succeed and return token2.
    let resp = app
        .clone()
        .oneshot(authed("POST", "/v1/auth/refresh", &token1))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "refresh must succeed");
    let token2 = body_json(resp).await["data"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(token1, token2, "refresh must issue a new, distinct token");

    // token1 must now be rejected (it was revoked by the refresh).
    let resp = app
        .clone()
        .oneshot(authed("GET", "/v1/auth/me", &token1))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "the pre-refresh token must be rejected after refresh"
    );

    // token2 must still be accepted.
    let resp = app
        .clone()
        .oneshot(authed("GET", "/v1/auth/me", &token2))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "the new token must be valid");
}

// ---------------------------------------------------------------------------
// Test 2: logout revokes the current token
// ---------------------------------------------------------------------------
#[tokio::test]
async fn logout_revokes_the_current_token() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let email = unique_email();
    let token = signup_and_get_token(app.clone(), &email).await;

    // Logout.
    let resp = app
        .clone()
        .oneshot(authed("POST", "/v1/auth/logout", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "logout must succeed");

    // The token must now be rejected.
    let resp = app
        .clone()
        .oneshot(authed("GET", "/v1/auth/me", &token))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "a logged-out token must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Test 3: a request in-flight at the moment of refresh
//
// Documents the accepted race window: a request that authenticates BEFORE the deny-list INSERT
// commits will succeed; one that authenticates AFTER will get 401. We can't deterministically
// control the race in a unit test, so we instead prove the boundary behaviour:
//
//   a) A /me call using the old token BEFORE the refresh fires → succeeds.
//   b) A /me call using the old token AFTER the refresh completes → 401.
//
// This verifies the design is "correct on both sides of the window" without requiring a real
// race condition.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn in_flight_request_behaviour_around_refresh_is_as_documented() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let email = unique_email();
    let token1 = signup_and_get_token(app.clone(), &email).await;

    // Part a: old token is valid BEFORE refresh.
    let resp = app
        .clone()
        .oneshot(authed("GET", "/v1/auth/me", &token1))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "old token must be valid before refresh fires"
    );

    // Refresh.
    let resp = app
        .clone()
        .oneshot(authed("POST", "/v1/auth/refresh", &token1))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Part b: old token is rejected AFTER refresh.
    let resp = app
        .clone()
        .oneshot(authed("GET", "/v1/auth/me", &token1))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "old token must be rejected after refresh completes — this documents the race window: \
         requests that arrived before the deny-list insert committed will have succeeded; \
         requests arriving after (this test) are correctly rejected"
    );
}

// ---------------------------------------------------------------------------
// Test 4: double-logout is a no-op (not an error)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn double_logout_is_harmless() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let email = unique_email();
    let token = signup_and_get_token(app.clone(), &email).await;

    app.clone()
        .oneshot(authed("POST", "/v1/auth/logout", &token))
        .await
        .unwrap();

    // Second logout with the already-revoked token must return 401 (token is revoked, not 500).
    let resp = app
        .oneshot(authed("POST", "/v1/auth/logout", &token))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "logging out an already-revoked token must be 401, not 500"
    );
}
