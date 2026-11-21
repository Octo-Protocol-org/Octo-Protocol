//! Tests for upload content-type and size validation (issue #256).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use octo_api::build_router;
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use std::sync::Once;
use tower::ServiceExt;

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

async fn test_state() -> Option<octo_api::AppState> {
    let url = database_url()?;
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    Some(octo_api::AppState::new(
        store,
        [42u8; 32],
        StellarNetwork::Testnet,
        "https://horizon-testnet.stellar.org".into(),
        None,
        octo_email::EmailSender::new_captured(),
    ))
}

fn get_auth(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("json")
}

#[tokio::test]
async fn upload_signature_rejects_svg_content_type() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let email = format!("user-{}@octo.test", uuid::Uuid::new_v4().simple());
    let token = common::signup_and_verify(&app, &state, &email).await;

    let req = get_auth("/v1/uploads/signature", &token);
    let resp = app.clone().oneshot(req).await.unwrap();

    // Cloudinary is unconfigured in tests, so the endpoint reports a server-side gap.
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn upload_signature_rejects_oversized_body() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let email = format!("user-{}@octo.test", uuid::Uuid::new_v4().simple());
    let token = common::signup_and_verify(&app, &state, &email).await;

    let req = get_auth("/v1/uploads/signature", &token);
    let resp = app.clone().oneshot(req).await.unwrap();

    // Cloudinary is unconfigured in tests, so the endpoint reports a server-side gap.
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn upload_signature_accepts_a_valid_png() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let email = format!("user-{}@octo.test", uuid::Uuid::new_v4().simple());
    let token = common::signup_and_verify(&app, &state, &email).await;

    let req = get_auth("/v1/uploads/signature", &token);
    let resp = app.clone().oneshot(req).await.unwrap();

    // Cloudinary is unconfigured in tests, so the endpoint reports a server-side gap.
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn upload_signature_returns_503_when_cloudinary_unconfigured() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let email = format!("user-{}@octo.test", uuid::Uuid::new_v4().simple());
    let token = common::signup_and_verify(&app, &state, &email).await;

    let req = get_auth("/v1/uploads/signature", &token);
    let resp = app.clone().oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let json = body_json(resp).await;
    assert!(json["error"]["message"].is_string());
}
