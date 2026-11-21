//! Tests for issue #459: rename and annotate wallets (`PATCH /v1/wallets/:id`).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use octo_api::{build_router, AppState};
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

async fn test_state() -> Option<AppState> {
    let url = database_url()?;
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    Some(AppState::new(
        store,
        [42u8; 32],
        StellarNetwork::Testnet,
        "https://horizon-testnet.stellar.org".into(),
        None,
        octo_email::EmailSender::new_captured(),
    ))
}

fn req_json(method: &str, uri: &str, token: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

/// A verified user with one wallet: `(token, wallet_id)`.
async fn user_with_wallet(app: &axum::Router, state: &AppState) -> (String, String) {
    let email = format!("u-{}@octo.test", uuid::Uuid::new_v4().simple());
    let token = common::signup_and_verify(app, state, &email).await;
    let kp = stellar_base::crypto::DalekKeyPair::random().unwrap();
    let body = common::wallet_body(app, &token, &kp).await;
    let (status, json) = send(app, req_json("POST", "/v1/wallets", &token, &body)).await;
    assert_eq!(status, StatusCode::CREATED);
    (token, json["data"]["id"].as_str().unwrap().to_string())
}

#[tokio::test]
async fn owner_can_rename_annotate_and_clear() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let (token, wallet) = user_with_wallet(&app, &state).await;
    let uri = format!("/v1/wallets/{wallet}");

    let (status, json) = send(
        &app,
        req_json("PATCH", &uri, &token, r#"{"label":"  Treasury  ","description":"ops float"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"]["label"], "Treasury");
    assert_eq!(json["data"]["description"], "ops float");

    // Omitted field stays; null clears.
    let (status, json) = send(&app, req_json("PATCH", &uri, &token, r#"{"description":null}"#)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"]["label"], "Treasury");
    assert!(json["data"]["description"].is_null());
}

#[tokio::test]
async fn rejects_oversized_control_and_empty_patches() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let (token, wallet) = user_with_wallet(&app, &state).await;
    let uri = format!("/v1/wallets/{wallet}");

    let oversized = serde_json::json!({ "label": "a".repeat(65) }).to_string();
    let control = serde_json::json!({ "label": "pay\nroll" }).to_string();
    let bidi = serde_json::json!({ "label": "abc\u{202E}fdp" }).to_string();
    let long_desc = serde_json::json!({ "description": "d".repeat(501) }).to_string();
    for body in [oversized, control, bidi, long_desc, "{}".into(), r#"{"owner":"x"}"#.into()] {
        let (status, _) = send(&app, req_json("PATCH", &uri, &token, &body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body {body} must be rejected");
    }
}

#[tokio::test]
async fn rename_is_audit_logged_without_the_label_text() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let (token, wallet) = user_with_wallet(&app, &state).await;

    let (status, _) = send(
        &app,
        req_json("PATCH", &format!("/v1/wallets/{wallet}"), &token, r#"{"label":"Renamed"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/audit-logs")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let logs = String::from_utf8_lossy(&bytes);
    assert!(logs.contains("updated wallet details (label)"), "audit row missing: {logs}");
    assert!(logs.contains(&wallet));
}
