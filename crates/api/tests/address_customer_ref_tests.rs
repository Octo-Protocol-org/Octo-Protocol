//! Tests for issue #460: per-wallet unique `customer_ref` on deposit addresses, with lookup.

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

fn get_auth(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn duplicate_customer_ref_on_the_same_wallet_is_a_conflict() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let (token, wallet) = user_with_wallet(&app, &state).await;
    let uri = format!("/v1/wallets/{wallet}/addresses");

    let (status, _) = send(&app, req_json("POST", &uri, &token, r#"{"customer_ref":"cust-1"}"#)).await;
    assert_eq!(status, StatusCode::CREATED);
    // Whitespace is trimmed, so a padded copy is still the same reference.
    let (status, _) = send(&app, req_json("POST", &uri, &token, r#"{"customer_ref":" cust-1 "}"#)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    // Addresses without a reference are never constrained.
    for _ in 0..2 {
        let (status, _) = send(&app, req_json("POST", &uri, &token, "{}")).await;
        assert_eq!(status, StatusCode::CREATED);
    }
}

#[tokio::test]
async fn the_same_reference_is_independent_across_wallets() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let (token_a, wallet_a) = user_with_wallet(&app, &state).await;
    let (token_b, wallet_b) = user_with_wallet(&app, &state).await;
    for (token, wallet) in [(&token_a, &wallet_a), (&token_b, &wallet_b)] {
        let (status, _) = send(
            &app,
            req_json("POST", &format!("/v1/wallets/{wallet}/addresses"), token, r#"{"customer_ref":"shared"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
    }
}

#[tokio::test]
async fn lookup_by_reference_returns_only_the_matching_address() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let (token, wallet) = user_with_wallet(&app, &state).await;
    let uri = format!("/v1/wallets/{wallet}/addresses");
    let (_, created) = send(&app, req_json("POST", &uri, &token, r#"{"customer_ref":"find-me"}"#)).await;
    send(&app, req_json("POST", &uri, &token, r#"{"customer_ref":"other"}"#)).await;

    let (status, json) = send(&app, get_auth(&format!("{uri}?customer_ref=find-me"), &token)).await;
    assert_eq!(status, StatusCode::OK);
    let data = json["data"]["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["id"], created["data"]["id"]);

    let (status, json) = send(&app, get_auth(&format!("{uri}?customer_ref=missing"), &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["data"]["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn oversized_or_control_character_references_are_rejected() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let (token, wallet) = user_with_wallet(&app, &state).await;
    let uri = format!("/v1/wallets/{wallet}/addresses");
    for bad in ["r".repeat(129), "a\nb".to_string()] {
        let body = serde_json::json!({ "customer_ref": bad }).to_string();
        let (status, _) = send(&app, req_json("POST", &uri, &token, &body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body} must be rejected");
    }
}
