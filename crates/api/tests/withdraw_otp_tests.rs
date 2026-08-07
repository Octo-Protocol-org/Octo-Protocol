//! Tests for the withdrawal OTP gate: `/v1/wallets/:id/withdraw/request-otp` and `.../confirm`.
//!
//! Uses fresh, unfunded testnet wallets, so a *correctly*-confirmed withdrawal still fails at
//! Horizon (no account on-chain) — the point of these tests is the OTP gate itself (an incorrect
//! or missing code must never reach Horizon at all), not on-chain success.
//!
//! Requires Postgres via `DATABASE_URL` (skipped with a message otherwise, like `api_tests.rs`).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use octo_api::{build_router, AppState};
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use std::sync::Once;
use stellar_base::crypto::DalekKeyPair;
use stellar_base::operations::Operation;
use stellar_base::transaction::{Transaction, MIN_BASE_FEE};
use stellar_base::xdr::XDRSerialize;
use tower::ServiceExt;
use uuid::Uuid;

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

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn post_json_auth(uri: &str, body: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Sign up, verify, and return `(token, email)` — the email is needed to pull the withdrawal
/// OTP back out of the captured-email test double.
async fn auth_token_and_email(app: &axum::Router, state: &AppState) -> (String, String) {
    let email = format!("withdraw-otp-{}@octo.test", Uuid::new_v4().simple());
    let token = common::signup_and_verify(app, state, &email).await;
    (token, email)
}

/// Register a non-custodial wallet for `kp` and return its wallet id.
async fn create_wallet(app: &axum::Router, token: &str, kp: &DalekKeyPair) -> String {
    let body = common::wallet_body(app, token, kp).await;
    let resp = app
        .clone()
        .oneshot(post_json_auth("/v1/wallets", &body, token))
        .await
        .unwrap();
    body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// A trivially-signed Payment inner transaction from `kp` (never funded on-chain — Horizon will
/// reject it on submission, which is fine: these tests only need a validly-*signed* envelope).
fn signed_payment_xdr(kp: &DalekKeyPair, destination_g: &str) -> String {
    let dest = stellar_base::crypto::PublicKey::from_account_id(destination_g).unwrap();
    let op = Operation::new_payment()
        .with_destination(dest)
        .with_amount(stellar_base::amount::Stroops::new(100))
        .unwrap()
        .with_asset(stellar_base::asset::Asset::new_native())
        .build()
        .unwrap();
    let mut tx = Transaction::builder(kp.public_key(), 1, MIN_BASE_FEE)
        .add_operation(op)
        .into_transaction()
        .unwrap();
    tx.sign(kp.as_ref(), &stellar_base::network::Network::new_test())
        .unwrap();
    tx.into_envelope().xdr_base64().unwrap()
}

#[tokio::test]
async fn request_otp_then_confirm_with_correct_code_relays_to_horizon() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: DATABASE_URL is not set");
        return;
    };
    let app = build_router(state.clone());
    let (token, email) = auth_token_and_email(&app, &state).await;
    let kp = DalekKeyPair::random().unwrap();
    let wallet_id = create_wallet(&app, &token, &kp).await;
    let dest = DalekKeyPair::random().unwrap().public_key().account_id();
    let xdr = signed_payment_xdr(&kp, &dest);

    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/withdraw/request-otp"),
            &serde_json::json!({ "transaction_xdr": xdr }).to_string(),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "request-otp must succeed");

    let code = state
        .email()
        .last_otp_for(&email)
        .expect("otp must be captured");

    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/withdraw/confirm"),
            &serde_json::json!({ "transaction_xdr": xdr, "code": code }).to_string(),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "confirm with the correct code must proceed to relay (Horizon may still reject an \
         unfunded account, but the OTP gate itself must pass)"
    );
    let out = body_json(resp).await;
    // Unfunded source account — Horizon rejects it, but that's past the OTP gate.
    assert_eq!(out["data"]["status"], "failed");
}

#[tokio::test]
async fn confirm_with_wrong_code_never_relays() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: DATABASE_URL is not set");
        return;
    };
    let app = build_router(state.clone());
    let (token, _email) = auth_token_and_email(&app, &state).await;
    let kp = DalekKeyPair::random().unwrap();
    let wallet_id = create_wallet(&app, &token, &kp).await;
    let dest = DalekKeyPair::random().unwrap().public_key().account_id();
    let xdr = signed_payment_xdr(&kp, &dest);

    app.clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/withdraw/request-otp"),
            &serde_json::json!({ "transaction_xdr": xdr }).to_string(),
            &token,
        ))
        .await
        .unwrap();

    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/withdraw/confirm"),
            &serde_json::json!({ "transaction_xdr": xdr, "code": "000000" }).to_string(),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "a wrong code must be rejected, never relayed"
    );
}

#[tokio::test]
async fn confirm_rejects_a_code_issued_for_a_different_transaction() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: DATABASE_URL is not set");
        return;
    };
    let app = build_router(state.clone());
    let (token, email) = auth_token_and_email(&app, &state).await;
    let kp = DalekKeyPair::random().unwrap();
    let wallet_id = create_wallet(&app, &token, &kp).await;
    let dest = DalekKeyPair::random().unwrap().public_key().account_id();
    let xdr_a = signed_payment_xdr(&kp, &dest);

    app.clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/withdraw/request-otp"),
            &serde_json::json!({ "transaction_xdr": xdr_a }).to_string(),
            &token,
        ))
        .await
        .unwrap();
    let code = state
        .email()
        .last_otp_for(&email)
        .expect("otp must be captured");

    // A different destination produces a different tx hash — the code above must not bind to it.
    let other_dest = DalekKeyPair::random().unwrap().public_key().account_id();
    let xdr_b = signed_payment_xdr(&kp, &other_dest);

    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/withdraw/confirm"),
            &serde_json::json!({ "transaction_xdr": xdr_b, "code": code }).to_string(),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "a code bound to one transaction must not confirm a different, swapped-in transaction"
    );
}

#[tokio::test]
async fn confirm_without_a_prior_otp_request_is_rejected() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: DATABASE_URL is not set");
        return;
    };
    let app = build_router(state.clone());
    let (token, _email) = auth_token_and_email(&app, &state).await;
    let kp = DalekKeyPair::random().unwrap();
    let wallet_id = create_wallet(&app, &token, &kp).await;
    let dest = DalekKeyPair::random().unwrap().public_key().account_id();
    let xdr = signed_payment_xdr(&kp, &dest);

    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/withdraw/confirm"),
            &serde_json::json!({ "transaction_xdr": xdr, "code": "123456" }).to_string(),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn request_otp_rejects_a_wallet_the_caller_does_not_own() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: DATABASE_URL is not set");
        return;
    };
    let app = build_router(state.clone());
    let (owner_token, _) = auth_token_and_email(&app, &state).await;
    let (other_token, _) = auth_token_and_email(&app, &state).await;
    let kp = DalekKeyPair::random().unwrap();
    let wallet_id = create_wallet(&app, &owner_token, &kp).await;
    let dest = DalekKeyPair::random().unwrap().public_key().account_id();
    let xdr = signed_payment_xdr(&kp, &dest);

    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/withdraw/request-otp"),
            &serde_json::json!({ "transaction_xdr": xdr }).to_string(),
            &other_token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
