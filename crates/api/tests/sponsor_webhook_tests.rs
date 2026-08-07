//! Tests for the `transaction.sponsored` webhook (issue: emit a webhook after every fee-bump
//! sponsorship attempt).
//!
//! These exercise the full `/v1/wallets/:id/sponsor` route against fresh, **unfunded** testnet
//! wallets, so the fee-bump always fails on submission (no friendbot funding required) — the
//! webhook must still fire with `status: "failed"`. The deliberately-confirmed counterpart,
//! `sponsored_webhook_fires_on_confirmation`, lives in `horizon_live_tests.rs` (gated behind
//! `OCTO_LIVE_TESTS=1`) because it needs two friendbot-funded accounts and a real on-chain
//! confirmation, matching this crate's existing convention for live-network tests.
//!
//! Require Postgres via `DATABASE_URL` (skipped with a message otherwise, like `api_tests.rs`).
//! The Horizon submission itself still reaches the real testnet network (there is no mock), but
//! only to observe a fast rejection — no funding or confirmation polling is involved.

mod common;

use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::Router;
use octo_api::{build_router, AppState};
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use std::sync::{Arc, Once};
use std::time::Duration;
use stellar_base::crypto::DalekKeyPair;
use stellar_base::operations::Operation;
use stellar_base::transaction::{Transaction, MIN_BASE_FEE};
use stellar_base::xdr::XDRSerialize;
use tokio::sync::Mutex;
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
    let master_key = [42u8; 32];
    Some(AppState::new(
        store,
        master_key,
        StellarNetwork::Testnet,
        "https://horizon-testnet.stellar.org".into(),
        None,
        octo_email::EmailSender::new_captured(),
    ))
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("json")
}

fn post_auth(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
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

async fn auth_token(app: &Router, state: &AppState) -> String {
    let email = format!("sponsor-{}@octo.test", Uuid::new_v4().simple());
    common::signup_and_verify(app, state, &email).await
}

/// Create a non-custodial wallet (client-generated key) via the API and provision its gas tank
/// (the server-held fee account sponsorship signs with). Returns `(wallet_id, master_account_g)`.
async fn create_wallet(app: &Router, token: &str) -> (String, String) {
    let kp = DalekKeyPair::random().unwrap();
    let reg_body = common::wallet_body(app, token, &kp).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/wallets")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(reg_body))
                .unwrap(),
        )
        .await
        .unwrap();
    let w = body_json(resp).await;
    let id = w["data"]["id"].as_str().unwrap().to_string();
    let address = w["data"]["address"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(post_auth(&format!("/v1/wallets/{id}/gas-tank"), token))
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "gas tank provisioning must succeed"
    );
    (id, address)
}

/// Insert a permissive `gas_sponsorship_configs` row (enabled, no caps) for `wallet_id`. There is
/// no API to configure sponsorship yet, so tests reach straight into the store, same as the
/// fee-bump groundwork this issue builds on.
async fn enable_sponsorship(state: &AppState, wallet_id: &str) {
    sqlx::query("INSERT INTO gas_sponsorship_configs (wallet_id, enabled) VALUES ($1::uuid, true)")
        .bind(wallet_id)
        .execute(state.store().pool())
        .await
        .expect("insert gas_sponsorship_configs");
}

/// A trivially-signed Payment inner transaction from a throwaway, never-funded keypair. Horizon
/// will reject it on submission (the source account does not exist) — used for the "failed"
/// outcome tests, which need no friendbot funding at all.
fn unfunded_payment_xdr(destination_g: &str) -> String {
    let kp = DalekKeyPair::random().unwrap();
    let dest = stellar_base::crypto::PublicKey::from_account_id(destination_g).unwrap();
    let op = Operation::new_payment()
        .with_destination(dest)
        .with_amount(stellar_base::amount::Stroops::new(100))
        .unwrap()
        .with_asset(stellar_base::asset::Asset::new_native())
        .build()
        .unwrap();
    let tx = Transaction::builder(kp.public_key(), 1, MIN_BASE_FEE)
        .add_operation(op)
        .into_transaction()
        .unwrap();
    let mut tx = tx;
    tx.sign(kp.as_ref(), &stellar_base::network::Network::new_test())
        .unwrap();
    tx.into_envelope().xdr_base64().unwrap()
}

/// Spin up a tiny local HTTP server that accepts any POST and records the JSON body, returning
/// `(webhook_url, received_bodies)`. Local loopback targets are normally rejected by
/// `is_safe_url`; tests opt in via `OCTO_ALLOW_LOCAL_WEBHOOKS=1` (the documented dev/test escape
/// hatch in `octo_webhooks::is_safe_url`).
async fn spawn_webhook_receiver() -> (String, Arc<Mutex<Vec<serde_json::Value>>>) {
    std::env::set_var("OCTO_ALLOW_LOCAL_WEBHOOKS", "1");

    let received = Arc::new(Mutex::new(Vec::new()));
    let received_for_route = received.clone();

    let app = Router::new().route(
        "/hook",
        post(move |body: Bytes| {
            let received = received_for_route.clone();
            async move {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) {
                    received.lock().await.push(v);
                }
                StatusCode::OK
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (format!("http://127.0.0.1:{}/hook", addr.port()), received)
}

/// Register a webhook endpoint for `wallet_id` pointed at `url`.
async fn register_webhook(app: &Router, token: &str, wallet_id: &str, url: &str) {
    let body = format!(r#"{{"url":"{url}"}}"#);
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/webhooks"),
            &body,
            token,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "webhook registration must succeed"
    );
}

#[tokio::test]
async fn sponsored_webhook_fires_on_failure() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: DATABASE_URL is not set");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (wallet_id, master_g) = create_wallet(&app, &token).await;
    enable_sponsorship(&state, &wallet_id).await;

    let (hook_url, received) = spawn_webhook_receiver().await;
    register_webhook(&app, &token, &wallet_id, &hook_url).await;

    let inner_xdr = unfunded_payment_xdr(&master_g);
    let body = format!(r#"{{"transaction_xdr":"{inner_xdr}","max_base_fee_stroops":1000}}"#);
    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/sponsor"),
            &body,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let out = body_json(resp).await;
    assert_eq!(
        out["data"]["status"], "failed",
        "an unfunded source account must fail on submission: {out}"
    );

    // Give the detached webhook-firing task a moment to run and deliver.
    tokio::time::sleep(Duration::from_millis(800)).await;

    let delivered = received.lock().await;
    assert_eq!(
        delivered.len(),
        1,
        "exactly one webhook delivery must have been received"
    );
    let payload = &delivered[0];
    assert_eq!(payload["event"], "transaction.sponsored");
    assert_eq!(payload["data"]["wallet_id"], wallet_id);
    assert_eq!(payload["data"]["status"], "failed");
    // Note: the gas tank is a real, signed account, so Horizon returns a structured rejection
    // (unfunded fee source) that still carries a tx hash — hence fee_bump_tx_hash may be present
    // on failure. The meaningful invariant is that the status is "failed" and the inner hash is
    // recorded for reconciliation.
    assert!(payload["data"]["inner_tx_hash"].as_str().is_some());

    let row: (String, String) = sqlx::query_as(
        "SELECT status, event_type FROM webhook_deliveries
         WHERE event_type = 'transaction.sponsored'
         ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_one(state.store().pool())
    .await
    .expect("delivery row must exist");
    assert_eq!(row.0, "delivered");
    assert_eq!(row.1, "transaction.sponsored");
}

#[tokio::test]
async fn sponsored_webhook_skipped_when_no_endpoint() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: DATABASE_URL is not set");
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app, &state).await;
    let (wallet_id, master_g) = create_wallet(&app, &token).await;
    enable_sponsorship(&state, &wallet_id).await;
    // Deliberately no webhook endpoint registered for this wallet.

    let inner_xdr = unfunded_payment_xdr(&master_g);
    let body = format!(r#"{{"transaction_xdr":"{inner_xdr}","max_base_fee_stroops":1000}}"#);
    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/sponsor"),
            &body,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    tokio::time::sleep(Duration::from_millis(500)).await;

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM webhook_deliveries wd
         JOIN webhook_endpoints we ON we.id = wd.endpoint_id
         WHERE we.wallet_id = $1::uuid",
    )
    .bind(&wallet_id)
    .fetch_one(state.store().pool())
    .await
    .expect("count query");
    assert_eq!(
        count, 0,
        "no webhook delivery should be recorded when the wallet has no endpoint"
    );
}
