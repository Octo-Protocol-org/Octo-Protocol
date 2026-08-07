//! Coverage for the withdrawal pre-flight balance / minimum-reserve check
//! (`crates/api/src/routes/withdrawals.rs::withdraw`).
//!
//! Requires Postgres via `DATABASE_URL` (see `docker-compose.yml`), same as the other
//! `crates/api/tests/*` files — skipped (with a message) if it isn't set.
//!
//! Horizon itself is a small local mock (not testnet), following the same convention as
//! `sponsor_e2e_tests.rs`: a wallet is created for real (real key material, real derived `G...`
//! address via `octo-wallet-core`), but `GET /accounts/*` is served by an in-process axum app
//! instead of live testnet, so these tests are deterministic and don't depend on a funded testnet
//! account.
//!
//! The mock answers every `GET /accounts/*` with the same canned response regardless of which
//! address was requested. That's deliberate, not a shortcut: each of these tests only cares about
//! ONE account's balance (the wallet's own), and the withdrawal route's later destination-exists
//! check only reads the `balances` array off whatever it's given — so a single canned "an account
//! exists with these balances" response correctly satisfies both the source-account pre-flight
//! check and (where the flow reaches it) the destination-exists check, without this test needing
//! to predict the wallet's randomly-derived address ahead of creating it.

mod common;

use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use octo_api::{build_router, AppState};
use octo_store::{NewWallet, Store};
use octo_wallet_core::{provision_wallet, StellarNetwork};
use serde_json::{json, Value};
use std::sync::Once;
use tower::ServiceExt;
use uuid::Uuid;

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

async fn test_state(horizon_url: String) -> Option<AppState> {
    let url = database_url()?;
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    let master_key = [42u8; 32];
    Some(AppState::new(
        store,
        master_key,
        StellarNetwork::Testnet,
        horizon_url,
        None,
        octo_email::EmailSender::new_captured(),
    ))
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("json")
}

fn post_json_auth(uri: &str, body: &str, token: &str) -> Request<axum::body::Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

/// Sign up a fresh user and return both its login JWT and its id. The id is needed because the
/// withdrawal fixture writes its wallet row directly (see [`create_wallet`]) and has to set
/// `user_id` itself for the route's ownership check to pass.
///
/// Signup only issues a token once the emailed OTP is consumed, so this goes through
/// `common::signup_and_verify_full` rather than posting to `/v1/auth/signup` directly.
async fn auth_token(app: &Router, state: &AppState) -> (String, Uuid) {
    let email = format!("withdraw-preflight-{}@octo.test", Uuid::new_v4().simple());
    let (token, user_id) = common::signup_and_verify_full(app, state, &email).await;
    (token, Uuid::parse_str(&user_id).expect("user id is a uuid"))
}

/// Create a **server-custody** wallet (real key derivation, real sealed seed) and return its id.
///
/// This writes the row through the store rather than `POST /v1/wallets`, because since the
/// non-custodial cutover that route only ever mints `custody = 'client'` rows — which carry no
/// server-side seed, so `withdraw` refuses them before the pre-flight check ever runs. The
/// withdrawal path serves legacy `custody = 'server'` rows, so that is what these tests must
/// exercise. `provision_wallet` seals under the same `[42u8; 32]` master key `test_state` uses,
/// so the handler can actually open the seed and sign.
async fn create_wallet(state: &AppState, user_id: Uuid) -> String {
    let provisioned = provision_wallet(&[42u8; 32], StellarNetwork::Testnet).expect("provision");
    let wallet = state
        .store()
        .create_wallet(NewWallet {
            network: "testnet",
            stellar_account_g: &provisioned.account_g,
            sealed_ciphertext: &provisioned.sealed.ciphertext,
            sealed_nonce: &provisioned.sealed.nonce,
            sealed_salt: &provisioned.sealed.salt,
            sealed_scheme: provisioned.sealed.scheme as i16,
            label: Some("withdraw-preflight"),
            user_id: Some(user_id),
            description: None,
        })
        .await
        .expect("create server-custody wallet");
    wallet.id.to_string()
}

/// A local mock Horizon: every `GET /accounts/*` returns the same canned `account_response`
/// (see module docs for why a catch-all is the right shape here); `POST /transactions` always
/// reports a successful submission.
async fn start_mock_horizon(account_response: Value) -> String {
    async fn get_account(
        axum::extract::State(body): axum::extract::State<Value>,
    ) -> axum::Json<Value> {
        axum::Json(body)
    }

    async fn submit() -> axum::Json<Value> {
        axum::Json(json!({
            "hash": format!("mock-{}", Uuid::new_v4().simple()),
            "successful": true,
            "ledger": 12345
        }))
    }

    let app = Router::new()
        .route("/accounts/:id", get(get_account))
        .route("/transactions", post(submit))
        .with_state(account_response);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock horizon");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// A native-XLM-only Horizon account response with the given balance and subentry count.
/// `sequence` must parse as i64 — `account_info()` hard-fails otherwise. Also serves fine as the
/// destination-exists response, since `balances()` only reads the `balances` field.
fn native_account(balance: &str, subentry_count: i64) -> Value {
    json!({
        "balances": [{ "balance": balance, "asset_type": "native" }],
        "sequence": "100",
        "subentry_count": subentry_count,
        "num_sponsoring": 0,
        "num_sponsored": 0
    })
}

const SOME_DESTINATION: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";

/// Asserts a given idempotency key never made it into the `withdrawals` table — the load-bearing
/// proof for both rejection tests (see the issue: a doomed request must never consume the key).
async fn assert_key_not_consumed(state: &AppState, key: &str) {
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM withdrawals WHERE idempotency_key = $1")
            .bind(key)
            .fetch_one(state.store().pool())
            .await
            .unwrap();
    assert_eq!(
        count, 0,
        "a request that could never succeed must not consume the idempotency key"
    );
}

#[tokio::test]
async fn withdraw_rejects_when_wallet_balance_is_insufficient_without_consuming_the_idempotency_key(
) {
    // Source account holds far less than the requested amount — the very first pre-flight check
    // must reject this before the idempotency key (or anything else) is touched.
    let horizon_url = start_mock_horizon(native_account("0.0000100", 0)).await; // 100 stroops

    let Some(state) = test_state(horizon_url).await else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };
    let app = build_router(state.clone());
    let (token, user_id) = auth_token(&app, &state).await;
    let wallet_id = create_wallet(&state, user_id).await;

    let key = format!("key-{}", Uuid::new_v4());
    let uri = format!("/v1/wallets/{wallet_id}/withdraw");
    let body = format!(
        r#"{{"destination":"{SOME_DESTINATION}","amount_stroops":50000000000,"idempotency_key":"{key}"}}"#
    );

    let resp = app
        .oneshot(post_json_auth(&uri, &body, &token))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "insufficient balance must be rejected with 400"
    );

    assert_key_not_consumed(&state, &key).await;
}

#[tokio::test]
async fn withdraw_rejects_native_withdrawal_that_would_breach_the_minimum_reserve() {
    // subentry_count 0 => min reserve = 5_000_000 * 2 = 10_000_000 stroops (1 XLM). The balance
    // below comfortably covers amount + fee (the protocol-floor fee is always a few hundred
    // stroops at most) but leaves far less than the 10_000_000-stroop reserve once that's
    // subtracted — so the *reserve* check must be what fails, not the balance check.
    let horizon_url = start_mock_horizon(native_account("0.5000100", 0)).await; // 5,000,100 stroops

    let Some(state) = test_state(horizon_url).await else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };
    let app = build_router(state.clone());
    let (token, user_id) = auth_token(&app, &state).await;
    let wallet_id = create_wallet(&state, user_id).await;

    let key = format!("key-{}", Uuid::new_v4());
    let uri = format!("/v1/wallets/{wallet_id}/withdraw");
    // amount_stroops is tiny (1 stroop) on purpose: the point under test is that balance minus
    // (amount + fee) undercuts the reserve, not that the withdrawal amount itself is large.
    let body = format!(
        r#"{{"destination":"{SOME_DESTINATION}","amount_stroops":1,"idempotency_key":"{key}"}}"#
    );

    let resp = app
        .oneshot(post_json_auth(&uri, &body, &token))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "a withdrawal that would breach the minimum reserve must be rejected with 400"
    );

    assert_key_not_consumed(&state, &key).await;
}

#[tokio::test]
async fn withdraw_succeeds_when_balance_is_sufficient() {
    let horizon_url = start_mock_horizon(native_account("1000.0000000", 0)).await; // 10B stroops

    let Some(state) = test_state(horizon_url).await else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };
    let app = build_router(state.clone());
    let (token, user_id) = auth_token(&app, &state).await;
    let wallet_id = create_wallet(&state, user_id).await;

    let key = format!("key-{}", Uuid::new_v4());
    let uri = format!("/v1/wallets/{wallet_id}/withdraw");
    let body = format!(
        r#"{{"destination":"{SOME_DESTINATION}","amount_stroops":1000000,"idempotency_key":"{key}"}}"#
    );

    let resp = app
        .oneshot(post_json_auth(&uri, &body, &token))
        .await
        .unwrap();
    let status = resp.status();
    let json = body_json(resp).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a well-funded withdrawal must succeed (got body: {json})"
    );
    assert_eq!(json["data"]["amount_stroops"], 1_000_000);
    assert_eq!(json["data"]["status"], "confirmed");

    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM withdrawals WHERE idempotency_key = $1")
            .bind(&key)
            .fetch_one(state.store().pool())
            .await
            .unwrap();
    assert_eq!(
        count, 1,
        "a successful withdrawal must record exactly one row"
    );
}
