//! Live Stellar testnet tests for friendbot funding + balance reads.
//!
//! These hit the real network and are **off by default**. Enable with both:
//!   `DATABASE_URL=...` (Postgres) and `OCTO_LIVE_TESTS=1`
//! e.g. `OCTO_LIVE_TESTS=1 cargo test -p octo-api --test horizon_live_tests`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
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

static LOAD_ENV: Once = Once::new();

fn enabled() -> bool {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("OCTO_LIVE_TESTS").as_deref() == Ok("1") && std::env::var("DATABASE_URL").is_ok()
}

async fn live_state() -> Option<AppState> {
    if !enabled() {
        return None;
    }
    let url = std::env::var("DATABASE_URL").ok()?;
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    Some(AppState::new(
        store,
        [7u8; 32],
        StellarNetwork::Testnet,
        "https://horizon-testnet.stellar.org".into(),
        Some("https://friendbot.stellar.org".into()),
    ))
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

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Sign up a fresh user and return its bearer token (wallet creation requires auth).
async fn auth_token(app: &axum::Router) -> String {
    let email = format!("live-{}@octo.test", uuid::Uuid::new_v4().simple());
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/signup")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"email":"{email}","password":"supersecret"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    body_json(resp).await["data"]["token"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn create_wallet_funds_and_has_balance() {
    let Some(state) = live_state().await else {
        eprintln!("SKIPPED: set OCTO_LIVE_TESTS=1 and DATABASE_URL to run live testnet tests");
        return;
    };
    let app = build_router(state);
    let token = auth_token(&app).await;

    // Client generates the key; server friendbot-funds the supplied account on testnet.
    let account = DalekKeyPair::random().unwrap().public_key().account_id();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/wallets")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(format!(r#"{{"public_key":"{account}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    let wallet = body_json(resp).await;
    let id = wallet["data"]["id"].as_str().unwrap().to_string();
    assert_eq!(
        wallet["data"]["funded"], true,
        "testnet wallet should be friendbot-funded"
    );

    // Balances should now include a positive native XLM balance.
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/wallets/{id}/balances"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bal = body_json(resp).await;
    let balances = bal["data"].as_array().unwrap();
    assert!(!balances.is_empty(), "funded account must have balances");
    let native = balances
        .iter()
        .find(|b| b["asset_type"] == "native")
        .expect("native balance present");
    let amount: f64 = native["balance"].as_str().unwrap().parse().unwrap();
    assert!(
        amount > 0.0,
        "native balance must be positive after funding"
    );
}

/// Create a non-custodial wallet from a caller-generated keypair, friendbot-funded on testnet.
/// Returns `(wallet_id, account_g, keypair, owner_token)` so the test can sign + relay locally.
async fn create_funded_wallet(app: &axum::Router) -> (String, String, DalekKeyPair, String) {
    let token = auth_token(app).await;
    let kp = DalekKeyPair::random().unwrap();
    let account = kp.public_key().account_id();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/wallets")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(format!(r#"{{"public_key":"{account}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    let w = body_json(resp).await;
    (
        w["data"]["id"].as_str().unwrap().to_string(),
        w["data"]["address"].as_str().unwrap().to_string(),
        kp,
        token,
    )
}

#[tokio::test]
async fn submit_signed_sends_xlm_on_chain() {
    let Some(state) = live_state().await else {
        eprintln!("SKIPPED: set OCTO_LIVE_TESTS=1 and DATABASE_URL");
        return;
    };
    let app = build_router(state);

    // Two funded wallets: A pays B. A signs the payment CLIENT-SIDE (the server never holds A's
    // key) and relays it through submit-signed.
    let (wallet_a, addr_a, kp_a, token_a) = create_funded_wallet(&app).await;
    let (_wallet_b, addr_b, _kp_b, _token_b) = create_funded_wallet(&app).await;

    // Build + sign a 1 XLM payment locally, using signing-info for the sequence number.
    let seq = sequence_with_retry("https://horizon-testnet.stellar.org", &addr_a).await;
    let dest = stellar_base::crypto::PublicKey::from_account_id(&addr_b).unwrap();
    let op = Operation::new_payment()
        .with_destination(dest)
        .with_amount(stellar_base::amount::Stroops::new(10_000_000))
        .unwrap()
        .with_asset(stellar_base::asset::Asset::new_native())
        .build()
        .unwrap();
    let mut tx = Transaction::builder(kp_a.public_key(), seq + 1, MIN_BASE_FEE)
        .add_operation(op)
        .into_transaction()
        .unwrap();
    tx.sign(kp_a.as_ref(), &stellar_base::network::Network::new_test())
        .unwrap();
    let signed_xdr = tx.into_envelope().xdr_base64().unwrap();

    let body = format!(r#"{{"transaction_xdr":"{signed_xdr}"}}"#);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/wallets/{wallet_a}/submit-signed"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token_a}"))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "submit-signed should be accepted"
    );
    let out = body_json(resp).await;
    assert_eq!(
        out["data"]["status"], "confirmed",
        "client-signed payment must confirm on-chain: {out}"
    );
    assert!(
        out["data"]["stellar_tx_hash"].as_str().is_some(),
        "a tx hash must be returned"
    );
}

/// Fetch `account_g`'s current sequence number, retrying for a bit while friendbot funding lands.
async fn sequence_with_retry(horizon_url: &str, account_g: &str) -> i64 {
    let horizon = octo_api::horizon::Horizon::new(horizon_url);
    for _ in 0..10 {
        if let Ok(seq) = horizon.account_sequence(account_g).await {
            return seq;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    panic!("account {account_g} never became available on Horizon after funding");
}

/// A signed Payment inner transaction from a fresh, friendbot-funded keypair to `destination_g`.
async fn funded_payment_xdr(friendbot_url: &str, horizon_url: &str, destination_g: &str) -> String {
    let kp = DalekKeyPair::random().expect("random keypair");
    let source_g = kp.public_key().account_id();
    octo_api::horizon::friendbot_fund(friendbot_url, &source_g)
        .await
        .expect("fund inner-tx source account");

    let seq = sequence_with_retry(horizon_url, &source_g).await;
    let dest = stellar_base::crypto::PublicKey::from_account_id(destination_g).unwrap();
    let op = Operation::new_payment()
        .with_destination(dest)
        .with_amount(stellar_base::amount::Stroops::new(100))
        .unwrap()
        .with_asset(stellar_base::asset::Asset::new_native())
        .build()
        .unwrap();
    let mut tx = Transaction::builder(kp.public_key(), seq + 1, MIN_BASE_FEE)
        .add_operation(op)
        .into_transaction()
        .unwrap();
    tx.sign(kp.as_ref(), &stellar_base::network::Network::new_test())
        .unwrap();
    tx.into_envelope().xdr_base64().unwrap()
}

/// Enable gas sponsorship (no caps) for `wallet_id`. There is no API for this yet, so the test
/// reaches straight into the store, same as the rest of the fee-bump groundwork this builds on.
async fn enable_sponsorship(state: &AppState, wallet_id: &str) {
    sqlx::query("INSERT INTO gas_sponsorship_configs (wallet_id, enabled) VALUES ($1::uuid, true)")
        .bind(wallet_id)
        .execute(state.store().pool())
        .await
        .expect("insert gas_sponsorship_configs");
}

/// Spin up a tiny local HTTP receiver and return `(url, received_bodies)`. Local loopback targets
/// are normally rejected by `is_safe_url`; `OCTO_ALLOW_LOCAL_WEBHOOKS=1` is the documented dev/test
/// escape hatch.
async fn spawn_webhook_receiver() -> (String, Arc<Mutex<Vec<serde_json::Value>>>) {
    std::env::set_var("OCTO_ALLOW_LOCAL_WEBHOOKS", "1");
    let received = Arc::new(Mutex::new(Vec::new()));
    let received_for_route = received.clone();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |bytes: axum::body::Bytes| {
            let received = received_for_route.clone();
            async move {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
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

#[tokio::test]
async fn sponsored_webhook_fires_on_confirmation() {
    let Some(state) = live_state().await else {
        eprintln!("SKIPPED: set OCTO_LIVE_TESTS=1 and DATABASE_URL to run live testnet tests");
        return;
    };
    let app = build_router(state.clone());

    // One user owns both the wallet and its webhook registration throughout.
    let token = auth_token(&app).await;
    let account = DalekKeyPair::random().unwrap().public_key().account_id();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/wallets")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(format!(r#"{{"public_key":"{account}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    let wallet = body_json(resp).await;
    let wallet_id = wallet["data"]["id"].as_str().unwrap().to_string();

    // The fee-bump is paid by the wallet's gas tank (a server-held fee account); provision +
    // friendbot-fund it, and use its address as the inner-tx recipient/sponsor reference.
    let resp = app
        .clone()
        .oneshot(post_auth(
            &format!("/v1/wallets/{wallet_id}/gas-tank"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let tank = body_json(resp).await;
    let master_g = tank["data"]["gas_tank_address"].as_str().unwrap().to_string();
    assert_eq!(
        tank["data"]["funded"], true,
        "the gas tank must be friendbot-funded to pay the fee-bump fee"
    );
    enable_sponsorship(&state, &wallet_id).await;

    let (hook_url, received) = spawn_webhook_receiver().await;
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/webhooks"),
            &format!(r#"{{"url":"{hook_url}"}}"#),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "webhook registration must succeed for the wallet's owner"
    );

    // A second, throwaway friendbot-funded account sources the inner (sponsored) payment.
    let inner_xdr = funded_payment_xdr(
        "https://friendbot.stellar.org",
        "https://horizon-testnet.stellar.org",
        &master_g,
    )
    .await;

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
        out["data"]["status"], "confirmed",
        "sponsored fee-bump must confirm on-chain: {out}"
    );
    assert!(out["data"]["fee_bump_tx_hash"].as_str().is_some());

    // Give the detached webhook-firing task a moment to deliver.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let delivered = received.lock().await;
    assert_eq!(
        delivered.len(),
        1,
        "exactly one webhook delivery must have been received"
    );
    let payload = &delivered[0];
    assert_eq!(payload["event"], "transaction.sponsored");
    assert_eq!(payload["data"]["wallet_id"], wallet_id);
    assert_eq!(payload["data"]["status"], "confirmed");
    assert!(payload["data"]["fee_bump_tx_hash"].as_str().is_some());

    let row_status: String = sqlx::query_scalar(
        "SELECT status FROM webhook_deliveries
         WHERE event_type = 'transaction.sponsored'
         ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_one(state.store().pool())
    .await
    .expect("delivery row must exist");
    assert_eq!(row_status, "delivered");
}
