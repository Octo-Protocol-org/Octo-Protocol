//! Integration test: Supervisor::tick must only poll wallets whose network matches its own.
//!
//! When a testnet Supervisor runs tick(), it must query Horizon only for the testnet wallet's
//! account and never touch the mainnet wallet's account — even though both wallets live in the
//! same `wallets` table.
//!
//! Requires Postgres via `DATABASE_URL` (from .env). Skips gracefully if absent.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::Router;
use octo_ingest::Supervisor;
use octo_store::{NewWallet, Store};
use octo_webhooks::WebhookSender;
use std::sync::{Arc, Mutex, Once};
use uuid::Uuid;

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

// Two distinct valid-looking G… account strings — the mock Horizon tracks which ones are hit.
const TESTNET_ACCOUNT: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";
const MAINNET_ACCOUNT: &str = "GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR";

/// Minimal valid Horizon payments-page response with zero records.
fn empty_page() -> &'static str {
    r#"{"_embedded":{"records":[]}}"#
}

/// Axum handler: record the account that was queried, then return an empty payments page.
async fn mock_payments_handler(
    Path(account): Path<String>,
    State(queried): State<Arc<Mutex<Vec<String>>>>,
) -> axum::response::Response<axum::body::Body> {
    queried.lock().unwrap().push(account);
    axum::response::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(empty_page()))
        .unwrap()
}

#[tokio::test]
async fn tick_only_polls_wallets_on_its_configured_network() {
    let Some(db_url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL to run supervisor network-isolation test");
        return;
    };

    let store = Store::connect(&db_url).await.expect("connect to DB");
    store.migrate().await.expect("run migrations");

    // Unique account suffix per test run so rows don't collide between parallel test invocations.
    let run_id = Uuid::new_v4().simple().to_string();
    let testnet_acct = format!("{TESTNET_ACCOUNT}-tn-{run_id}");
    let mainnet_acct = format!("{MAINNET_ACCOUNT}-mn-{run_id}");

    // Create one testnet wallet and one mainnet wallet.
    store
        .create_wallet(NewWallet {
            network: "testnet",
            stellar_account_g: &testnet_acct,
            sealed_ciphertext: b"ct",
            sealed_nonce: b"nonce",
            sealed_salt: b"salt",
            label: Some("testnet-wallet"),
            user_id: None,
            description: None,
        })
        .await
        .expect("create testnet wallet");

    store
        .create_wallet(NewWallet {
            network: "mainnet",
            stellar_account_g: &mainnet_acct,
            sealed_ciphertext: b"ct",
            sealed_nonce: b"nonce",
            sealed_salt: b"salt",
            label: Some("mainnet-wallet"),
            user_id: None,
            description: None,
        })
        .await
        .expect("create mainnet wallet");

    // Spin up a local axum mock that records every account queried.
    let queried: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        // Horizon payments URL pattern: /accounts/{account}/payments?...
        .route("/accounts/{account}/payments", get(mock_payments_handler))
        .with_state(queried.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock Horizon");
    let mock_addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock Horizon serve");
    });

    let horizon_url = format!("http://{mock_addr}");

    // Run a Supervisor configured for "testnet" only.
    let webhooks = WebhookSender::new(store.clone());
    let supervisor = Supervisor::new(store.clone(), horizon_url, webhooks, "testnet");
    supervisor.tick(10).await.expect("supervisor tick");

    // Give any async Horizon requests a moment to land in the mock.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let accounts_hit = queried.lock().unwrap().clone();

    // The testnet account must have been polled at least once.
    assert!(
        accounts_hit.iter().any(|a| a.starts_with(TESTNET_ACCOUNT)),
        "testnet account should have been queried; got: {accounts_hit:?}"
    );

    // The mainnet account must never have been queried.
    assert!(
        !accounts_hit.iter().any(|a| a.starts_with(MAINNET_ACCOUNT)),
        "mainnet account must NOT be queried by a testnet supervisor; got: {accounts_hit:?}"
    );
}
