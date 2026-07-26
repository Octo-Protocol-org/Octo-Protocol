//! Integration test: Supervisor::tick must poll wallets CONCURRENTLY, not one at a time.
//!
//! Sequential polling meant a single slow wallet blocked every wallet behind it — with hundreds
//! of wallets, a deposit on a late one could sit unprocessed for minutes. This test proves ticks
//! overlap by giving every mock Horizon request an artificial delay and asserting the whole pass
//! finishes in much less than N * delay (which would only be possible with sequential polling).
//!
//! Requires Postgres via `DATABASE_URL` (from .env). Skips gracefully if absent.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::Router;
use octo_ingest::Supervisor;
use octo_store::{NewWallet, Store};
use octo_webhooks::WebhookSender;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Once};
use std::time::Duration;
use uuid::Uuid;

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

const WALLET_COUNT: usize = 15;
const REQUEST_DELAY_MS: u64 = 200;

fn empty_page() -> &'static str {
    r#"{"_embedded":{"records":[]}}"#
}

/// Sleeps `REQUEST_DELAY_MS` before responding, and counts concurrent in-flight requests.
async fn slow_mock_payments_handler(
    Path(_account): Path<String>,
    State((in_flight, max_seen)): State<(Arc<AtomicUsize>, Arc<AtomicUsize>)>,
) -> axum::response::Response<axum::body::Body> {
    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
    max_seen.fetch_max(now, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(REQUEST_DELAY_MS)).await;
    in_flight.fetch_sub(1, Ordering::SeqCst);
    axum::response::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(empty_page()))
        .unwrap()
}

#[tokio::test]
async fn tick_polls_wallets_concurrently_not_sequentially() {
    let Some(db_url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL to run supervisor concurrency test");
        return;
    };

    let store = Store::connect(&db_url).await.expect("connect to DB");
    store.migrate().await.expect("run migrations");

    let run_id = Uuid::new_v4().simple().to_string();
    for i in 0..WALLET_COUNT {
        let acct = format!(
            "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6-{run_id}-{i}"
        );
        store
            .create_wallet(NewWallet {
                network: "testnet",
                stellar_account_g: &acct,
                sealed_ciphertext: b"ct",
                sealed_nonce: b"nonce",
                sealed_salt: b"salt",
                sealed_scheme: 1,
                label: Some("concurrency-test-wallet"),
                user_id: None,
                description: None,
            })
            .await
            .expect("create wallet");
    }

    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/accounts/:account/payments", get(slow_mock_payments_handler))
        .with_state((in_flight.clone(), max_seen.clone()));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock Horizon");
    let mock_addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock Horizon serve");
    });

    let horizon_url = format!("http://{mock_addr}");
    let webhooks = WebhookSender::new(store.clone());
    let supervisor = Supervisor::new(store.clone(), horizon_url, webhooks, "testnet");

    // A dev DB accumulates testnet wallets across many prior test runs — this supervisor will
    // poll ALL of them (this test can't isolate to only the WALLET_COUNT it just created), so
    // compute the sequential-worst-case bound from the real total, not the constant.
    let total_testnet_wallets = store
        .list_wallets()
        .await
        .expect("list wallets")
        .into_iter()
        .filter(|w| w.network == "testnet")
        .count();

    let started = std::time::Instant::now();
    supervisor.tick(10).await.expect("supervisor tick");
    let elapsed = started.elapsed();

    let sequential_worst_case =
        Duration::from_millis(REQUEST_DELAY_MS * total_testnet_wallets as u64);
    assert!(
        elapsed < sequential_worst_case / 2,
        "tick took {elapsed:?} for {total_testnet_wallets} testnet wallets at \
         {REQUEST_DELAY_MS}ms each — this is only possible if wallets were polled \
         sequentially, not concurrently"
    );

    let peak_concurrency = max_seen.load(Ordering::SeqCst);
    assert!(
        peak_concurrency > 1,
        "expected multiple wallet polls in flight at once; observed peak concurrency = {peak_concurrency}"
    );
}
