//! Integration tests for the cursor-resume contract documented in crates/ingest/src/lib.rs.
//!
//! Covers two scenarios beyond the single-record idempotency test already in process_tests.rs:
//!
//! 1. **Crash-resume**: process a full page of N records via `poll_once`, then call `poll_once`
//!    again (simulating a restart where the cursor has already advanced to the last record). The
//!    second call must record zero new deposits and must not regress the cursor.
//!
//! 2. **Out-of-order page replay**: process the same N records twice via `Ingestor::process` but
//!    in reversed order the second time (simulating Horizon re-delivering records around a
//!    ledger-close boundary). Every record must deduplicate correctly regardless of order.
//!
//! Requires Postgres via `DATABASE_URL` (from .env). Skips gracefully if absent.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::Router;
use octo_ingest::horizon::{PaymentRecord, TransactionRecord};
use octo_ingest::{Ingestor, Processed};
use octo_store::{NewWallet, Store};
use serde::Deserialize;
use std::sync::{Arc, Mutex, Once};
use uuid::Uuid;

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

const BASE: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";

/// Build a trivial payment record directed at BASE.
fn make_record(id: &str) -> PaymentRecord {
    PaymentRecord {
        id: id.to_string(),
        paging_token: id.to_string(),
        kind: "payment".into(),
        transaction_hash: Some(format!("hash-{id}")),
        transaction_successful: true,
        from: Some("Gsender".into()),
        to: Some(BASE.into()),
        to_muxed: None,
        to_muxed_id: None,
        asset_type: Some("native".into()),
        asset_code: None,
        asset_issuer: None,
        amount: Some("1.0000000".into()),
        starting_balance: None,
        transaction: Some(TransactionRecord {
            memo_type: None,
            memo: None,
            ledger: Some(42),
        }),
    }
}

// ---------------------------------------------------------------------------
// Shared state for the mock Horizon
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockState {
    /// The records to return for the initial (cursor-less) request.
    records: Vec<PaymentRecord>,
    /// After the first page is consumed (cursor == last paging_token) return empty.
    last_cursor: String,
    /// How many times the payments endpoint was called.
    call_count: Arc<Mutex<usize>>,
}

#[derive(Deserialize)]
struct PaymentsQuery {
    cursor: Option<String>,
}

/// Axum handler for `/accounts/:account/payments?...`
async fn mock_payments_handler(
    Query(q): Query<PaymentsQuery>,
    State(state): State<MockState>,
) -> axum::response::Response<axum::body::Body> {
    *state.call_count.lock().unwrap() += 1;

    // When the cursor has already passed our last record, return an empty page.
    let records = if q.cursor.as_deref() == Some(&state.last_cursor) {
        vec![]
    } else {
        state.records.clone()
    };

    let body = serde_json::json!({
        "_embedded": { "records": records }
    });

    axum::response::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

/// Spin up a mock Horizon and return its base URL plus shared call-count.
async fn start_mock_horizon(state: MockState) -> (String, Arc<Mutex<usize>>) {
    let call_count = state.call_count.clone();
    let app = Router::new()
        .route("/accounts/{account}/payments", get(mock_payments_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock Horizon");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock Horizon serve");
    });

    (format!("http://{addr}"), call_count)
}

/// Create an isolated wallet + ingestor backed by the provided Horizon URL.
async fn setup_with_horizon(db_url: &str, horizon_url: &str) -> Option<(Store, Ingestor, Uuid)> {
    let store = Store::connect(db_url).await.expect("connect");
    store.migrate().await.expect("migrate");

    let run_id = Uuid::new_v4().simple().to_string();
    let wallet = store
        .create_wallet(octo_store::NewWallet {
            network: "testnet",
            stellar_account_g: &format!("{BASE}-resume-{run_id}"),
            sealed_ciphertext: b"ct",
            sealed_nonce: b"nonce",
            sealed_salt: b"salt",
            label: None,
            user_id: None,
            description: None,
        })
        .await
        .expect("create wallet");

    let ingestor = Ingestor::new(
        store.clone(),
        horizon_url,
        wallet.id,
        BASE.to_string(),
    );
    Some((store, ingestor, wallet.id))
}

// ---------------------------------------------------------------------------
// Test 1: crash-resume — a second poll_once after the cursor has advanced
//         must record zero new deposits.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn resumed_poll_after_full_page_processes_nothing_new() {
    let Some(db_url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL to run cursor-resume tests");
        return;
    };

    // Build a page of 3 records.
    let records: Vec<PaymentRecord> = (1..=3).map(|i| make_record(&format!("op-resume-{i}"))).collect();
    let last_cursor = records.last().unwrap().paging_token.clone();

    let mock_state = MockState {
        records: records.clone(),
        last_cursor: last_cursor.clone(),
        call_count: Arc::new(Mutex::new(0)),
    };
    let (horizon_url, call_count) = start_mock_horizon(mock_state).await;

    let Some((store, ingestor, wallet_id)) = setup_with_horizon(&db_url, &horizon_url).await else {
        return;
    };

    // First poll: processes all 3 records and advances cursor to last_cursor.
    let n = ingestor.poll_once(10).await.expect("first poll_once");
    assert_eq!(n, 3, "first poll should process all 3 records");

    let tx_count_after_first = store.list_transactions(wallet_id).await.unwrap().len();
    assert_eq!(tx_count_after_first, 3);

    // Verify cursor was advanced to the last record's paging token.
    let cursor = store.get_cursor(wallet_id).await.unwrap();
    assert_eq!(cursor.as_deref(), Some(last_cursor.as_str()), "cursor must point at last record");

    // Second poll: same mock returns empty page (cursor == last_cursor).
    // This simulates resuming after a crash — no records should be re-recorded.
    let n2 = ingestor.poll_once(10).await.expect("second poll_once");
    assert_eq!(n2, 0, "resumed poll must process zero new records");

    let tx_count_after_second = store.list_transactions(wallet_id).await.unwrap().len();
    assert_eq!(
        tx_count_after_second, 3,
        "no new deposits must be recorded on cursor-resume"
    );

    // Cursor must not have regressed.
    let cursor_after = store.get_cursor(wallet_id).await.unwrap();
    assert_eq!(
        cursor_after.as_deref(),
        Some(last_cursor.as_str()),
        "cursor must not regress after a resumed empty poll"
    );

    // The mock was called at least twice (initial + resume).
    assert!(
        *call_count.lock().unwrap() >= 2,
        "mock Horizon should have been called at least twice"
    );
}

// ---------------------------------------------------------------------------
// Test 2: out-of-order replay — same records re-processed in reversed order
//         must all deduplicate correctly, no extra deposits.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn replayed_page_out_of_original_order_still_dedupes_correctly() {
    let Some(db_url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL to run cursor-resume tests");
        return;
    };

    // We only need Ingestor::process here, not poll_once, so no mock Horizon needed.
    let store = Store::connect(&db_url).await.expect("connect");
    store.migrate().await.expect("migrate");

    let run_id = Uuid::new_v4().simple().to_string();
    let wallet = store
        .create_wallet(octo_store::NewWallet {
            network: "testnet",
            stellar_account_g: &format!("{BASE}-reorder-{run_id}"),
            sealed_ciphertext: b"ct",
            sealed_nonce: b"nonce",
            sealed_salt: b"salt",
            label: None,
            user_id: None,
            description: None,
        })
        .await
        .expect("create wallet");

    let ingestor = Ingestor::new(store.clone(), "http://unused", wallet.id, BASE.to_string());

    // Build a page of 5 records in ascending order.
    let records: Vec<PaymentRecord> = (1..=5)
        .map(|i| make_record(&format!("op-reorder-{run_id}-{i}")))
        .collect();

    // First pass: process all 5 in original ascending order.
    for rec in &records {
        let outcome = ingestor.process(rec).await.expect("process");
        assert!(
            matches!(outcome, Processed::Recorded { .. }),
            "first-pass record should be Recorded, got {outcome:?}"
        );
    }

    let tx_count_after_first = store.list_transactions(wallet.id).await.unwrap().len();
    assert_eq!(tx_count_after_first, 5, "all 5 records should be stored after first pass");

    // Second pass: replay in reversed (out-of-order) sequence.
    let reversed: Vec<&PaymentRecord> = records.iter().rev().collect();
    for rec in reversed {
        let outcome = ingestor.process(rec).await.expect("process (replay)");
        assert_eq!(
            outcome,
            Processed::Duplicate,
            "re-delivered record {} must be a no-op duplicate, got {outcome:?}",
            rec.id
        );
    }

    // No additional deposits must have been recorded.
    let tx_count_after_second = store.list_transactions(wallet.id).await.unwrap().len();
    assert_eq!(
        tx_count_after_second, 5,
        "out-of-order replay must not create any new deposit rows"
    );
}
