//! Fault-injection tests for the Horizon resilience layer.
//!
//! These spin up a local axum mock Horizon server and verify:
//!
//! 1. `balances` / `account_sequence` retry on transient 5xx failures and recover.
//! 2. `submit_transaction` is **never** retried — exactly one attempt regardless of
//!    `max_attempts`.
//! 3. The circuit breaker opens after the configured threshold and short-circuits calls
//!    without making a network request.
//! 4. The circuit breaker closes after the cool-down and a successful probe.
//!
//! No database is required.

use axum::extract::State;
use axum::routing::{get, post};
use axum::Router;
use octo_api::horizon::Horizon;
use octo_resilience::{CircuitBreaker, RetryPolicy};
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Mock Horizon helpers
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockState {
    /// Remaining failures before returning 200.
    fail_remaining: Arc<AtomicU32>,
    /// Total call count.
    call_count: Arc<AtomicU32>,
    /// HTTP status code for failures.
    fail_status: u16,
}

impl MockState {
    fn new(fails: u32, status: u16) -> Self {
        Self {
            fail_remaining: Arc::new(AtomicU32::new(fails)),
            call_count: Arc::new(AtomicU32::new(0)),
            fail_status: status,
        }
    }
}

async fn account_handler(
    State(s): State<MockState>,
) -> axum::response::Response<axum::body::Body> {
    s.call_count.fetch_add(1, Ordering::SeqCst);
    if s.fail_remaining.load(Ordering::SeqCst) > 0 {
        s.fail_remaining.fetch_sub(1, Ordering::SeqCst);
        return axum::response::Response::builder()
            .status(s.fail_status)
            .body(axum::body::Body::from("error"))
            .unwrap();
    }
    let body = r#"{"id":"G","balances":[{"balance":"100.0000000","asset_type":"native"}],"sequence":"9876543"}"#;
    axum::response::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn submit_handler(
    State(s): State<MockState>,
) -> axum::response::Response<axum::body::Body> {
    s.call_count.fetch_add(1, Ordering::SeqCst);
    if s.fail_remaining.load(Ordering::SeqCst) > 0 {
        s.fail_remaining.fetch_sub(1, Ordering::SeqCst);
        return axum::response::Response::builder()
            .status(s.fail_status)
            .body(axum::body::Body::from("error"))
            .unwrap();
    }
    let body = r#"{"hash":"txhash123","successful":true}"#;
    axum::response::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn start_mock(state: MockState) -> (String, MockState) {
    let app = Router::new()
        .route("/accounts/{account}", get(account_handler))
        .route("/transactions", post(submit_handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), state)
}

fn test_client(url: &str, max_attempts: u32, cb_threshold: u32, reset_ms: u64) -> Horizon {
    let retry = RetryPolicy {
        max_attempts,
        base_delay_ms: 0,
        max_delay_ms: 0,
        multiplier: 1.0,
        jitter_factor: 0.0,
    };
    let circuit = CircuitBreaker::new(cb_threshold, Duration::from_millis(reset_ms));
    Horizon::with_resilience(url, retry, circuit)
}

const GADDR: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";

// ---------------------------------------------------------------------------
// 1. Read-only retries recover after N transient failures
// ---------------------------------------------------------------------------

#[tokio::test]
async fn balances_retries_on_5xx_then_succeeds() {
    // Fail twice, succeed on the 3rd attempt.
    let (url, state) = start_mock(MockState::new(2, 500)).await;
    let client = test_client(&url, 3, 20, 60_000);

    let balances = client.balances(GADDR).await.expect("should recover");
    assert_eq!(balances.len(), 1);
    assert_eq!(balances[0].asset_type, "native");
    assert_eq!(
        state.call_count.load(Ordering::SeqCst),
        3,
        "must take exactly 3 attempts (2 failures + 1 success)"
    );
}

#[tokio::test]
async fn account_sequence_retries_on_5xx_then_succeeds() {
    let (url, state) = start_mock(MockState::new(1, 503)).await;
    let client = test_client(&url, 3, 20, 60_000);

    let seq = client.account_sequence(GADDR).await.expect("should recover");
    assert_eq!(seq, 9_876_543);
    assert_eq!(state.call_count.load(Ordering::SeqCst), 2);
}

// ---------------------------------------------------------------------------
// 2. submit_transaction is NEVER retried (double-submission risk guard)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn submit_transaction_is_never_retried_even_on_5xx() {
    // Mock always fails — max_attempts = 5, but Submit must attempt exactly once.
    let (url, state) = start_mock(MockState::new(999, 503)).await;
    let client = test_client(&url, 5, 100, 60_000);

    let result = client.submit_transaction("fake_xdr").await;
    assert!(result.is_err(), "submit must fail when mock always returns 503");
    assert_eq!(
        state.call_count.load(Ordering::SeqCst),
        1,
        "submit_transaction must be attempted exactly once — retrying risks double-submission"
    );
}

// ---------------------------------------------------------------------------
// 3. Circuit opens after threshold, short-circuits without a network call
// ---------------------------------------------------------------------------

#[tokio::test]
async fn circuit_opens_after_threshold_and_short_circuits() {
    // Always fail; threshold = 3.
    let (url, state) = start_mock(MockState::new(999, 500)).await;
    let client = test_client(&url, 1, 3, 60_000);

    // Three failing calls open the circuit.
    for _ in 0..3 {
        let _ = client.balances(GADDR).await;
    }
    assert_eq!(state.call_count.load(Ordering::SeqCst), 3);

    // Fourth call: circuit is open — must NOT reach the server.
    let _ = client.balances(GADDR).await;
    assert_eq!(
        state.call_count.load(Ordering::SeqCst),
        3,
        "no additional network call must be made when circuit is open"
    );
}

// ---------------------------------------------------------------------------
// 4. Circuit closes after cool-down and successful probe
// ---------------------------------------------------------------------------

#[tokio::test]
async fn circuit_closes_after_cooldown() {
    // Fail 3 times, then succeed.
    let (url, _state) = start_mock(MockState::new(3, 500)).await;
    // reset_ms = 50 so the test doesn't take long.
    let client = test_client(&url, 1, 3, 50);

    // Open the circuit.
    for _ in 0..3 {
        let _ = client.balances(GADDR).await;
    }
    // Confirm circuit is open.
    assert!(client.balances(GADDR).await.is_err());

    // Wait for the cool-down.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Mock now returns 200. Probe must succeed and close the circuit.
    let result = client.balances(GADDR).await;
    assert!(result.is_ok(), "circuit should close after cool-down + successful probe");
}
