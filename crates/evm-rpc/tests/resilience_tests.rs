//! Fault-injection tests for `EvmRpcClient`'s resilience layer, in the style of
//! `crates/api/tests/horizon_resilience_tests.rs`.
//!
//! 1. Read-only calls retry on transient 5xx failures and recover.
//! 2. `eth_sendRawTransaction` is **never** retried — exactly one attempt regardless of
//!    `max_attempts` (the submit-asymmetry rule, AD-5).
//! 3. The circuit breaker opens after the configured threshold and short-circuits calls without
//!    making a network request.
//! 4. The circuit breaker closes after the cool-down and a successful probe.

use axum::extract::State;
use axum::routing::post;
use axum::Router;
use octo_evm_rpc::EvmRpcClient;
use octo_resilience::{CircuitBreaker, RetryPolicy};
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Mock JSON-RPC endpoint
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockState {
    /// Remaining failures before returning a successful JSON-RPC result.
    fail_remaining: Arc<AtomicU32>,
    call_count: Arc<AtomicU32>,
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

async fn rpc_handler(State(s): State<MockState>) -> axum::response::Response<axum::body::Body> {
    s.call_count.fetch_add(1, Ordering::SeqCst);
    if s.fail_remaining.load(Ordering::SeqCst) > 0 {
        s.fail_remaining.fetch_sub(1, Ordering::SeqCst);
        return axum::response::Response::builder()
            .status(s.fail_status)
            .body(axum::body::Body::from("error"))
            .unwrap();
    }
    let body = r#"{"jsonrpc":"2.0","id":1,"result":"0x2a"}"#;
    axum::response::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn start_mock(state: MockState) -> (String, MockState) {
    let app = Router::new()
        .route("/", post(rpc_handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), state)
}

fn test_client(url: &str, max_attempts: u32, cb_threshold: u32, reset_ms: u64) -> EvmRpcClient {
    let retry = RetryPolicy {
        max_attempts,
        base_delay_ms: 0,
        max_delay_ms: 0,
        multiplier: 1.0,
        jitter_factor: 0.0,
    };
    let circuit = CircuitBreaker::new(cb_threshold, Duration::from_millis(reset_ms));
    EvmRpcClient::with_resilience(url, "eip155:1", retry, circuit).unwrap()
}

// ---------------------------------------------------------------------------
// 1. Read-only retries recover after N transient failures
// ---------------------------------------------------------------------------

#[tokio::test]
async fn read_only_call_retries_on_5xx_then_succeeds() {
    // Fail twice, succeed on the 3rd attempt.
    let (url, state) = start_mock(MockState::new(2, 500)).await;
    let client = test_client(&url, 3, 20, 60_000);

    let block_number = client.eth_block_number().await.expect("should recover");
    assert_eq!(block_number, ethnum::U256::from(42u32));
    assert_eq!(
        state.call_count.load(Ordering::SeqCst),
        3,
        "must take exactly 3 attempts (2 failures + 1 success)"
    );
}

#[tokio::test]
async fn read_only_call_exhausts_retries_and_returns_transport_error() {
    let (url, state) = start_mock(MockState::new(999, 503)).await;
    let client = test_client(&url, 3, 100, 60_000);

    let result = client.eth_block_number().await;
    assert!(matches!(result, Err(octo_evm_rpc::RpcError::Transport)));
    assert_eq!(state.call_count.load(Ordering::SeqCst), 3);
}

// ---------------------------------------------------------------------------
// 2. eth_sendRawTransaction is NEVER retried (double-submission risk guard)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn send_raw_transaction_is_never_retried_even_on_5xx() {
    // Mock always fails — max_attempts = 5, but Submit must attempt exactly once.
    let (url, state) = start_mock(MockState::new(999, 503)).await;
    let client = test_client(&url, 5, 100, 60_000);

    let result = client.eth_send_raw_transaction("0xdeadbeef").await;
    assert!(
        result.is_err(),
        "must fail when the mock always returns 503"
    );
    assert_eq!(
        state.call_count.load(Ordering::SeqCst),
        1,
        "eth_sendRawTransaction must be attempted exactly once — retrying risks double-submission"
    );
}

// ---------------------------------------------------------------------------
// 3. Circuit opens after threshold, short-circuits without a network call
// ---------------------------------------------------------------------------

#[tokio::test]
async fn circuit_opens_after_threshold_and_short_circuits() {
    let (url, state) = start_mock(MockState::new(999, 500)).await;
    let client = test_client(&url, 1, 3, 60_000);

    for _ in 0..3 {
        let _ = client.eth_block_number().await;
    }
    assert_eq!(state.call_count.load(Ordering::SeqCst), 3);

    let result = client.eth_block_number().await;
    assert!(matches!(result, Err(octo_evm_rpc::RpcError::CircuitOpen)));
    assert_eq!(
        state.call_count.load(Ordering::SeqCst),
        3,
        "no additional network call must be made when the circuit is open"
    );
}

// ---------------------------------------------------------------------------
// 4. Circuit closes after cool-down and successful probe
// ---------------------------------------------------------------------------

#[tokio::test]
async fn circuit_closes_after_cooldown_and_successful_probe() {
    let (url, _state) = start_mock(MockState::new(3, 500)).await;
    let client = test_client(&url, 1, 3, 50);

    for _ in 0..3 {
        let _ = client.eth_block_number().await;
    }
    assert!(matches!(
        client.eth_block_number().await,
        Err(octo_evm_rpc::RpcError::CircuitOpen)
    ));

    tokio::time::sleep(Duration::from_millis(100)).await;

    let result = client.eth_block_number().await;
    assert!(
        result.is_ok(),
        "circuit should close after cool-down + successful probe"
    );
}
