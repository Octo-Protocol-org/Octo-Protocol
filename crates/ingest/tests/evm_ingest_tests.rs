//! EVM deposit detection integration tests.
//!
//! Tests the `EvmIngestor` against a real Postgres database (skips cleanly when `DATABASE_URL`
//! is absent). Covers:
//!
//! 1. **Happy path**: a Transfer to a registered deposit address is recorded as `unconfirmed`.
//! 2. **Adversarial / fake Transfer**: a hostile contract emits a Transfer with a deposit address
//!    in `topics[2]` and a huge value — must be rejected because `log.address` is not registered.
//! 3. **Idempotency / replay**: processing the same log twice records nothing new.
//! 4. **Crash-resume**: cursor advances block-by-block so a restart re-processes only unfinished
//!    work.
//! 5. **Unregistered token quarantine**: a Transfer from an unregistered token to a known address
//!    is skipped (not credited).
//! 6. **Range bisection**: a mock RPC returning `RangeTooLarge` causes bisection, not a stall.
//! 7. **Removed log (reorg)**: a log with `removed: true` is never processed.
//! 8. **Amount at 6 and 18 decimals**: both USDC and DAI-like values are stored correctly.

use axum::Router;
use axum::routing::post;
use octo_ingest::evm::{EvmIngestor, EvmLog, RegisteredToken};
use octo_ingest::Processed;
use octo_store::{NewWallet, Store};
use serde_json::json;
use std::sync::{Arc, Mutex, Once};
use uuid::Uuid;

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// USDC contract address (Ethereum mainnet — used as a stand-in for tests).
const USDC_CONTRACT: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
/// DAI contract address (Ethereum mainnet).
const DAI_CONTRACT: &str = "0x6B175474E89094C44Da98b954EedeAC495271d0F";
/// A deposit address belonging to our test wallet.
const DEPOSIT_ADDR: &str = "0xdeadbeef00000000000000000000000000000001";
/// An unrelated external address (the sender in most tests).
const SENDER_ADDR: &str = "0xcafe000000000000000000000000000000000001";
/// A hostile contract that is NOT registered.
const HOSTILE_CONTRACT: &str = "0xbad0000000000000000000000000000000000001";

const TRANSFER_TOPIC: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

const CHAIN_ID: &str = "eip155:1";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Pad a 20-byte hex address to a 32-byte ABI-encoded topic.
fn as_topic(addr: &str) -> String {
    let hex = addr.strip_prefix("0x").unwrap_or(addr);
    format!("0x{:0>64}", hex.to_lowercase())
}

/// Encode a u64 as a 32-byte ABI uint256 data field.
fn as_data(value: u64) -> String {
    format!("0x{value:0>64x}")
}

/// Build a minimal Transfer `EvmLog`.
fn transfer_log(
    contract: &str,
    from: &str,
    to: &str,
    amount: u64,
    block: u64,
    log_index: u32,
    tx_hash: &str,
) -> EvmLog {
    EvmLog {
        address: contract.to_string(),
        transaction_hash: tx_hash.to_string(),
        topics: vec![
            TRANSFER_TOPIC.to_string(),
            as_topic(from),
            as_topic(to),
        ],
        data: as_data(amount),
        block_number: format!("0x{block:x}"),
        log_index: format!("0x{log_index:x}"),
        removed: false,
    }
}

/// Create an isolated wallet and `EvmIngestor` for one test.
async fn setup(
    store: &Store,
    rpc_url: &str,
) -> (Uuid, EvmIngestor) {
    let run_id = Uuid::new_v4().simple().to_string();
    let wallet = store
        .create_wallet(NewWallet {
            network: "testnet",
            stellar_account_g: &format!("G_EVM_TEST_{run_id}"),
            sealed_ciphertext: b"ct",
            sealed_nonce: b"nonce",
            sealed_salt: b"salt",
            sealed_scheme: 1,
            label: None,
            user_id: None,
            description: None,
        })
        .await
        .expect("create wallet");

    // Register the deposit address in the store as a muxed address row.
    // We repurpose muxed_address as deposit_address for the EVM path until the schema migration.
    let addr = store
        .allocate_address(
            wallet.id,
            |_id| Ok(DEPOSIT_ADDR.to_string()),
            Some("evm-test-customer"),
            json!({}),
        )
        .await
        .expect("allocate EVM deposit address");

    let tokens = vec![
        RegisteredToken {
            contract_address: USDC_CONTRACT.to_string(),
            symbol: "USDC".to_string(),
            decimals: 6,
        },
        RegisteredToken {
            contract_address: DAI_CONTRACT.to_string(),
            symbol: "DAI".to_string(),
            decimals: 18,
        },
    ];

    let ingestor = EvmIngestor::new(
        store.clone(),
        rpc_url,
        wallet.id,
        CHAIN_ID,
        vec![DEPOSIT_ADDR.to_lowercase()],
        tokens,
    );

    let _ = addr; // ensure the address row exists
    (wallet.id, ingestor)
}

// ---------------------------------------------------------------------------
// Mock JSON-RPC server helpers
// ---------------------------------------------------------------------------

/// Shared state for the mock RPC server.
#[derive(Clone)]
struct MockRpcState {
    /// Canned response to return for eth_blockNumber.
    block_number: Arc<Mutex<u64>>,
    /// Canned logs to return for eth_getLogs.
    logs: Arc<Mutex<Vec<serde_json::Value>>>,
    /// If set, return a RangeTooLarge error for the first N calls to eth_getLogs.
    range_too_large_count: Arc<Mutex<u32>>,
    /// How many eth_getLogs calls were made.
    get_logs_call_count: Arc<Mutex<u32>>,
}

/// Axum handler for the mock RPC endpoint.
async fn mock_rpc_handler(
    axum::extract::State(state): axum::extract::State<MockRpcState>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let method = body.get("method").and_then(|m| m.as_str()).unwrap_or("");
    match method {
        "eth_blockNumber" => {
            let n = *state.block_number.lock().unwrap();
            axum::Json(json!({ "jsonrpc": "2.0", "id": 1, "result": format!("0x{n:x}") }))
        }
        "eth_getLogs" => {
            let mut count = state.get_logs_call_count.lock().unwrap();
            *count += 1;
            let mut remaining = state.range_too_large_count.lock().unwrap();
            if *remaining > 0 {
                *remaining -= 1;
                drop(remaining);
                drop(count);
                return axum::Json(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": { "code": -32005, "message": "query returned more than 10000 results. Try with this block range [0x0, 0x4e20]." }
                }));
            }
            let logs = state.logs.lock().unwrap().clone();
            axum::Json(json!({ "jsonrpc": "2.0", "id": 1, "result": logs }))
        }
        other => axum::Json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": -32601, "message": format!("method not found: {other}") }
        })),
    }
}

async fn start_mock_rpc(state: MockRpcState) -> String {
    let app = Router::new()
        .route("/", post(mock_rpc_handler))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock RPC");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock RPC serve");
    });
    format!("http://{addr}/")
}

fn rpc_log(log: &EvmLog) -> serde_json::Value {
    json!({
        "address": log.address,
        "transactionHash": log.transaction_hash,
        "topics": log.topics,
        "data": log.data,
        "blockNumber": log.block_number,
        "logIndex": log.log_index,
        "removed": log.removed,
    })
}

// ---------------------------------------------------------------------------
// Test 1: Happy path — Transfer to registered deposit address is recorded
// ---------------------------------------------------------------------------

#[tokio::test]
async fn erc20_transfer_to_deposit_address_is_recorded() {
    let Some(db_url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL to run EVM ingest tests");
        return;
    };
    let store = Store::connect(&db_url).await.expect("connect");
    store.migrate().await.expect("migrate");

    let log = transfer_log(
        USDC_CONTRACT,
        SENDER_ADDR,
        DEPOSIT_ADDR,
        1_000_000, // 1 USDC (6 decimals)
        100,
        0,
        "0xaaa0000000000000000000000000000000000000000000000000000000000001",
    );

    let mock_state = MockRpcState {
        block_number: Arc::new(Mutex::new(100)),
        logs: Arc::new(Mutex::new(vec![rpc_log(&log)])),
        range_too_large_count: Arc::new(Mutex::new(0)),
        get_logs_call_count: Arc::new(Mutex::new(0)),
    };
    let rpc_url = start_mock_rpc(mock_state).await;

    let (wallet_id, ingestor) = setup(&store, &rpc_url).await;

    let result = ingestor.process_log(&log).await.expect("process_log");
    assert_eq!(
        result,
        Processed::Recorded { attributed: true },
        "Transfer to a registered deposit address must be recorded and attributed"
    );

    let txs = store
        .list_transactions(wallet_id, 10, None)
        .await
        .expect("list_transactions");
    assert_eq!(txs.len(), 1, "one transaction row expected");
    let tx = &txs[0];
    assert_eq!(tx.amount_stroops, 1_000_000);
    assert_eq!(tx.asset_code, "USDC");
    assert_eq!(tx.status, "unconfirmed", "EVM deposits must be unconfirmed until #222");
    assert_eq!(tx.asset_issuer.as_deref(), Some(USDC_CONTRACT));
}

// ---------------------------------------------------------------------------
// Test 2: Amount at 18 decimals (DAI-like)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dai_transfer_18_decimals_stored_correctly() {
    let Some(db_url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL to run EVM ingest tests");
        return;
    };
    let store = Store::connect(&db_url).await.expect("connect");
    store.migrate().await.expect("migrate");

    // 1.0 DAI = 1_000_000_000_000_000_000 attoDAI
    let amount: u64 = 1_000_000_000_000_000_000;
    let log = transfer_log(
        DAI_CONTRACT,
        SENDER_ADDR,
        DEPOSIT_ADDR,
        amount,
        200,
        1,
        "0xbbb0000000000000000000000000000000000000000000000000000000000001",
    );

    let mock_state = MockRpcState {
        block_number: Arc::new(Mutex::new(200)),
        logs: Arc::new(Mutex::new(vec![rpc_log(&log)])),
        range_too_large_count: Arc::new(Mutex::new(0)),
        get_logs_call_count: Arc::new(Mutex::new(0)),
    };
    let rpc_url = start_mock_rpc(mock_state).await;

    let (wallet_id, ingestor) = setup(&store, &rpc_url).await;

    let result = ingestor.process_log(&log).await.expect("process_log (DAI)");
    assert_eq!(
        result,
        Processed::Recorded { attributed: true },
        "DAI Transfer must be recorded"
    );

    let txs = store
        .list_transactions(wallet_id, 10, None)
        .await
        .expect("list_transactions");
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0].amount_stroops, amount as i64);
    assert_eq!(txs[0].asset_code, "DAI");
    assert_eq!(txs[0].status, "unconfirmed");
}

// ---------------------------------------------------------------------------
// Test 3: Adversarial — fake Transfer from hostile contract must be rejected
//
// This is the critical security test. A hostile contract emits a Transfer event
// with our deposit address in topics[2] and a large value in data. Because
// log.address is not a registered token, it must be Skipped.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fake_transfer_from_unregistered_contract_is_skipped() {
    let Some(db_url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL to run EVM ingest tests");
        return;
    };
    let store = Store::connect(&db_url).await.expect("connect");
    store.migrate().await.expect("migrate");

    // Hostile contract emits Transfer with deposit address as `to` and 1 billion USDC as value.
    let hostile_log = transfer_log(
        HOSTILE_CONTRACT,  // ← NOT a registered contract
        SENDER_ADDR,
        DEPOSIT_ADDR,
        1_000_000_000_000_000, // 1 billion USDC (6 decimals) — attacker's desired credit
        300,
        0,
        "0xccc0000000000000000000000000000000000000000000000000000000000001",
    );

    let mock_state = MockRpcState {
        block_number: Arc::new(Mutex::new(300)),
        logs: Arc::new(Mutex::new(vec![rpc_log(&hostile_log)])),
        range_too_large_count: Arc::new(Mutex::new(0)),
        get_logs_call_count: Arc::new(Mutex::new(0)),
    };
    let rpc_url = start_mock_rpc(mock_state).await;

    let (wallet_id, ingestor) = setup(&store, &rpc_url).await;

    // The process_log call must skip the hostile log.
    let result = ingestor
        .process_log(&hostile_log)
        .await
        .expect("process_log should not error for a skipped log");

    assert_eq!(
        result,
        Processed::Skipped,
        "A Transfer emitted by an unregistered contract must be Skipped — topics alone must never cause attribution"
    );

    // No transactions must have been recorded.
    let txs = store
        .list_transactions(wallet_id, 10, None)
        .await
        .expect("list_transactions");
    assert_eq!(
        txs.len(),
        0,
        "hostile fake Transfer must not create any transaction row"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Idempotency / replay — processing the same log twice records nothing new
// ---------------------------------------------------------------------------

#[tokio::test]
async fn replay_same_log_is_idempotent() {
    let Some(db_url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL to run EVM ingest tests");
        return;
    };
    let store = Store::connect(&db_url).await.expect("connect");
    store.migrate().await.expect("migrate");

    let log = transfer_log(
        USDC_CONTRACT,
        SENDER_ADDR,
        DEPOSIT_ADDR,
        500_000, // 0.5 USDC
        400,
        0,
        "0xddd0000000000000000000000000000000000000000000000000000000000001",
    );

    let mock_state = MockRpcState {
        block_number: Arc::new(Mutex::new(400)),
        logs: Arc::new(Mutex::new(vec![rpc_log(&log)])),
        range_too_large_count: Arc::new(Mutex::new(0)),
        get_logs_call_count: Arc::new(Mutex::new(0)),
    };
    let rpc_url = start_mock_rpc(mock_state).await;

    let (wallet_id, ingestor) = setup(&store, &rpc_url).await;

    // First delivery: must be recorded.
    let r1 = ingestor.process_log(&log).await.expect("first process");
    assert_eq!(r1, Processed::Recorded { attributed: true });

    // Second delivery (replay): must be a no-op duplicate.
    let r2 = ingestor.process_log(&log).await.expect("second process");
    assert_eq!(r2, Processed::Duplicate, "replay must be a Duplicate");

    // Third delivery (another replay): still no-op.
    let r3 = ingestor.process_log(&log).await.expect("third process");
    assert_eq!(r3, Processed::Duplicate, "second replay must also be Duplicate");

    let txs = store
        .list_transactions(wallet_id, 10, None)
        .await
        .expect("list_transactions");
    assert_eq!(txs.len(), 1, "only one transaction row despite three deliveries");
    assert_eq!(txs[0].amount_stroops, 500_000);
}

// ---------------------------------------------------------------------------
// Test 5: Crash-resume — cursor advances block-by-block
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cursor_advances_per_block_and_resume_is_exactly_once() {
    let Some(db_url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL to run EVM ingest tests");
        return;
    };
    let store = Store::connect(&db_url).await.expect("connect");
    store.migrate().await.expect("migrate");

    // Build two logs at different block numbers to simulate a two-block range.
    let log_b500 = transfer_log(
        USDC_CONTRACT, SENDER_ADDR, DEPOSIT_ADDR, 100_000, 500, 0,
        "0xeee0000000000000000000000000000000000000000000000000000000000001",
    );
    let log_b501 = transfer_log(
        USDC_CONTRACT, SENDER_ADDR, DEPOSIT_ADDR, 200_000, 501, 0,
        "0xeee0000000000000000000000000000000000000000000000000000000000002",
    );

    let mock_state = MockRpcState {
        block_number: Arc::new(Mutex::new(501)),
        logs: Arc::new(Mutex::new(vec![rpc_log(&log_b500), rpc_log(&log_b501)])),
        range_too_large_count: Arc::new(Mutex::new(0)),
        get_logs_call_count: Arc::new(Mutex::new(0)),
    };
    let rpc_url = start_mock_rpc(mock_state).await;

    let (wallet_id, ingestor) = setup(&store, &rpc_url).await;

    // Process both logs individually (simulating poll_once's inner loop).
    let r1 = ingestor.process_log(&log_b500).await.expect("block 500");
    assert_eq!(r1, Processed::Recorded { attributed: true });
    store
        .set_evm_cursor(wallet_id, CHAIN_ID, 500)
        .await
        .expect("set cursor after block 500");

    let r2 = ingestor.process_log(&log_b501).await.expect("block 501");
    assert_eq!(r2, Processed::Recorded { attributed: true });
    store
        .set_evm_cursor(wallet_id, CHAIN_ID, 501)
        .await
        .expect("set cursor after block 501");

    // Cursor should now be at 501.
    let cursor = store
        .get_evm_cursor(wallet_id, CHAIN_ID)
        .await
        .expect("get cursor");
    assert_eq!(cursor, Some(501), "cursor should be at block 501");

    // Simulate a crash-resume: replay both logs. Both must deduplicate.
    let r3 = ingestor.process_log(&log_b500).await.expect("replay b500");
    assert_eq!(r3, Processed::Duplicate, "replay of block 500 log must be Duplicate");

    let r4 = ingestor.process_log(&log_b501).await.expect("replay b501");
    assert_eq!(r4, Processed::Duplicate, "replay of block 501 log must be Duplicate");

    let txs = store
        .list_transactions(wallet_id, 10, None)
        .await
        .expect("list_transactions");
    assert_eq!(txs.len(), 2, "exactly two deposits recorded after crash-resume");
}

// ---------------------------------------------------------------------------
// Test 6: Unregistered token quarantine — Skipped (not credited)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn transfer_of_unregistered_token_to_known_address_is_skipped() {
    let Some(db_url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL to run EVM ingest tests");
        return;
    };
    let store = Store::connect(&db_url).await.expect("connect");
    store.migrate().await.expect("migrate");

    // Some random token that is NOT in our registry.
    let random_token = "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984"; // UNI, not registered

    let log = transfer_log(
        random_token,   // not registered
        SENDER_ADDR,
        DEPOSIT_ADDR,   // but to a known deposit address
        9_999_999,
        600,
        0,
        "0xfff0000000000000000000000000000000000000000000000000000000000001",
    );

    let mock_state = MockRpcState {
        block_number: Arc::new(Mutex::new(600)),
        logs: Arc::new(Mutex::new(vec![rpc_log(&log)])),
        range_too_large_count: Arc::new(Mutex::new(0)),
        get_logs_call_count: Arc::new(Mutex::new(0)),
    };
    let rpc_url = start_mock_rpc(mock_state).await;

    let (wallet_id, ingestor) = setup(&store, &rpc_url).await;

    let result = ingestor
        .process_log(&log)
        .await
        .expect("process_log should not error");

    assert_eq!(
        result,
        Processed::Skipped,
        "A Transfer of an unregistered token must be Skipped, not credited"
    );

    let txs = store
        .list_transactions(wallet_id, 10, None)
        .await
        .expect("list_transactions");
    assert_eq!(
        txs.len(), 0,
        "no transaction row for unregistered token transfer"
    );
}

// ---------------------------------------------------------------------------
// Test 7: Range bisection — RangeTooLarge causes bisection, not a stall
// ---------------------------------------------------------------------------

#[tokio::test]
async fn range_too_large_error_causes_bisection_not_stall() {
    let Some(db_url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL to run EVM ingest tests");
        return;
    };
    let store = Store::connect(&db_url).await.expect("connect");
    store.migrate().await.expect("migrate");

    let log = transfer_log(
        USDC_CONTRACT,
        SENDER_ADDR,
        DEPOSIT_ADDR,
        250_000,
        700,
        0,
        "0x0010000000000000000000000000000000000000000000000000000000000001",
    );

    // First eth_getLogs call returns RangeTooLarge; second returns the log.
    let mock_state = MockRpcState {
        block_number: Arc::new(Mutex::new(700)),
        logs: Arc::new(Mutex::new(vec![rpc_log(&log)])),
        range_too_large_count: Arc::new(Mutex::new(1)), // first call fails
        get_logs_call_count: Arc::new(Mutex::new(0)),
    };
    let get_logs_call_count = Arc::clone(&mock_state.get_logs_call_count);
    let rpc_url = start_mock_rpc(mock_state).await;

    let (_wallet_id, mut ingestor) = setup(&store, &rpc_url).await;

    // poll_once must succeed after bisecting the range.
    let n = ingestor.poll_once().await.expect("poll_once after bisection");

    // At least one log should have been processed, and eth_getLogs was called more than once
    // (the bisection triggers a retry).
    let calls = *get_logs_call_count.lock().unwrap();
    assert!(
        calls >= 2,
        "eth_getLogs must be retried after RangeTooLarge (got {calls} calls)"
    );
    // n >= 1 because the bisected (smaller) range succeeded and returned the log.
    assert!(n >= 1, "at least one log must have been processed after bisection");
}

// ---------------------------------------------------------------------------
// Test 8: Removed log (reorg) is never processed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn removed_log_is_never_processed() {
    let Some(db_url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL to run EVM ingest tests");
        return;
    };
    let store = Store::connect(&db_url).await.expect("connect");
    store.migrate().await.expect("migrate");

    let mut log = transfer_log(
        USDC_CONTRACT,
        SENDER_ADDR,
        DEPOSIT_ADDR,
        100_000,
        800,
        0,
        "0x0020000000000000000000000000000000000000000000000000000000000001",
    );
    log.removed = true; // simulate reorg

    let mock_state = MockRpcState {
        block_number: Arc::new(Mutex::new(800)),
        logs: Arc::new(Mutex::new(vec![rpc_log(&log)])),
        range_too_large_count: Arc::new(Mutex::new(0)),
        get_logs_call_count: Arc::new(Mutex::new(0)),
    };
    let rpc_url = start_mock_rpc(mock_state).await;

    let (wallet_id, mut ingestor) = setup(&store, &rpc_url).await;

    // poll_once processes the range but the removed flag is checked there.
    let n = ingestor.poll_once().await.expect("poll_once with removed log");
    // count in process_range skips removed logs, so n should be 0.
    assert_eq!(n, 0, "removed (reorged) log must not be counted as processed");

    let txs = store
        .list_transactions(wallet_id, 10, None)
        .await
        .expect("list_transactions");
    assert_eq!(txs.len(), 0, "removed log must produce no transaction row");
}

// ---------------------------------------------------------------------------
// Test 9: Transfer to a non-deposit address is Skipped
// ---------------------------------------------------------------------------

#[tokio::test]
async fn transfer_to_non_deposit_address_is_skipped() {
    let Some(db_url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL to run EVM ingest tests");
        return;
    };
    let store = Store::connect(&db_url).await.expect("connect");
    store.migrate().await.expect("migrate");

    // Transfer to an address that belongs to a different wallet / is not in our registry.
    let other_addr = "0x9999999999999999999999999999999999999999";
    let log = transfer_log(
        USDC_CONTRACT,
        SENDER_ADDR,
        other_addr, // NOT our deposit address
        100_000,
        900,
        0,
        "0x0030000000000000000000000000000000000000000000000000000000000001",
    );

    let mock_state = MockRpcState {
        block_number: Arc::new(Mutex::new(900)),
        logs: Arc::new(Mutex::new(vec![])),
        range_too_large_count: Arc::new(Mutex::new(0)),
        get_logs_call_count: Arc::new(Mutex::new(0)),
    };
    let rpc_url = start_mock_rpc(mock_state).await;

    let (wallet_id, ingestor) = setup(&store, &rpc_url).await;

    let result = ingestor.process_log(&log).await.expect("process_log");
    assert_eq!(result, Processed::Skipped, "Transfer to unknown address must be Skipped");

    let txs = store
        .list_transactions(wallet_id, 10, None)
        .await
        .expect("list_transactions");
    assert_eq!(txs.len(), 0, "no transaction row for Transfer to non-deposit address");
}

// ---------------------------------------------------------------------------
// Test 10: EVM deposits are always recorded as 'unconfirmed' (not 'confirmed')
//          — crediting gated on #222 must not be bypassed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn evm_deposit_status_is_always_unconfirmed() {
    let Some(db_url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL to run EVM ingest tests");
        return;
    };
    let store = Store::connect(&db_url).await.expect("connect");
    store.migrate().await.expect("migrate");

    let log = transfer_log(
        USDC_CONTRACT,
        SENDER_ADDR,
        DEPOSIT_ADDR,
        100_000,
        1000,
        0,
        "0x0040000000000000000000000000000000000000000000000000000000000001",
    );

    let mock_state = MockRpcState {
        block_number: Arc::new(Mutex::new(1000)),
        logs: Arc::new(Mutex::new(vec![])),
        range_too_large_count: Arc::new(Mutex::new(0)),
        get_logs_call_count: Arc::new(Mutex::new(0)),
    };
    let rpc_url = start_mock_rpc(mock_state).await;

    let (wallet_id, ingestor) = setup(&store, &rpc_url).await;

    ingestor.process_log(&log).await.expect("process_log");

    let txs = store
        .list_transactions(wallet_id, 10, None)
        .await
        .expect("list_transactions");
    assert_eq!(txs.len(), 1);
    assert_eq!(
        txs[0].status,
        "unconfirmed",
        "EVM deposits must be 'unconfirmed' until #222 promotion — \
         this ensures merging #221 before #222 cannot create spendable balances"
    );
}
