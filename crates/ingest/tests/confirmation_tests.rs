//! Integration tests for the EVM confirmation tracker and reorg detector
//! (`octo_ingest::confirmation`), run against a real Anvil node.
//!
//! Require Postgres via `DATABASE_URL` and the `anvil` binary (Foundry) on `PATH`; both tests
//! print a `SKIPPED` message and return early if either is unavailable, matching this crate's
//! other DB-backed integration tests.
//!
//! Anvil's `evm_snapshot` / `evm_revert` is used to simulate a reorg: state is snapshotted before
//! a deposit's block is mined, then reverted and re-mined onto a different fork — a real chain
//! producing a real same-height-different-hash divergence, not a mocked one.

use octo_ingest::confirmation::{ConfirmationTracker, TickOutcome};
use octo_store::{NewEvmDeposit, NewEvmWallet, Store};
use octo_webhooks::WebhookSender;
use serde_json::json;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;
use uuid::Uuid;

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

// ---------------------------------------------------------------------------
// Anvil harness
// ---------------------------------------------------------------------------

struct Anvil {
    child: tokio::process::Child,
    url: String,
}

impl Anvil {
    /// Spawn a fresh, isolated Anvil instance on a free local port and wait until it accepts
    /// JSON-RPC requests. Returns `None` (rather than panicking) if the `anvil` binary isn't
    /// installed, so tests can skip cleanly like the other DB-gated tests in this crate do.
    async fn spawn() -> Option<Self> {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .ok()?
            .local_addr()
            .ok()?
            .port();
        let child = tokio::process::Command::new("anvil")
            .args(["--port", &port.to_string(), "--silent"])
            .kill_on_drop(true)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        let url = format!("http://127.0.0.1:{port}");

        for _ in 0..200 {
            if rpc_call(&url, "eth_blockNumber", json!([])).await.is_some() {
                return Some(Self { child, url });
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        None
    }
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// Raw JSON-RPC call, for the Anvil-only debug/test methods `octo_ingest::evm_rpc::EvmRpcClient`
/// deliberately doesn't wrap (it only needs `eth_getBlockByNumber`).
async fn rpc_call(url: &str, method: &str, params: serde_json::Value) -> Option<serde_json::Value> {
    let resp = reqwest::Client::new()
        .post(url)
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
        .send()
        .await
        .ok()?;
    let body: serde_json::Value = resp.json().await.ok()?;
    body.get("result").cloned()
}

async fn mine_block(url: &str) {
    rpc_call(url, "evm_mine", json!([])).await;
}

async fn snapshot(url: &str) -> String {
    rpc_call(url, "evm_snapshot", json!([]))
        .await
        .and_then(|v| v.as_str().map(str::to_string))
        .expect("evm_snapshot")
}

async fn revert_to(url: &str, snapshot_id: &str) {
    rpc_call(url, "evm_revert", json!([snapshot_id])).await;
}

/// The current tip as `(number, hash)`, via the same `eth_getBlockByNumber("latest", false)`
/// shape the tracker itself uses.
async fn latest(url: &str) -> (i64, String) {
    let block = rpc_call(url, "eth_getBlockByNumber", json!(["latest", false]))
        .await
        .expect("latest block");
    let number = i64::from_str_radix(
        block["number"].as_str().unwrap().trim_start_matches("0x"),
        16,
    )
    .unwrap();
    let hash = block["hash"].as_str().unwrap().to_lowercase();
    (number, hash)
}

// ---------------------------------------------------------------------------
// Webhook capture sink
// ---------------------------------------------------------------------------

type Captured = Arc<Mutex<Vec<serde_json::Value>>>;

async fn sink(
    axum::extract::State(store): axum::extract::State<Captured>,
    body: axum::body::Bytes,
) -> &'static str {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) {
        store.lock().unwrap().push(v);
    }
    "ok"
}

async fn start_sink() -> (Captured, String) {
    let captured: Captured = Arc::new(Mutex::new(Vec::new()));
    let app = axum::Router::new()
        .route("/hook", axum::routing::post(sink))
        .with_state(captured.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (captured, format!("http://{addr}/hook"))
}

async fn wait_for<F: Fn() -> bool>(pred: F) -> bool {
    for _ in 0..100 {
        if pred() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

async fn evm_wallet(store: &Store, confirmation_depth: i32, reorg_rewind_bound: i32) -> Uuid {
    let identity = format!("0x{:040x}", Uuid::new_v4().as_u128());
    store
        .create_evm_wallet(NewEvmWallet {
            network: "testnet",
            chain_id: "eip155:31337",
            identity_address: &identity,
            sealed_ciphertext: b"ciphertext",
            sealed_nonce: b"nonce12bytes",
            sealed_salt: b"saltsaltsaltsalt",
            sealed_scheme: 1,
            confirmation_depth,
            reorg_rewind_bound,
            label: Some("anvil-test"),
            user_id: None,
            description: None,
        })
        .await
        .expect("create evm wallet")
        .id
}

async fn deposit_address(store: &Store, wallet_id: Uuid) -> Uuid {
    let salt = Uuid::new_v4().as_u128();
    store
        .allocate_evm_address(
            wallet_id,
            move |index| Ok(format!("0x{:040x}", salt.wrapping_add(index as u128))),
            Some("test-customer"),
            json!({}),
        )
        .await
        .expect("allocate address")
        .id
}

#[allow(clippy::too_many_arguments)]
async fn record_deposit(
    store: &Store,
    wallet_id: Uuid,
    address_id: Uuid,
    amount: i64,
    block_number: i64,
    block_hash: &str,
) -> Uuid {
    store
        .record_evm_deposit(&NewEvmDeposit {
            wallet_id,
            address_id: Some(address_id),
            asset_code: "ETH".into(),
            asset_issuer: None,
            amount_stroops: amount,
            source_account: Some("0xsender".into()),
            destination_account: Some("0xreceiver".into()),
            evm_tx_hash: format!("0xtx{}", Uuid::new_v4().simple()),
            log_index: 0,
            block_number,
            block_hash: block_hash.to_string(),
        })
        .await
        .expect("record deposit")
        .expect("not a duplicate")
        .id
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Progressive confirmation counting, and promotion to `confirmed` at exactly the wallet's
/// configured depth — and, per the issue, a deposit below that depth must not be spendable
/// (`sum_deposits_for_address` must not count it until promoted).
#[tokio::test]
async fn progressive_confirmation_and_promotion_at_exact_depth() {
    let Some(db_url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let Some(anvil) = Anvil::spawn().await else {
        eprintln!("SKIPPED: anvil (foundry) not found on PATH");
        return;
    };

    let store = Store::connect(&db_url).await.expect("connect");
    store.migrate().await.expect("migrate");

    let depth = 3;
    let wallet_id = evm_wallet(&store, depth, depth * 2).await;
    let address_id = deposit_address(&store, wallet_id).await;
    let tracker = ConfirmationTracker::new(store.clone(), &anvil.url, wallet_id);

    // First tick establishes the tracker's starting cursor (nothing to confirm yet).
    tracker.poll_once().await.expect("initial tick");

    mine_block(&anvil.url).await;
    let (dep_block, dep_hash) = latest(&anvil.url).await;
    let tx_id = record_deposit(&store, wallet_id, address_id, 5_000_000, dep_block, &dep_hash).await;

    // 0 confirmations (tip == deposit block): must not be spendable yet.
    let outcome = tracker.poll_once().await.expect("tick 0");
    assert!(matches!(outcome, TickOutcome::Synced { promoted: 0 }));
    assert_eq!(store.sum_deposits_for_address(address_id).await.unwrap(), 0);

    // Advance one block at a time; confirmations must climb 1, 2, ... and the deposit must stay
    // unspendable right up to (but not including) the configured depth.
    for expected_confirmations in 1..depth {
        mine_block(&anvil.url).await;
        let outcome = tracker.poll_once().await.expect("progressive tick");
        assert!(matches!(outcome, TickOutcome::Synced { promoted: 0 }));
        assert_eq!(
            store.sum_deposits_for_address(address_id).await.unwrap(),
            0,
            "must not be spendable below confirmation_depth (at {expected_confirmations} confirmations)"
        );
    }

    // The tick that pushes confirmations to exactly `depth` promotes it.
    mine_block(&anvil.url).await;
    let outcome = tracker.poll_once().await.expect("promotion tick");
    assert!(
        matches!(outcome, TickOutcome::Synced { promoted: 1 }),
        "expected exactly one promotion at depth, got {outcome:?}"
    );
    assert_eq!(
        store.sum_deposits_for_address(address_id).await.unwrap(),
        5_000_000,
        "must become spendable the instant it reaches confirmation_depth"
    );

    let tx = store.get_transaction(tx_id).await.unwrap().unwrap();
    assert_eq!(tx.status, "confirmed");
    assert_eq!(tx.confirmation_state.as_deref(), Some("confirmed"));
}

/// The acceptance test for issue #222: a deposit reaches `confirmed` (spendable, counted in the
/// balance), a reorg then reverts its block, and the tracker must mark it `orphaned`, drop it
/// back out of the balance, and fire `deposit.orphaned` — never silently, never by deleting the
/// row.
#[tokio::test]
async fn reorg_orphans_a_confirmed_deposit_reduces_balance_and_fires_webhook() {
    let Some(db_url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let Some(anvil) = Anvil::spawn().await else {
        eprintln!("SKIPPED: anvil (foundry) not found on PATH");
        return;
    };
    std::env::set_var("OCTO_ALLOW_LOCAL_WEBHOOKS", "1");

    let store = Store::connect(&db_url).await.expect("connect");
    store.migrate().await.expect("migrate");

    let (captured, hook_url) = start_sink().await;
    let depth = 1;
    let wallet_id = evm_wallet(&store, depth, 6).await;
    store
        .create_webhook_endpoint(wallet_id, &hook_url, "test-secret")
        .await
        .unwrap();
    let address_id = deposit_address(&store, wallet_id).await;
    let tracker = ConfirmationTracker::new(store.clone(), &anvil.url, wallet_id)
        .with_webhooks(WebhookSender::new(store.clone()));

    // Establish the pre-deposit cursor, then snapshot right before the deposit's block so a
    // revert removes exactly (and only) history from here on.
    tracker.poll_once().await.expect("initial tick");
    let snap = snapshot(&anvil.url).await;

    mine_block(&anvil.url).await;
    let (dep_block, dep_hash) = latest(&anvil.url).await;
    let tx_id = record_deposit(&store, wallet_id, address_id, 7_000_000, dep_block, &dep_hash).await;

    // Reach `confirmed` on the original fork.
    mine_block(&anvil.url).await;
    let outcome = tracker.poll_once().await.expect("promotion tick");
    assert!(matches!(outcome, TickOutcome::Synced { promoted: 1 }));
    assert_eq!(
        store.sum_deposits_for_address(address_id).await.unwrap(),
        7_000_000
    );

    // Revert to before the deposit's block, then mine a different block at the same height —
    // a real same-height, different-hash reorg.
    revert_to(&anvil.url, &snap).await;
    mine_block(&anvil.url).await;

    let outcome = tracker.poll_once().await.expect("reorg tick");
    match outcome {
        TickOutcome::Reorged { orphaned, .. } => assert_eq!(orphaned, 1),
        other => panic!("expected Reorged, got {other:?}"),
    }

    let tx = store.get_transaction(tx_id).await.unwrap().unwrap();
    assert_eq!(tx.status, "orphaned");
    assert_eq!(tx.confirmation_state.as_deref(), Some("orphaned"));
    assert!(tx.orphaned_at.is_some());
    assert_eq!(
        store.sum_deposits_for_address(address_id).await.unwrap(),
        0,
        "balance must drop once the deposit is orphaned"
    );

    let fired = wait_for(|| {
        captured
            .lock()
            .unwrap()
            .iter()
            .any(|e| e["event"] == "deposit.orphaned")
    })
    .await;
    assert!(fired, "deposit.orphaned webhook must fire");
    let events = captured.lock().unwrap().clone();
    let event = events
        .iter()
        .find(|e| e["event"] == "deposit.orphaned")
        .unwrap();
    assert_eq!(event["data"]["id"], tx_id.to_string());
    assert_eq!(event["data"]["status"], "orphaned");
}

/// A reorg deeper than `reorg_rewind_bound` must alert (loudly) instead of guessing at or
/// looping toward a common ancestor — and must leave deposit/cursor state untouched so an
/// operator can intervene rather than have the tracker silently misbehave.
#[tokio::test]
async fn deep_reorg_beyond_bound_alerts_without_orphaning() {
    let Some(db_url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let Some(anvil) = Anvil::spawn().await else {
        eprintln!("SKIPPED: anvil (foundry) not found on PATH");
        return;
    };

    let store = Store::connect(&db_url).await.expect("connect");
    store.migrate().await.expect("migrate");

    // A rewind bound of 1: the common ancestor will be much further back than that.
    let wallet_id = evm_wallet(&store, 1, 1).await;
    let address_id = deposit_address(&store, wallet_id).await;
    let tracker = ConfirmationTracker::new(store.clone(), &anvil.url, wallet_id);

    tracker.poll_once().await.expect("initial tick");
    let snap = snapshot(&anvil.url).await;

    mine_block(&anvil.url).await;
    let (dep_block, dep_hash) = latest(&anvil.url).await;
    let tx_id = record_deposit(&store, wallet_id, address_id, 1_000_000, dep_block, &dep_hash).await;

    // Advance several more blocks on the original fork before reverting, so the eventual common
    // ancestor is more than `reorg_rewind_bound` (1) blocks behind the cursor at revert time.
    for _ in 0..4 {
        mine_block(&anvil.url).await;
    }
    tracker.poll_once().await.expect("advance tick");

    revert_to(&anvil.url, &snap).await;
    mine_block(&anvil.url).await;

    let outcome = tracker.poll_once().await.expect("deep reorg tick");
    assert!(
        matches!(outcome, TickOutcome::DeepReorgAlert),
        "expected DeepReorgAlert, got {outcome:?}"
    );

    // State must be untouched: still whatever it was before the alerted tick, never orphaned by
    // a tracker that couldn't actually verify the reorg's extent.
    let tx = store.get_transaction(tx_id).await.unwrap().unwrap();
    assert_ne!(tx.status, "orphaned");
}
