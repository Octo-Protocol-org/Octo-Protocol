//! End-to-end webhook test: a recorded deposit fires a signed `deposit.created` webhook to a
//! locally-hosted sink. Requires Postgres via `DATABASE_URL`.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use octo_ingest::horizon::PaymentRecord;
use octo_ingest::Ingestor;
use octo_store::{NewWallet, Store};
use octo_webhooks::{sign, Event, WebhookSender};
use std::sync::atomic::{AtomicU32, Ordering};
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

/// Captured webhook request.
#[derive(Clone, Default)]
struct Captured {
    body: Vec<u8>,
    signature: Option<String>,
}

type Shared = Arc<Mutex<Option<Captured>>>;

async fn sink(
    State(store): State<Shared>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> &'static str {
    let signature = headers
        .get(sign::SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    *store.lock().unwrap() = Some(Captured {
        body: body.to_vec(),
        signature,
    });
    "ok"
}

#[tokio::test]
async fn deposit_fires_signed_webhook() {
    let Some(url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    // Allow the test to deliver to a localhost sink.
    std::env::set_var("OCTO_ALLOW_LOCAL_WEBHOOKS", "1");

    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");

    // Start a local webhook sink on an ephemeral port.
    let captured: Shared = Arc::new(Mutex::new(None));
    let app = Router::new()
        .route("/hook", post(sink))
        .with_state(captured.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Create a wallet + register the sink as a webhook endpoint.
    let wallet = store
        .create_wallet(NewWallet {
            network: "testnet",
            stellar_account_g: &format!("{BASE}-{}", Uuid::new_v4().simple()),
            sealed_ciphertext: b"ct",
            sealed_nonce: b"n",
            sealed_salt: b"s",
            sealed_scheme: 1, // octo_crypto::SCHEME_V1
            label: None,
            user_id: None,
            description: None,
        })
        .await
        .unwrap();
    let secret = "test-secret-123";
    let hook_url = format!("http://{addr}/hook");
    store
        .create_webhook_endpoint(wallet.id, &hook_url, secret)
        .await
        .unwrap();

    // An ingestor with webhooks attached.
    let ingestor = Ingestor::new(store.clone(), "http://unused", wallet.id, BASE.to_string())
        .with_webhooks(WebhookSender::new(store.clone()));

    // Process a plain deposit → records it and should fire the webhook.
    let rec = PaymentRecord {
        id: format!("wh-op-{}", Uuid::new_v4().simple()),
        paging_token: "pt".into(),
        kind: "payment".into(),
        // Must be unique per run: deposits dedup on (transaction hash, op index), so a fixed
        // literal makes the second run a Duplicate — nothing is recorded and no webhook fires.
        transaction_hash: Some(format!("wh-hash-{}", Uuid::new_v4().simple())),
        transaction_successful: true,
        from: Some("Gsender".into()),
        to: Some(BASE.into()),
        to_muxed: None,
        to_muxed_id: None,
        asset_type: Some("native".into()),
        asset_code: None,
        asset_issuer: None,
        amount: Some("3.5000000".into()),
        starting_balance: None,
        transaction: None,
    };
    ingestor.process(&rec).await.unwrap();

    // Give the dispatch a moment (it awaits, but the spawned server needs to handle it).
    for _ in 0..50 {
        if captured.lock().unwrap().is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let cap = captured
        .lock()
        .unwrap()
        .clone()
        .expect("webhook was delivered");

    // The signature header must verify against the body with our secret.
    let sig = cap.signature.expect("signature header present");
    assert!(
        sign::verify(secret.as_bytes(), &cap.body, &sig),
        "webhook signature must verify"
    );

    // The body must be the deposit.created event with the right amount.
    let json: serde_json::Value = serde_json::from_slice(&cap.body).unwrap();
    assert_eq!(json["event"], "deposit.created");
    assert_eq!(json["data"]["amount_stroops"], 35_000_000);
    assert_eq!(json["data"]["attributed"], false);
}

/// A sink that always responds with a server error, forcing the sender through its full retry
/// budget before giving up.
async fn always_fails_sink(State(hits): State<Arc<AtomicU32>>) -> StatusCode {
    hits.fetch_add(1, Ordering::SeqCst);
    StatusCode::INTERNAL_SERVER_ERROR
}

/// `WebhookSender::dispatch` loops over every active endpoint for a wallet sequentially. A
/// endpoint that always fails must not starve or block delivery to a healthy sibling endpoint
/// registered on the same wallet.
#[tokio::test]
async fn dispatch_delivers_to_healthy_endpoint_despite_sibling_failure() {
    let Some(url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    // Allow the test to deliver to localhost sinks.
    std::env::set_var("OCTO_ALLOW_LOCAL_WEBHOOKS", "1");

    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");

    // A sink that always succeeds immediately.
    let healthy_captured: Shared = Arc::new(Mutex::new(None));
    let healthy_app = Router::new()
        .route("/hook", post(sink))
        .with_state(healthy_captured.clone());
    let healthy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let healthy_addr = healthy_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(healthy_listener, healthy_app).await.unwrap();
    });

    // A sink that always fails (500s every attempt).
    let failing_hits: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
    let failing_app = Router::new()
        .route("/hook", post(always_fails_sink))
        .with_state(failing_hits.clone());
    let failing_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let failing_addr = failing_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(failing_listener, failing_app).await.unwrap();
    });

    // One wallet, two sibling endpoints: one doomed, one healthy.
    let wallet = store
        .create_wallet(NewWallet {
            network: "testnet",
            stellar_account_g: &format!("{BASE}-{}", Uuid::new_v4().simple()),
            sealed_ciphertext: b"ct",
            sealed_nonce: b"n",
            sealed_salt: b"s",
            sealed_scheme: 1,
            label: None,
            user_id: None,
            description: None,
        })
        .await
        .unwrap();

    let healthy_secret = "healthy-secret-123";
    let failing_ep = store
        .create_webhook_endpoint(
            wallet.id,
            &format!("http://{failing_addr}/hook"),
            "failing-secret-456",
        )
        .await
        .unwrap();
    let healthy_ep = store
        .create_webhook_endpoint(
            wallet.id,
            &format!("http://{healthy_addr}/hook"),
            healthy_secret,
        )
        .await
        .unwrap();

    let sender = WebhookSender::new(store.clone());
    let event = Event {
        event_type: "deposit.created".into(),
        data: serde_json::json!({ "amount_stroops": 1 }),
    };

    // `active_webhook_endpoints` has no defined ordering, so this must hold regardless of which
    // endpoint dispatch happens to process first.
    let delivered = sender.dispatch(wallet.id, &event).await;
    assert_eq!(
        delivered, 1,
        "the healthy sibling must still be delivered to despite the other endpoint always failing"
    );

    // The healthy sink actually received the signed payload.
    for _ in 0..50 {
        if healthy_captured.lock().unwrap().is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let cap = healthy_captured
        .lock()
        .unwrap()
        .clone()
        .expect("healthy endpoint was delivered to");
    let sig = cap.signature.expect("signature header present");
    assert!(
        sign::verify(healthy_secret.as_bytes(), &cap.body, &sig),
        "webhook signature must verify with the healthy endpoint's own secret"
    );

    // The failing endpoint was actually attempted, i.e. it was not skipped, only that it never
    // succeeded.
    assert!(
        failing_hits.load(Ordering::SeqCst) >= 1,
        "the failing endpoint must still have been attempted despite always erroring"
    );

    // Both endpoints get their own `webhook_deliveries` row with the correct respective outcome.
    let failing_status: String =
        sqlx::query_scalar("SELECT status FROM webhook_deliveries WHERE endpoint_id = $1")
            .bind(failing_ep.id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(failing_status, "failed");

    let healthy_status: String =
        sqlx::query_scalar("SELECT status FROM webhook_deliveries WHERE endpoint_id = $1")
            .bind(healthy_ep.id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(healthy_status, "delivered");
}
