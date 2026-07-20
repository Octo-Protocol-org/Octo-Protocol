//! End-to-end webhook test: a recorded deposit fires a signed `deposit.created` webhook to a
//! locally-hosted sink. Requires Postgres via `DATABASE_URL`.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::Router;
use octo_ingest::horizon::PaymentRecord;
use octo_ingest::Ingestor;
use octo_store::{NewWallet, Store};
use octo_webhooks::{sign, WebhookSender};
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
