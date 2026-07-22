use axum::{routing::get, Json, Router};
use octo_ingest::{Ingestor, LastPollTracker};
use octo_store::{NewWallet, Store};
use std::sync::Once;
use tokio::net::TcpListener;
use uuid::Uuid;

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

const BASE: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";

async fn setup_test_server(success: bool) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/accounts/:account/payments",
        get(move || async move {
            if success {
                (
                    axum::http::StatusCode::OK,
                    Json(serde_json::json!({
                        "_embedded": {
                            "records": []
                        }
                    })),
                )
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({})),
                )
            }
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (server_url, handle)
}

#[tokio::test]
async fn poll_once_updates_the_last_poll_timestamp_on_success() {
    let Some(db_url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };

    let store = Store::connect(&db_url).await.expect("connect");
    store.migrate().await.expect("migrate");

    let wallet = store
        .create_wallet(NewWallet {
            network: "testnet",
            stellar_account_g: &format!("{BASE}-{}", Uuid::new_v4().simple()),
            sealed_ciphertext: b"ct",
            sealed_nonce: b"n",
            sealed_salt: b"s",
            sealed_scheme: 1,            label: None,
            user_id: None,
            description: None,
        })
        .await
        .unwrap();

    let (server_url, _server_handle) = setup_test_server(true).await;

    let tracker = LastPollTracker::new();
    let ingestor = Ingestor::new(store.clone(), &server_url, wallet.id, BASE.to_string())
        .with_tracker(tracker.clone());

    assert!(tracker.last_poll(wallet.id).is_none());

    ingestor.poll_once(10).await.unwrap();

    let ts = tracker.last_poll(wallet.id);
    assert!(ts.is_some());
    assert!(ts.unwrap() > 0);
}

#[tokio::test]
async fn failed_poll_does_not_update_the_last_poll_timestamp() {
    let Some(db_url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };

    let store = Store::connect(&db_url).await.expect("connect");
    store.migrate().await.expect("migrate");

    let wallet = store
        .create_wallet(NewWallet {
            network: "testnet",
            stellar_account_g: &format!("{BASE}-{}", Uuid::new_v4().simple()),
            sealed_ciphertext: b"ct",
            sealed_nonce: b"n",
            sealed_salt: b"s",
            sealed_scheme: 1,            label: None,
            user_id: None,
            description: None,
        })
        .await
        .unwrap();

    let (server_url, _server_handle) = setup_test_server(false).await;

    let tracker = LastPollTracker::new();
    let ingestor = Ingestor::new(store.clone(), &server_url, wallet.id, BASE.to_string())
        .with_tracker(tracker.clone());

    assert!(tracker.last_poll(wallet.id).is_none());

    let res = ingestor.poll_once(10).await;
    assert!(res.is_err());

    assert!(tracker.last_poll(wallet.id).is_none());
}
