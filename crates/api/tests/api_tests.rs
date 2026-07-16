//! Integration tests for the octo API. Require Postgres via `DATABASE_URL` (loaded from .env).
//!
//! These drive the real axum router with in-process requests, exercising
//! crypto + wallet-core + store together. Skipped (with a message) if no DATABASE_URL.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use octo_api::{build_router, AppState, Envelope}; // زدنا Envelope هنا
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use std::sync::Once;
use tower::ServiceExt; // for `oneshot`

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

async fn test_state() -> Option<AppState> {
    let url = database_url()?;
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    let master_key = [42u8; 32]; // deterministic test key
    Some(AppState::new(
        store,
        master_key,
        StellarNetwork::Testnet,
        "https://horizon-testnet.stellar.org".into(),
        None,
    ))
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("json")
}

// ... (باقي الدوال الموجودة أصلاً في ملفك: post, get, get_auth, post_auth, auth_token)
// احتفظي بباقي الدوال القديمة هنا حتى لتحت (باش ما نكثروش الكود)

#[tokio::test]
async fn test_oversized_body_returns_envelope() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    
    // إرسال طلب كبير جداً (أكبر من الحد المسموح به عادة)
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/wallets")
                .header("Content-Type", "application/json")
                .body(Body::from(vec![0; 1024 * 1024 * 10])) // 10MB
                .unwrap(),
        )
        .await
        .unwrap();

    // التحقق من أننا نرجع 413
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    
    // التحقق من أن الجسم (body) يطابق الـ Envelope
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let envelope: Envelope = serde_json::from_slice(&bytes).expect("Response should be a valid Envelope");
    
    assert_eq!(envelope.status_code, 413);
    assert!(!envelope.message.is_empty());
}

// ... (كملي باقي الـ tests الموجودة عندك في الملف)
