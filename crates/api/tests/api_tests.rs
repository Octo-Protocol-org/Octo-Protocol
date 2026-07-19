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

#[tokio::test]
async fn addresses_return_both_forms_and_share_base() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let token = auth_token(&app).await;

    // Create a wallet (empty body is allowed).
    let resp = app
        .clone()
        .oneshot(post_auth("/v1/wallets", &token))
        .await
        .unwrap();
    let wallet = body_json(resp).await;
    let wallet_id = wallet["data"]["id"].as_str().unwrap().to_string();
    let base = wallet["data"]["address"].as_str().unwrap().to_string();

    // Create two addresses.
    let mut muxed = vec![];
    let mut memo_ids = vec![];
    for _ in 0..2 {
        let uri = format!("/v1/wallets/{wallet_id}/addresses");
        let resp = app.clone().oneshot(post_auth(&uri, &token)).await.unwrap();
        let st = resp.status();
        let j = body_json(resp).await;
        assert_eq!(st, StatusCode::CREATED, "address create failed: {j}");
        let d = &j["data"];
        assert!(d["muxed_address"].as_str().unwrap().starts_with('M'));
        // The fallback form shares the same base G... account.
        assert_eq!(d["base_address"].as_str().unwrap(), base);
        muxed.push(d["muxed_address"].as_str().unwrap().to_string());
        memo_ids.push(d["memo_id"].as_i64().unwrap());
    }

    assert_ne!(muxed[0], muxed[1], "distinct muxed addresses");
    assert_eq!(memo_ids, vec![1, 2], "ids allocated sequentially from 1");

    // List returns both.
    let uri = format!("/v1/wallets/{wallet_id}/addresses");
    let resp = app.oneshot(get_auth(&uri, &token)).await.unwrap();
    let list = body_json(resp).await;
    assert_eq!(list["data"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn transactions_endpoint_returns_list() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let token = auth_token(&app).await;

    let resp = app
        .clone()
        .oneshot(post_auth("/v1/wallets", &token))
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // A new wallet has no transactions yet → empty array, 200.
    let uri = format!("/v1/wallets/{wallet_id}/transactions");
    let resp = app.clone().oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["data"].as_array().unwrap().len(), 0);

    // Unknown wallet (authed user) → 404.
    let uri = format!("/v1/wallets/{}/transactions", uuid::Uuid::new_v4());
    let resp = app.oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_unknown_wallet_is_404() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let token = auth_token(&app).await;
    let uri = format!("/v1/wallets/{}", uuid::Uuid::new_v4());
    let resp = app.oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unauthenticated_request_is_401() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    // No token at all → 401 (auth required on wallet endpoints).
    let uri = format!("/v1/wallets/{}", uuid::Uuid::new_v4());
    let resp = app.oneshot(get(&uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn addresses_on_unknown_wallet_is_404() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let token = auth_token(&app).await;
    let uri = format!("/v1/wallets/{}/addresses", uuid::Uuid::new_v4());
    let resp = app.oneshot(post_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// DELETE with an Authorization bearer token.
fn delete_auth(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn post_json(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn post_json_auth(uri: &str, body: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn withdraw_requires_destination_amount_and_idempotency_key() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let token = auth_token(&app).await;
    // Create a wallet to target.
    let resp = app
        .clone()
        .oneshot(post_auth("/v1/wallets", &token))
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let uri = format!("/v1/wallets/{wallet_id}/withdraw");

    // Missing everything.
    let resp = app
        .clone()
        .oneshot(post_json_auth(&uri, "{}", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Missing idempotency key (has dest + amount).
    let body = r#"{"destination":"GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6","amount_stroops":100}"#;
    let resp = app
        .oneshot(post_json_auth(&uri, body, &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn withdraw_duplicate_idempotency_key_conflicts_before_signing() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app).await;
    let resp = app
        .clone()
        .oneshot(post_auth("/v1/wallets", &token))
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let uri = format!("/v1/wallets/{wallet_id}/withdraw");

    // Pre-insert a withdrawal with a known idempotency key (simulating a prior request) so the
    // second attempt conflicts at create_withdrawal BEFORE any Horizon/signing happens.
    let key = format!("key-{}", uuid::Uuid::new_v4());
    state
        .store()
        .create_withdrawal(octo_store::NewWithdrawal {
            wallet_id: wallet_id.parse().unwrap(),
            idempotency_key: &key,
            destination_account: "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6",
            asset_code: "native",
            asset_issuer: None,
            amount_stroops: 100,
            memo_id: None,
        })
        .await
        .unwrap();

    let body = format!(
        r#"{{"destination":"GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6","amount_stroops":100,"idempotency_key":"{key}"}}"#
    );
    let resp = app
        .oneshot(post_json_auth(&uri, &body, &token))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "retry with same idempotency key must 409 (no double-spend)"
    );
}

#[tokio::test]
async fn api_key_generate_and_get() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let token = auth_token(&app).await;

    // Create a wallet owned by this user.
    let resp = app
        .clone()
        .oneshot(post_auth("/v1/wallets", &token))
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Before generation: not configured.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/wallets/{wallet_id}/api-key"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["data"]["configured"], false);

    // Generate → returns the full key once, prefixed octo_sk_test_.
    let resp = app
        .clone()
        .oneshot(post_auth(
            &format!("/v1/wallets/{wallet_id}/api-key"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let j = body_json(resp).await;
    let key = j["data"]["api_key"].as_str().unwrap().to_string();
    assert!(key.starts_with("octo_sk_test_"), "key was {key}");
    assert!(key.len() > 20);

    // Get → configured, prefix only (never the full key).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/wallets/{wallet_id}/api-key"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let j = body_json(resp).await;
    assert_eq!(j["data"]["configured"], true);
    let prefix = j["data"]["prefix"].as_str().unwrap();
    assert!(key.starts_with(prefix), "prefix must match the key");
    assert!(
        prefix.len() < key.len(),
        "prefix must be shorter than the key"
    );
}

#[tokio::test]
async fn api_key_requires_ownership() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);

    // User A creates a wallet.
    let token_a = auth_token(&app).await;
    let resp = app
        .clone()
        .oneshot(post_auth("/v1/wallets", &token_a))
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // User B cannot generate a key for A's wallet → 404 (not revealed).
    let token_b = auth_token(&app).await;
    let resp = app
        .oneshot(post_auth(
            &format!("/v1/wallets/{wallet_id}/api-key"),
            &token_b,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Generate an API key for a wallet and return the full key string.
async fn api_key_for(app: &axum::Router, token: &str, wallet_id: &str) -> String {
    let resp = app
        .clone()
        .oneshot(post_auth(
            &format!("/v1/wallets/{wallet_id}/api-key"),
            token,
        ))
        .await
        .unwrap();
    body_json(resp).await["data"]["api_key"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn api_key_can_create_address_on_its_wallet() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let token = auth_token(&app).await;

    // Create a wallet + its API key.
    let resp = app
        .clone()
        .oneshot(post_auth("/v1/wallets", &token))
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let key = api_key_for(&app, &token, &wallet_id).await;
    assert!(key.starts_with("octo_sk_"));

    // Use the API KEY (not the login token) to create a deposit address.
    let resp = app
        .oneshot(post_auth(
            &format!("/v1/wallets/{wallet_id}/addresses"),
            &key,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "API key should create addresses"
    );
    let j = body_json(resp).await;
    assert!(j["data"]["muxed_address"]
        .as_str()
        .unwrap()
        .starts_with('M'));
}

#[tokio::test]
async fn api_key_cannot_touch_another_wallet() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let token = auth_token(&app).await;

    // Two wallets owned by the same user; key for wallet A.
    let a = body_json(
        app.clone()
            .oneshot(post_auth("/v1/wallets", &token))
            .await
            .unwrap(),
    )
    .await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let b = body_json(
        app.clone()
            .oneshot(post_auth("/v1/wallets", &token))
            .await
            .unwrap(),
    )
    .await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let key_a = api_key_for(&app, &token, &a).await;

    // Key A on wallet B → 404 (scope enforced, existence not revealed).
    let resp = app
        .oneshot(post_auth(&format!("/v1/wallets/{b}/addresses"), &key_a))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn api_key_cannot_withdraw() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let token = auth_token(&app).await;

    let wallet_id = body_json(
        app.clone()
            .oneshot(post_auth("/v1/wallets", &token))
            .await
            .unwrap(),
    )
    .await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let key = api_key_for(&app, &token, &wallet_id).await;

    // Withdrawals are dashboard-only: an API key is rejected with 401.
    let body = r#"{"destination":"GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6","amount_stroops":100,"idempotency_key":"k1"}"#;
    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/withdraw"),
            body,
            &key,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "API keys must not be allowed to withdraw"
    );
}

#[tokio::test]
async fn audit_logs_record_and_list() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);

    // Signup records "created an account"; capture the token.
    let email = format!("audit-{}@octo.test", uuid::Uuid::new_v4().simple());
    let resp = app
        .clone()
        .oneshot(post_json(
            "/v1/auth/signup",
            &format!(r#"{{"email":"{email}","password":"supersecret"}}"#),
        ))
        .await
        .unwrap();
    let token = body_json(resp).await["data"]["token"]
        .as_str()
        .unwrap()
        .to_string();

    // Create a wallet → records "created master wallet".
    app.clone()
        .oneshot(post_auth("/v1/wallets", &token))
        .await
        .unwrap();

    // List all audit logs for this user.
    let resp = app
        .clone()
        .oneshot(get_auth("/v1/audit-logs", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let logs = body_json(resp).await;
    let arr = logs["data"].as_array().unwrap();
    assert!(
        arr.len() >= 2,
        "expected signup + wallet events, got {}",
        arr.len()
    );
    let actions: Vec<&str> = arr.iter().map(|l| l["action"].as_str().unwrap()).collect();
    assert!(actions.iter().any(|a| a.contains("account")));
    assert!(actions.iter().any(|a| a.contains("wallet")));

    // Filter by category=wallet → only wallet events.
    let resp = app
        .oneshot(get_auth("/v1/audit-logs?category=wallet", &token))
        .await
        .unwrap();
    let filtered = body_json(resp).await;
    let arr = filtered["data"].as_array().unwrap();
    assert!(!arr.is_empty());
    assert!(arr.iter().all(|l| l["category"] == "wallet"));
}

// --- sponsored transaction tests -------------------------------------------

async fn insert_sponsored_tx(
    pool: &sqlx::PgPool,
    wallet_id: &str,
    status: &str,
    fee_stroops: i64,
) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO sponsored_transactions (id, wallet_id, inner_tx_hash, fee_bump_tx_hash, fee_stroops, status)
         VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)",
    )
    .bind(&id)
    .bind(wallet_id)
    .bind(format!("inner-tx-{id}"))
    .bind(format!("fee-tx-{id}"))
    .bind(fee_stroops)
    .bind(status)
    .execute(pool)
    .await
    .unwrap();
    id
}

#[tokio::test]
async fn list_sponsored_transactions_returns_empty_for_new_wallet() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let token = auth_token(&app).await;

    let resp = app
        .clone()
        .oneshot(post_auth("/v1/wallets", &token))
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let uri = format!("/v1/wallets/{wallet_id}/sponsored-transactions");
    let resp = app.oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["data"]["data"].as_array().unwrap().len(), 0);
    assert!(j["data"]["next_cursor"].is_null());
}

#[tokio::test]
async fn list_sponsored_transactions_pagination() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app).await;

    let resp = app
        .clone()
        .oneshot(post_auth("/v1/wallets", &token))
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Insert 10 sponsored transactions with increasing fee_stroops.
    for i in 0..10 {
        insert_sponsored_tx(state.store().pool(), &wallet_id, "confirmed", (i + 1) * 100).await;
        // Small delay to ensure distinct created_at ordering.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }

    // Fetch with limit=3, follow cursor across pages.
    let mut all_ids: Vec<String> = vec![];
    let mut cursor: Option<String> = None;

    loop {
        let uri = match cursor {
            Some(ref c) => {
                format!("/v1/wallets/{wallet_id}/sponsored-transactions?limit=3&before={c}")
            }
            None => format!("/v1/wallets/{wallet_id}/sponsored-transactions?limit=3"),
        };
        let resp = app.clone().oneshot(get_auth(&uri, &token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        let items = j["data"]["data"].as_array().unwrap();
        for item in items {
            all_ids.push(item["id"].as_str().unwrap().to_string());
        }
        let next = j["data"]["next_cursor"].as_str().map(|s| s.to_string());
        if next.is_none() {
            break;
        }
        cursor = next;
    }

    assert_eq!(
        all_ids.len(),
        10,
        "all 10 rows must be retrieved across pages"
    );
    // Verify no duplicates.
    let mut unique = all_ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 10, "all ids must be distinct");
}

#[tokio::test]
async fn list_sponsored_transactions_status_filter() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app).await;

    let resp = app
        .clone()
        .oneshot(post_auth("/v1/wallets", &token))
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Insert 2 confirmed + 2 failed.
    for _ in 0..2 {
        insert_sponsored_tx(state.store().pool(), &wallet_id, "confirmed", 100).await;
        insert_sponsored_tx(state.store().pool(), &wallet_id, "failed", 100).await;
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }

    // Filter by status=failed.
    let uri = format!("/v1/wallets/{wallet_id}/sponsored-transactions?status=failed");
    let resp = app.oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    let items = j["data"]["data"].as_array().unwrap();
    assert_eq!(items.len(), 2, "only 2 failed rows expected");
    for item in items {
        assert_eq!(item["status"], "failed");
    }
}

#[tokio::test]
async fn list_sponsored_transactions_requires_auth() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let uri = format!(
        "/v1/wallets/{}/sponsored-transactions",
        uuid::Uuid::new_v4()
    );
    let resp = app.oneshot(get(&uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// --- webhook delivery history ------------------------------------------------

/// Register a webhook endpoint for `wallet_id` and return its id.
async fn register_webhook_endpoint(app: &axum::Router, token: &str, wallet_id: &str) -> String {
    let uri = format!("/v1/wallets/{wallet_id}/webhooks");
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &uri,
            r#"{"url":"https://example.com/hook"}"#,
            token,
        ))
        .await
        .unwrap();
    let json = body_json(resp).await;
    json["data"]["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn list_webhook_deliveries_returns_history_newest_first() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app).await;

    let resp = app
        .clone()
        .oneshot(post_auth("/v1/wallets", &token))
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let endpoint_id = register_webhook_endpoint(&app, &token, &wallet_id).await;
    let endpoint_uuid: uuid::Uuid = endpoint_id.parse().unwrap();

    // Seed 3 delivery attempts directly via the store, oldest first.
    for i in 0..3 {
        state
            .store()
            .log_webhook_delivery(
                endpoint_uuid,
                "transaction.sponsored",
                &serde_json::json!({"seq": i}),
                "delivered",
                1,
                Some(200),
            )
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }

    let uri = format!("/v1/wallets/{wallet_id}/webhooks/{endpoint_id}/deliveries");
    let resp = app.oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    let rows = j["data"].as_array().unwrap();
    assert_eq!(rows.len(), 3);

    // Newest first: seq 2, then 1, then 0.
    let seqs: Vec<i64> = rows
        .iter()
        .map(|r| r["payload"]["seq"].as_i64().unwrap())
        .collect();
    assert_eq!(seqs, vec![2, 1, 0], "expected newest-first ordering");
}

#[tokio::test]
async fn get_deliveries_for_an_endpoint_not_owned_by_the_wallet_in_the_url_is_404() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let owner_token = auth_token(&app).await;
    let other_token = auth_token(&app).await;

    let resp = app
        .clone()
        .oneshot(post_auth("/v1/wallets", &owner_token))
        .await
        .unwrap();
    let owner_wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let endpoint_id = register_webhook_endpoint(&app, &owner_token, &owner_wallet_id).await;

    let resp = app
        .clone()
        .oneshot(post_auth("/v1/wallets", &other_token))
        .await
        .unwrap();
    let other_wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Querying the owner's endpoint id under a different (but validly owned) wallet must 404,
    // not leak that the endpoint exists elsewhere.
    let uri = format!("/v1/wallets/{other_wallet_id}/webhooks/{endpoint_id}/deliveries");
    let resp = app.oneshot(get_auth(&uri, &other_token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_deliveries_respects_the_limit_parameter() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state.clone());
    let token = auth_token(&app).await;

    let resp = app
        .clone()
        .oneshot(post_auth("/v1/wallets", &token))
        .await
        .unwrap();
    let wallet_id = body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let endpoint_id = register_webhook_endpoint(&app, &token, &wallet_id).await;
    let endpoint_uuid: uuid::Uuid = endpoint_id.parse().unwrap();

    for i in 0..5 {
        state
            .store()
            .log_webhook_delivery(
                endpoint_uuid,
                "transaction.sponsored",
                &serde_json::json!({"seq": i}),
                "delivered",
                1,
                Some(200),
            )
            .await
            .unwrap();
    }

    let uri = format!("/v1/wallets/{wallet_id}/webhooks/{endpoint_id}/deliveries?limit=2");
    let resp = app
        .clone()
        .oneshot(get_auth(&uri, &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["data"].as_array().unwrap().len(), 2);

    // Out-of-range limit is rejected rather than silently clamped.
    let uri = format!("/v1/wallets/{wallet_id}/webhooks/{endpoint_id}/deliveries?limit=201");
    let resp = app.oneshot(get_auth(&uri, &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
