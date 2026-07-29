//! Live Stellar testnet tests for friendbot funding + balance reads.
//!
//! These hit the real network and are **off by default**. Enable with both:
//!   `DATABASE_URL=...` (Postgres) and `OCTO_LIVE_TESTS=1`
//! e.g. `OCTO_LIVE_TESTS=1 cargo test -p octo-api --test horizon_live_tests`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use octo_api::{build_router, AppState};
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use std::sync::{Arc, Once};
use std::time::Duration;
use stellar_base::crypto::DalekKeyPair;
use stellar_base::operations::Operation;
use stellar_base::transaction::{Transaction, MIN_BASE_FEE};
use stellar_base::xdr::XDRSerialize;
use tokio::sync::Mutex;
use tower::ServiceExt;

static LOAD_ENV: Once = Once::new();

fn enabled() -> bool {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("OCTO_LIVE_TESTS").as_deref() == Ok("1") && std::env::var("DATABASE_URL").is_ok()
}

async fn live_state() -> Option<AppState> {
    if !enabled() {
        return None;
    }
    let url = std::env::var("DATABASE_URL").ok()?;
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    Some(AppState::new(
        store,
        [7u8; 32],
        StellarNetwork::Testnet,
        "https://horizon-testnet.stellar.org".into(),
        Some("https://friendbot.stellar.org".into()),
    ))
}

fn post_auth(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
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

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Sign up a fresh user and return its bearer token (wallet creation requires auth).
async fn auth_token(app: &axum::Router) -> String {
    let email = format!("live-{}@octo.test", uuid::Uuid::new_v4().simple());
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/signup")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"email":"{email}","password":"supersecret"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    body_json(resp).await["data"]["token"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn create_wallet_funds_and_has_balance() {
    let Some(state) = live_state().await else {
        eprintln!("SKIPPED: set OCTO_LIVE_TESTS=1 and DATABASE_URL to run live testnet tests");
        return;
    };
    let app = build_router(state);
    let token = auth_token(&app).await;

    // Client generates the key; server friendbot-funds the supplied account on testnet.
    let account = DalekKeyPair::random().unwrap().public_key().account_id();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/wallets")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(format!(r#"{{"public_key":"{account}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    let wallet = body_json(resp).await;
    let id = wallet["data"]["id"].as_str().unwrap().to_string();
    assert_eq!(
        wallet["data"]["funded"], true,
        "testnet wallet should be friendbot-funded"
    );

    // Balances should now include a positive native XLM balance.
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/wallets/{id}/balances"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bal = body_json(resp).await;
    let balances = bal["data"].as_array().unwrap();
    assert!(!balances.is_empty(), "funded account must have balances");
    let native = balances
        .iter()
        .find(|b| b["asset_type"] == "native")
        .expect("native balance present");
    let amount: f64 = native["balance"].as_str().unwrap().parse().unwrap();
    assert!(
        amount > 0.0,
        "native balance must be positive after funding"
    );
}

/// Create a non-custodial wallet from a caller-generated keypair, friendbot-funded on testnet.
/// Returns `(wallet_id, account_g, keypair, owner_token)` so the test can sign + relay locally.
async fn create_funded_wallet(app: &axum::Router) -> (String, String, DalekKeyPair, String) {
    let token = auth_token(app).await;
    let kp = DalekKeyPair::random().unwrap();
    let account = kp.public_key().account_id();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/wallets")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(format!(r#"{{"public_key":"{account}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    let w = body_json(resp).await;
    (
        w["data"]["id"].as_str().unwrap().to_string(),
        w["data"]["address"].as_str().unwrap().to_string(),
        kp,
        token,
    )
}

#[tokio::test]
async fn submit_signed_sends_xlm_on_chain() {
    let Some(state) = live_state().await else {
        eprintln!("SKIPPED: set OCTO_LIVE_TESTS=1 and DATABASE_URL");
        return;
    };
    let app = build_router(state);

    // Two funded wallets: A pays B. A signs the payment CLIENT-SIDE (the server never holds A's
    // key) and relays it through submit-signed.
    let (wallet_a, addr_a, kp_a, token_a) = create_funded_wallet(&app).await;
    let (_wallet_b, addr_b, _kp_b, _token_b) = create_funded_wallet(&app).await;

    // Build + sign a 1 XLM payment locally, using signing-info for the sequence number.
    let seq = sequence_with_retry("https://horizon-testnet.stellar.org", &addr_a).await;
    let dest = stellar_base::crypto::PublicKey::from_account_id(&addr_b).unwrap();
    let op = Operation::new_payment()
        .with_destination(dest)
        .with_amount(stellar_base::amount::Stroops::new(10_000_000))
        .unwrap()
        .with_asset(stellar_base::asset::Asset::new_native())
        .build()
        .unwrap();
    let mut tx = Transaction::builder(kp_a.public_key(), seq + 1, MIN_BASE_FEE)
        .add_operation(op)
        .into_transaction()
        .unwrap();
    tx.sign(kp_a.as_ref(), &stellar_base::network::Network::new_test())
        .unwrap();
    let signed_xdr = tx.into_envelope().xdr_base64().unwrap();

    let body = format!(r#"{{"transaction_xdr":"{signed_xdr}"}}"#);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/wallets/{wallet_a}/submit-signed"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token_a}"))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "submit-signed should be accepted"
    );
    let out = body_json(resp).await;
    assert_eq!(
        out["data"]["status"], "confirmed",
        "client-signed payment must confirm on-chain: {out}"
    );
    assert!(
        out["data"]["stellar_tx_hash"].as_str().is_some(),
        "a tx hash must be returned"
    );
}

/// Enable the withdrawal allowlist for `wallet_id` after seeding it with `seed_address` — the
/// `put_config` route refuses to enable with zero entries, so every enable-test needs at least
/// one address on the list first (usually a throwaway one, not the address under test).
async fn enable_allowlist(app: &axum::Router, wallet_id: &str, token: &str, seed_address: &str) {
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/whitelist"),
            &format!(r#"{{"address":"{seed_address}"}}"#),
            token,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "seeding the whitelist must succeed"
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/wallets/{wallet_id}/whitelist/config"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(r#"{"enabled":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "enabling the allowlist must succeed once it has an entry"
    );
}

/// Build + sign a native-XLM payment from `kp`/`addr` (source) to `dest_g`, using live
/// signing-info for the sequence number. Mirrors `submit_signed_sends_xlm_on_chain`'s inline
/// construction so allowlist tests can target an arbitrary destination.
async fn sign_payment_xdr(addr: &str, kp: &DalekKeyPair, dest_g: &str) -> String {
    let seq = sequence_with_retry("https://horizon-testnet.stellar.org", addr).await;
    let dest = stellar_base::crypto::PublicKey::from_account_id(dest_g).unwrap();
    let op = Operation::new_payment()
        .with_destination(dest)
        .with_amount(stellar_base::amount::Stroops::new(10_000_000))
        .unwrap()
        .with_asset(stellar_base::asset::Asset::new_native())
        .build()
        .unwrap();
    let mut tx = Transaction::builder(kp.public_key(), seq + 1, MIN_BASE_FEE)
        .add_operation(op)
        .into_transaction()
        .unwrap();
    tx.sign(kp.as_ref(), &stellar_base::network::Network::new_test())
        .unwrap();
    tx.into_envelope().xdr_base64().unwrap()
}

#[tokio::test]
async fn submit_signed_enforces_withdrawal_allowlist() {
    let Some(state) = live_state().await else {
        eprintln!("SKIPPED: set OCTO_LIVE_TESTS=1 and DATABASE_URL");
        return;
    };
    let app = build_router(state);

    // A pays B, but B is never whitelisted — a third wallet C seeds the allowlist so enabling it
    // doesn't require B to already be on the list (that would defeat the point of the test).
    let (wallet_a, addr_a, kp_a, token_a) = create_funded_wallet(&app).await;
    let (_wallet_b, addr_b, _kp_b, _token_b) = create_funded_wallet(&app).await;
    let (_wallet_c, addr_c, _kp_c, _token_c) = create_funded_wallet(&app).await;

    enable_allowlist(&app, &wallet_a, &token_a, &addr_c).await;

    let signed_xdr = sign_payment_xdr(&addr_a, &kp_a, &addr_b).await;
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_a}/submit-signed"),
            &format!(r#"{{"transaction_xdr":"{signed_xdr}"}}"#),
            &token_a,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a payment to a non-whitelisted destination must be rejected before it reaches Horizon"
    );
    let out = body_json(resp).await;
    assert_eq!(
        out["message"], "destination is not on this wallet's withdrawal allowlist",
        "rejection must name the real reason: {out}"
    );

    // Now whitelist B specifically and confirm the *same shape* of payment succeeds — proving
    // enforcement is a real gate, not an always-reject.
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_a}/whitelist"),
            &format!(r#"{{"address":"{addr_b}"}}"#),
            &token_a,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let signed_xdr = sign_payment_xdr(&addr_a, &kp_a, &addr_b).await;
    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_a}/submit-signed"),
            &format!(r#"{{"transaction_xdr":"{signed_xdr}"}}"#),
            &token_a,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "once whitelisted, the same destination must be accepted"
    );
    let out = body_json(resp).await;
    assert_eq!(
        out["data"]["status"], "confirmed",
        "the now-whitelisted payment must confirm on-chain: {out}"
    );
}

/// Fetch `account_g`'s current sequence number, retrying for a bit while friendbot funding lands.
async fn sequence_with_retry(horizon_url: &str, account_g: &str) -> i64 {
    let horizon = octo_api::horizon::Horizon::new(horizon_url);
    for _ in 0..10 {
        if let Ok(seq) = horizon.account_sequence(account_g).await {
            return seq;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    panic!("account {account_g} never became available on Horizon after funding");
}

/// A signed Payment inner transaction from a fresh, friendbot-funded keypair to `destination_g`.
async fn funded_payment_xdr(friendbot_url: &str, horizon_url: &str, destination_g: &str) -> String {
    let kp = DalekKeyPair::random().expect("random keypair");
    let source_g = kp.public_key().account_id();
    octo_api::horizon::friendbot_fund(friendbot_url, &source_g)
        .await
        .expect("fund inner-tx source account");

    let seq = sequence_with_retry(horizon_url, &source_g).await;
    let dest = stellar_base::crypto::PublicKey::from_account_id(destination_g).unwrap();
    let op = Operation::new_payment()
        .with_destination(dest)
        .with_amount(stellar_base::amount::Stroops::new(100))
        .unwrap()
        .with_asset(stellar_base::asset::Asset::new_native())
        .build()
        .unwrap();
    let mut tx = Transaction::builder(kp.public_key(), seq + 1, MIN_BASE_FEE)
        .add_operation(op)
        .into_transaction()
        .unwrap();
    tx.sign(kp.as_ref(), &stellar_base::network::Network::new_test())
        .unwrap();
    tx.into_envelope().xdr_base64().unwrap()
}

/// Enable gas sponsorship (no caps) for `wallet_id`. There is no API for this yet, so the test
/// reaches straight into the store, same as the rest of the fee-bump groundwork this builds on.
async fn enable_sponsorship(state: &AppState, wallet_id: &str) {
    sqlx::query("INSERT INTO gas_sponsorship_configs (wallet_id, enabled) VALUES ($1::uuid, true)")
        .bind(wallet_id)
        .execute(state.store().pool())
        .await
        .expect("insert gas_sponsorship_configs");
}

/// Spin up a tiny local HTTP receiver and return `(url, received_bodies)`. Local loopback targets
/// are normally rejected by `is_safe_url`; `OCTO_ALLOW_LOCAL_WEBHOOKS=1` is the documented dev/test
/// escape hatch.
async fn spawn_webhook_receiver() -> (String, Arc<Mutex<Vec<serde_json::Value>>>) {
    std::env::set_var("OCTO_ALLOW_LOCAL_WEBHOOKS", "1");
    let received = Arc::new(Mutex::new(Vec::new()));
    let received_for_route = received.clone();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |bytes: axum::body::Bytes| {
            let received = received_for_route.clone();
            async move {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    received.lock().await.push(v);
                }
                StatusCode::OK
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://127.0.0.1:{}/hook", addr.port()), received)
}

#[tokio::test]
async fn sponsored_webhook_fires_on_confirmation() {
    let Some(state) = live_state().await else {
        eprintln!("SKIPPED: set OCTO_LIVE_TESTS=1 and DATABASE_URL to run live testnet tests");
        return;
    };
    let app = build_router(state.clone());

    // One user owns both the wallet and its webhook registration throughout.
    let token = auth_token(&app).await;
    let account = DalekKeyPair::random().unwrap().public_key().account_id();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/wallets")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(format!(r#"{{"public_key":"{account}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    let wallet = body_json(resp).await;
    let wallet_id = wallet["data"]["id"].as_str().unwrap().to_string();

    // The fee-bump is paid by the wallet's gas tank (a server-held fee account); provision +
    // friendbot-fund it, and use its address as the inner-tx recipient/sponsor reference.
    let resp = app
        .clone()
        .oneshot(post_auth(
            &format!("/v1/wallets/{wallet_id}/gas-tank"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let tank = body_json(resp).await;
    let master_g = tank["data"]["gas_tank_address"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        tank["data"]["funded"], true,
        "the gas tank must be friendbot-funded to pay the fee-bump fee"
    );
    enable_sponsorship(&state, &wallet_id).await;

    let (hook_url, received) = spawn_webhook_receiver().await;
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/webhooks"),
            &format!(r#"{{"url":"{hook_url}"}}"#),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "webhook registration must succeed for the wallet's owner"
    );

    // A second, throwaway friendbot-funded account sources the inner (sponsored) payment.
    let inner_xdr = funded_payment_xdr(
        "https://friendbot.stellar.org",
        "https://horizon-testnet.stellar.org",
        &master_g,
    )
    .await;

    let body = format!(r#"{{"transaction_xdr":"{inner_xdr}","max_base_fee_stroops":1000}}"#);
    let resp = app
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/sponsor"),
            &body,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let out = body_json(resp).await;
    assert_eq!(
        out["data"]["status"], "confirmed",
        "sponsored fee-bump must confirm on-chain: {out}"
    );
    assert!(out["data"]["fee_bump_tx_hash"].as_str().is_some());

    // Give the detached webhook-firing task a moment to deliver.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let delivered = received.lock().await;
    assert_eq!(
        delivered.len(),
        1,
        "exactly one webhook delivery must have been received"
    );
    let payload = &delivered[0];
    assert_eq!(payload["event"], "transaction.sponsored");
    assert_eq!(payload["data"]["wallet_id"], wallet_id);
    assert_eq!(payload["data"]["status"], "confirmed");
    assert!(payload["data"]["fee_bump_tx_hash"].as_str().is_some());

    let row_status: String = sqlx::query_scalar(
        "SELECT status FROM webhook_deliveries
         WHERE event_type = 'transaction.sponsored'
         ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_one(state.store().pool())
    .await
    .expect("delivery row must exist");
    assert_eq!(row_status, "delivered");
}

#[tokio::test]
async fn payment_link_wrong_asset_deposit_is_recorded_but_not_confirmed() {
    let Some(state) = live_state().await else {
        eprintln!("SKIPPED: set OCTO_LIVE_TESTS=1 and DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());

    let (wallet_id, merchant_g, _kp, token) = create_funded_wallet(&app).await;
    // Friendbot's HTTP call returning success doesn't guarantee Horizon has indexed the new
    // account yet for lookups from other calls — settle before anyone tries to pay it.
    sequence_with_retry("https://horizon-testnet.stellar.org", &merchant_g).await;
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/payment-links"),
            r#"{"name":"Live test link"}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    let slug = created["data"]["slug"].as_str().unwrap().to_string();
    let link_id: uuid::Uuid = created["data"]["id"].as_str().unwrap().parse().unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/pay/{slug}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let deposit_address = body_json(resp).await["data"]["deposit_address"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/pay/{slug}/intent"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"payer_name":"Ada","payer_email":"ada@example.com","amount_usdc_stroops":25000000}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let payment_id = body_json(resp).await["data"]["payment_id"]
        .as_str()
        .unwrap()
        .to_string();

    // A payer sends native XLM (NOT USDC) to the link's deposit address. v1 payment links are
    // USDC-only, so ingest must record the deposit (it's still real money that landed on the
    // wallet) but must NOT treat it as fulfilling this USDC-denominated payment — otherwise a
    // misdirected/wrong-asset transfer would silently mark a payment "confirmed" that the
    // merchant never actually received in the asset they expected.
    let payer = DalekKeyPair::random().unwrap();
    let payer_g = payer.public_key().account_id();
    octo_api::horizon::friendbot_fund("https://friendbot.stellar.org", &payer_g)
        .await
        .expect("fund payer");
    let seq = sequence_with_retry("https://horizon-testnet.stellar.org", &payer_g).await;
    // The link's deposit address is muxed (M...), not a plain account (G...). Decode it with the
    // official `stellar-strkey` crate (the same one `octo-wallet-core` uses) rather than
    // `stellar-base`'s own muxed strkey parsing, which encodes the id/key payload in the wrong
    // byte order and silently produces a different underlying account.
    let decoded = stellar_strkey::ed25519::MuxedAccount::from_string(&deposit_address).unwrap();
    let dest = stellar_base::crypto::MuxedEd25519PublicKey::new(
        stellar_base::crypto::PublicKey::from_slice(&decoded.ed25519).unwrap(),
        decoded.id,
    );
    let op = Operation::new_payment()
        .with_destination(dest)
        .with_amount(stellar_base::amount::Stroops::new(25_000_000))
        .unwrap()
        .with_asset(stellar_base::asset::Asset::new_native())
        .build()
        .unwrap();
    let mut tx = Transaction::builder(payer.public_key(), seq + 1, MIN_BASE_FEE)
        .add_operation(op)
        .into_transaction()
        .unwrap();
    tx.sign(payer.as_ref(), &stellar_base::network::Network::new_test())
        .unwrap();
    let signed_xdr = tx.into_envelope().xdr_base64().unwrap();
    let submit = state.horizon().submit_transaction(&signed_xdr).await;
    let submitted_ok = matches!(&submit, Ok(r) if r.successful);
    assert!(
        submitted_ok,
        "payer's payment to the link's deposit address must confirm on-chain: {submit:?}"
    );

    let ingestor = octo_ingest::Ingestor::new(
        state.store().clone(),
        "https://horizon-testnet.stellar.org",
        wallet_id.parse().unwrap(),
        merchant_g,
    )
    .with_webhooks(state.webhooks().clone());

    // Poll a few times — Horizon's payments stream needs a moment to reflect the new ledger.
    let mut processed = 0;
    for _ in 0..10 {
        processed = ingestor.poll_once(50).await.expect("poll_once");
        if processed > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    assert!(processed > 0, "ingest must record the payer's deposit (even though it's the wrong asset — it's still real money on the wallet, just not what this payment link is waiting for)");

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/pay/{slug}/payments/{payment_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let status = body_json(resp).await;
    assert_eq!(
        status["data"]["status"], "pending",
        "an XLM deposit must NOT confirm a USDC-denominated payment link: {status}"
    );
    assert!(status["data"]["transaction_id"].is_null());

    let collected: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount_usdc_stroops), 0)::bigint FROM payment_link_payments \
         WHERE payment_link_id = $1 AND status = 'confirmed'",
    )
    .bind(link_id)
    .fetch_one(state.store().pool())
    .await
    .expect("collected total");
    assert_eq!(
        collected, 0,
        "collected total must stay 0 — no USDC has actually arrived, only XLM"
    );
}

#[tokio::test]
async fn payment_link_public_submit_rejects_wrong_asset() {
    let Some(state) = live_state().await else {
        eprintln!("SKIPPED: set OCTO_LIVE_TESTS=1 and DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());

    let (wallet_id, merchant_g, _kp, token) = create_funded_wallet(&app).await;
    sequence_with_retry("https://horizon-testnet.stellar.org", &merchant_g).await;
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/payment-links"),
            r#"{"name":"Submit relay test link"}"#,
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let slug = body_json(resp).await["data"]["slug"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/pay/{slug}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let deposit_address = body_json(resp).await["data"]["deposit_address"]
        .as_str()
        .unwrap()
        .to_string();

    // The payer builds and signs a payment to the RIGHT address but in native XLM, not USDC —
    // this is what a Freighter wallet without the old asset check would have produced (the exact
    // bug that let "5 XLM" get counted as a $5 USDC payment). The relay must reject it before it
    // ever reaches Horizon, not just record it and let ingest silently mis-confirm the payment.
    let payer = DalekKeyPair::random().unwrap();
    let payer_g = payer.public_key().account_id();
    octo_api::horizon::friendbot_fund("https://friendbot.stellar.org", &payer_g)
        .await
        .expect("fund payer");
    let seq = sequence_with_retry("https://horizon-testnet.stellar.org", &payer_g).await;
    let decoded = stellar_strkey::ed25519::MuxedAccount::from_string(&deposit_address).unwrap();
    let dest = stellar_base::crypto::MuxedEd25519PublicKey::new(
        stellar_base::crypto::PublicKey::from_slice(&decoded.ed25519).unwrap(),
        decoded.id,
    );
    let op = Operation::new_payment()
        .with_destination(dest)
        .with_amount(stellar_base::amount::Stroops::new(10_000_000))
        .unwrap()
        .with_asset(stellar_base::asset::Asset::new_native())
        .build()
        .unwrap();
    let mut tx = Transaction::builder(payer.public_key(), seq + 1, MIN_BASE_FEE)
        .add_operation(op)
        .into_transaction()
        .unwrap();
    tx.sign(payer.as_ref(), &stellar_base::network::Network::new_test())
        .unwrap();
    let signed_xdr = tx.into_envelope().xdr_base64().unwrap();

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/pay/{slug}/submit-signed"))
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"transaction_xdr":"{signed_xdr}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "a non-USDC payment must be rejected by the relay, even to the correct destination"
    );
}

#[tokio::test]
async fn payment_link_public_submit_rejects_wrong_destination() {
    let Some(state) = live_state().await else {
        eprintln!("SKIPPED: set OCTO_LIVE_TESTS=1 and DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());

    let (wallet_id, merchant_g, _kp, token) = create_funded_wallet(&app).await;
    sequence_with_retry("https://horizon-testnet.stellar.org", &merchant_g).await;
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/payment-links"),
            r#"{"name":"Reject test link"}"#,
            &token,
        ))
        .await
        .unwrap();
    let slug = body_json(resp).await["data"]["slug"]
        .as_str()
        .unwrap()
        .to_string();

    // A payer signs a payment to somewhere else entirely (their own account) — the relay must
    // reject it rather than forwarding an unrelated payment under this link's name.
    let payer = DalekKeyPair::random().unwrap();
    let payer_g = payer.public_key().account_id();
    octo_api::horizon::friendbot_fund("https://friendbot.stellar.org", &payer_g)
        .await
        .expect("fund payer");
    let seq = sequence_with_retry("https://horizon-testnet.stellar.org", &payer_g).await;
    let dest = stellar_base::crypto::PublicKey::from_account_id(&payer_g).unwrap();
    let op = Operation::new_payment()
        .with_destination(dest)
        .with_amount(stellar_base::amount::Stroops::new(10_000_000))
        .unwrap()
        .with_asset(stellar_base::asset::Asset::new_native())
        .build()
        .unwrap();
    let mut tx = Transaction::builder(payer.public_key(), seq + 1, MIN_BASE_FEE)
        .add_operation(op)
        .into_transaction()
        .unwrap();
    tx.sign(payer.as_ref(), &stellar_base::network::Network::new_test())
        .unwrap();
    let signed_xdr = tx.into_envelope().xdr_base64().unwrap();

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/pay/{slug}/submit-signed"))
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"transaction_xdr":"{signed_xdr}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "a payment to any destination other than this link's own address must be rejected"
    );
}

#[tokio::test]
async fn payment_link_signing_info_returns_the_requested_payer_account_sequence() {
    let Some(state) = live_state().await else {
        eprintln!("SKIPPED: set OCTO_LIVE_TESTS=1 and DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());

    let (wallet_id, merchant_g, _kp, token) = create_funded_wallet(&app).await;
    sequence_with_retry("https://horizon-testnet.stellar.org", &merchant_g).await;
    let resp = app
        .clone()
        .oneshot(post_json_auth(
            &format!("/v1/wallets/{wallet_id}/payment-links"),
            r#"{"name":"Signing info test link"}"#,
            &token,
        ))
        .await
        .unwrap();
    let slug = body_json(resp).await["data"]["slug"]
        .as_str()
        .unwrap()
        .to_string();

    // A payer account, distinct from the merchant, that we can independently check the
    // sequence of via Horizon.
    let payer = DalekKeyPair::random().unwrap();
    let payer_g = payer.public_key().account_id();
    octo_api::horizon::friendbot_fund("https://friendbot.stellar.org", &payer_g)
        .await
        .expect("fund payer");
    let expected_seq = sequence_with_retry("https://horizon-testnet.stellar.org", &payer_g).await;

    // Without `account`, the endpoint falls back to the merchant's own sequence (used by nothing
    // in the current frontend, kept only so the query param stays optional).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/pay/{slug}/signing-info?account={payer_g}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let info = body_json(resp).await;
    assert_eq!(
        info["data"]["account"], payer_g,
        "signing-info must echo back the PAYER's account, not the merchant's"
    );
    let returned_seq: i64 = info["data"]["sequence"]
        .as_str()
        .expect("sequence must be a string, not a JSON number")
        .parse()
        .unwrap();
    assert_eq!(
        returned_seq, expected_seq,
        "signing-info must return the payer's own sequence — using the merchant's here is exactly \
         the bug that produced tx_bad_seq for a Freighter-signed payment"
    );

    // Build and sign a payment using this sequence exactly like the pay page's Freighter path
    // does, and confirm Horizon actually accepts it (the real end-to-end regression check).
    let seq_str = info["data"]["sequence"].as_str().unwrap();
    let seq: i64 = seq_str.parse().unwrap();
    let dest = stellar_base::crypto::PublicKey::from_account_id(&merchant_g).unwrap();
    let op = Operation::new_payment()
        .with_destination(dest)
        .with_amount(stellar_base::amount::Stroops::new(10_000_000))
        .unwrap()
        .with_asset(stellar_base::asset::Asset::new_native())
        .build()
        .unwrap();
    let mut tx = Transaction::builder(payer.public_key(), seq + 1, MIN_BASE_FEE)
        .add_operation(op)
        .into_transaction()
        .unwrap();
    tx.sign(payer.as_ref(), &stellar_base::network::Network::new_test())
        .unwrap();
    let signed_xdr = tx.into_envelope().xdr_base64().unwrap();
    let submit = state.horizon().submit_transaction(&signed_xdr).await;
    let submitted_ok = matches!(&submit, Ok(r) if r.successful);
    assert!(
        submitted_ok,
        "a payment built from signing-info's returned sequence must be accepted by Horizon \
         (not tx_bad_seq): {submit:?}"
    );
}
