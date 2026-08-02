//! Cross-wallet authorization matrix for `authorize_wallet` (crates/api/src/auth.rs).
//!
//! `authorize_wallet` has two independent authorization paths — dashboard-JWT ownership and
//! API-key-implies-wallet — each of which must reject cross-tenant access on *every* route that
//! calls it. `api_tests.rs::api_key_cannot_touch_another_wallet` spot-checks a couple of routes;
//! this file exhaustively covers the full route set.
//!
//! The route list below was built by grepping `crates/api/src/auth.rs` call sites of
//! `authorize_wallet` (see `crates/api/src/routes/{webhooks,sponsorship,sponsor,addresses}.rs`
//! and `crates/api/src/routes/wallets.rs`), then cross-referencing against the router wiring in
//! `crates/api/src/lib.rs::build_router` to get the exact `(method, path)` pairs. Note that
//! `GET /v1/wallets/:id/sponsored-transactions` is deliberately excluded: it is guarded by
//! `require_login` + a manual ownership check, not by `authorize_wallet` (it does not accept API
//! keys at all), so it is out of scope for this matrix.
//!
//! Every `authorize_wallet`-guarded handler calls it *before* parsing the request body, so an
//! empty body is sufficient to exercise the authorization check on POST/PUT routes too.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use octo_api::{build_router, AppState};
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

/// Build a request with an arbitrary method and an `Authorization: Bearer <token>` header, no
/// body. Every `authorize_wallet`-guarded route runs the authz check before reading the body, so
/// this is sufficient to exercise all of them (GET/POST/PUT alike).
fn req_auth(method: &str, uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// POST with no body but an Authorization bearer token (mirrors `api_tests.rs::post_auth`).
fn post_auth(uri: &str, token: &str) -> Request<Body> {
    req_auth("POST", uri, token)
}

/// Sign up a fresh user via the router and return its bearer token.
async fn auth_token(app: &axum::Router) -> String {
    let email = format!("u-{}@octo.test", uuid::Uuid::new_v4().simple());
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

/// Create a wallet for `token`'s user and return its id. Non-custodial: the caller generates the
/// keypair and sends only the public account (mirrors `api_tests.rs::create_wallet_req`).
async fn create_wallet(app: &axum::Router, token: &str) -> String {
    let account = stellar_base::crypto::DalekKeyPair::random()
        .unwrap()
        .public_key()
        .account_id();
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
    assert_eq!(resp.status(), StatusCode::CREATED);
    body_json(resp).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Generate an API key for a wallet (via its owner's JWT) and return the full key string.
async fn api_key_for(app: &axum::Router, token: &str, wallet_id: &str) -> String {
    let resp = app
        .clone()
        .oneshot(post_auth(
            &format!("/v1/wallets/{wallet_id}/api-key"),
            token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    body_json(resp).await["data"]["api_key"]
        .as_str()
        .unwrap()
        .to_string()
}

/// One route guarded by `authorize_wallet`, described generically enough to build a request
/// against an arbitrary wallet id.
struct GuardedRoute {
    /// Human-readable name for assertion failure messages.
    name: &'static str,
    method: &'static str,
    /// Builds the request path for the given wallet id.
    path: fn(&str) -> String,
}

/// The exhaustive set of routes that call `authorize_wallet` (see module docs for how this list
/// was derived). Keep in sync with call sites in `crates/api/src/routes/*.rs`.
fn guarded_routes() -> Vec<GuardedRoute> {
    vec![
        GuardedRoute {
            name: "GET /v1/wallets/:id",
            method: "GET",
            path: |id| format!("/v1/wallets/{id}"),
        },
        GuardedRoute {
            name: "GET /v1/wallets/:id/balances",
            method: "GET",
            path: |id| format!("/v1/wallets/{id}/balances"),
        },
        GuardedRoute {
            name: "GET /v1/wallets/:id/transactions",
            method: "GET",
            path: |id| format!("/v1/wallets/{id}/transactions"),
        },
        GuardedRoute {
            name: "POST /v1/wallets/:id/addresses",
            method: "POST",
            path: |id| format!("/v1/wallets/{id}/addresses"),
        },
        GuardedRoute {
            name: "GET /v1/wallets/:id/addresses",
            method: "GET",
            path: |id| format!("/v1/wallets/{id}/addresses"),
        },
        GuardedRoute {
            name: "POST /v1/wallets/:id/webhooks",
            method: "POST",
            path: |id| format!("/v1/wallets/{id}/webhooks"),
        },
        GuardedRoute {
            name: "GET /v1/wallets/:id/webhooks",
            method: "GET",
            path: |id| format!("/v1/wallets/{id}/webhooks"),
        },
        GuardedRoute {
            name: "GET /v1/wallets/:id/webhooks/:endpoint_id/deliveries",
            method: "GET",
            // authorize_wallet runs before the endpoint lookup, so an arbitrary endpoint id is
            // fine here — cross-wallet rejection must happen before we'd even check it exists.
            path: |id| format!("/v1/wallets/{id}/webhooks/{}/deliveries", uuid::Uuid::new_v4()),
        },
        GuardedRoute {
            name: "GET /v1/wallets/:id/sponsorship",
            method: "GET",
            path: |id| format!("/v1/wallets/{id}/sponsorship"),
        },
        GuardedRoute {
            name: "PUT /v1/wallets/:id/sponsorship",
            method: "PUT",
            path: |id| format!("/v1/wallets/{id}/sponsorship"),
        },
        GuardedRoute {
            name: "POST /v1/wallets/:id/sponsor",
            method: "POST",
            path: |id| format!("/v1/wallets/{id}/sponsor"),
        },
    ]
}

/// A JWT-authenticated user (not an API key) must be rejected with 404 — not 401/403, which would
/// reveal the wallet exists — from every `authorize_wallet`-guarded route when targeting a wallet
/// they don't own. Checked in both directions: A's JWT against B's wallet, and B's JWT against
/// A's wallet.
#[tokio::test]
async fn jwt_owner_of_wallet_a_is_404_on_every_guarded_route_for_wallet_b() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state);

    let token_a = auth_token(&app).await;
    let wallet_a = create_wallet(&app, &token_a).await;

    let token_b = auth_token(&app).await;
    let wallet_b = create_wallet(&app, &token_b).await;

    for route in guarded_routes() {
        // A's JWT against B's wallet.
        let uri = (route.path)(&wallet_b);
        let resp = app
            .clone()
            .oneshot(req_auth(route.method, &uri, &token_a))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{}: user A's JWT against B's wallet must be 404, got {}",
            route.name,
            resp.status()
        );

        // Vice versa: B's JWT against A's wallet.
        let uri = (route.path)(&wallet_a);
        let resp = app
            .clone()
            .oneshot(req_auth(route.method, &uri, &token_b))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{}: user B's JWT against A's wallet must be 404, got {}",
            route.name,
            resp.status()
        );
    }
}

/// An API key minted for wallet A must be rejected with 404 (not 401/403) from every
/// `authorize_wallet`-guarded route when used against wallet B's id.
#[tokio::test]
async fn api_key_for_wallet_a_is_404_on_every_guarded_route_for_wallet_b() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state);

    let token_a = auth_token(&app).await;
    let wallet_a = create_wallet(&app, &token_a).await;
    let key_a = api_key_for(&app, &token_a, &wallet_a).await;

    let token_b = auth_token(&app).await;
    let wallet_b = create_wallet(&app, &token_b).await;

    for route in guarded_routes() {
        let uri = (route.path)(&wallet_b);
        let resp = app
            .clone()
            .oneshot(req_auth(route.method, &uri, &key_a))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{}: wallet A's API key against B's wallet must be 404, got {}",
            route.name,
            resp.status()
        );
    }
}
