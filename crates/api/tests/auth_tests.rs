//! Integration tests for dashboard auth (signup / login / me). Require Postgres via DATABASE_URL.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use octo_api::{build_router, AppState};
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use std::sync::Once;
use tower::ServiceExt;

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
    Some(
        AppState::new(
            store,
            [42u8; 32],
            StellarNetwork::Testnet,
            "https://horizon-testnet.stellar.org".into(),
            None,
        )
        .with_jwt_secret(b"test-jwt-secret-at-least-16-bytes".to_vec()),
    )
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let b = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&b).unwrap()
}

fn post_json(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn unique_email() -> String {
    format!("user-{}@octo.test", uuid::Uuid::new_v4().simple())
}

/// Sign up a fresh user and return `(token, user_id)`.
async fn signup(app: &axum::Router, email: &str) -> (String, String) {
    let resp = app
        .clone()
        .oneshot(post_json(
            "/v1/auth/signup",
            &format!(r#"{{"email":"{email}","password":"supersecret"}}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let j = body_json(resp).await;
    (
        j["data"]["token"].as_str().unwrap().to_string(),
        j["data"]["user"]["id"].as_str().unwrap().to_string(),
    )
}

fn post_refresh(token: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method("POST").uri("/v1/auth/refresh");
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    b.body(Body::empty()).unwrap()
}

/// Decode a JWT payload (no verification — test-side inspection only).
fn jwt_claims(token: &str) -> serde_json::Value {
    use base64::Engine;
    let payload = token.split('.').nth(1).unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Forge an HS256 JWT with the test secret and an arbitrary `exp` (mirrors the server's format).
fn forge_token(sub: &str, exp: i64) -> String {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"; // {"alg":"HS256","typ":"JWT"}
    let payload = b64(format!(r#"{{"sub":"{sub}","exp":{exp}}}"#).as_bytes());
    let signing_input = format!("{header}.{payload}");
    let mut mac =
        <Hmac<sha2::Sha256> as Mac>::new_from_slice(b"test-jwt-secret-at-least-16-bytes").unwrap();
    mac.update(signing_input.as_bytes());
    let sig = b64(&mac.finalize().into_bytes());
    format!("{signing_input}.{sig}")
}

#[tokio::test]
async fn refresh_issues_a_new_token_with_an_extended_expiry_for_the_same_user() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state);
    let email = unique_email();
    let (token, user_id) = signup(&app, &email).await;
    let old_claims = jwt_claims(&token);

    // Ensure the wall clock advances so the new exp is strictly later.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let resp = app
        .clone()
        .oneshot(post_refresh(Some(&token)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    let new_token = j["data"]["token"].as_str().unwrap().to_string();
    assert_eq!(j["data"]["user"]["id"], user_id.as_str());
    assert_eq!(j["data"]["user"]["email"], email);

    // Same subject, strictly later expiry.
    let new_claims = jwt_claims(&new_token);
    assert_eq!(new_claims["sub"], old_claims["sub"]);
    assert!(new_claims["exp"].as_i64().unwrap() > old_claims["exp"].as_i64().unwrap());

    // The refreshed token works against a protected route.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/me")
                .header("authorization", format!("Bearer {new_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["data"]["email"], email);
}

#[tokio::test]
async fn refresh_rejects_an_expired_token() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let (_token, user_id) = signup(&app, &unique_email()).await;

    // Correctly signed, but expired a minute ago.
    let expired = forge_token(&user_id, chrono::Utc::now().timestamp() - 60);
    let resp = app.oneshot(post_refresh(Some(&expired))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_rejects_a_missing_or_malformed_token() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);

    // No Authorization header at all.
    let resp = app.clone().oneshot(post_refresh(None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Garbage bearer token.
    let resp = app
        .clone()
        .oneshot(post_refresh(Some("not.a.jwt")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Well-formed JWT signed with the wrong secret.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/refresh")
                .header("authorization", "Basic abc123") // wrong scheme
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn signup_login_me_flow() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state);
    let email = unique_email();

    // Signup → 201 + token.
    let resp = app
        .clone()
        .oneshot(post_json(
            "/v1/auth/signup",
            &format!(r#"{{"email":"{email}","password":"supersecret"}}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let j = body_json(resp).await;
    let token = j["data"]["token"].as_str().unwrap().to_string();
    assert_eq!(j["data"]["user"]["email"], email);
    assert!(!token.is_empty());

    // /me with the token → the same user.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/auth/me")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["data"]["email"], email);

    // Login with the right password → token.
    let resp = app
        .oneshot(post_json(
            "/v1/auth/login",
            &format!(r#"{{"email":"{email}","password":"supersecret"}}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!body_json(resp).await["data"]["token"]
        .as_str()
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn duplicate_email_is_rejected() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let email = unique_email();
    let body = format!(r#"{{"email":"{email}","password":"supersecret"}}"#);

    let r1 = app
        .clone()
        .oneshot(post_json("/v1/auth/signup", &body))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::CREATED);
    let r2 = app
        .oneshot(post_json("/v1/auth/signup", &body))
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let email = unique_email();
    app.clone()
        .oneshot(post_json(
            "/v1/auth/signup",
            &format!(r#"{{"email":"{email}","password":"supersecret"}}"#),
        ))
        .await
        .unwrap();

    let resp = app
        .oneshot(post_json(
            "/v1/auth/login",
            &format!(r#"{{"email":"{email}","password":"wrongpass1"}}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn me_without_token_is_401() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/me")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn short_password_rejected() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let resp = app
        .oneshot(post_json(
            "/v1/auth/signup",
            &format!(r#"{{"email":"{}","password":"short"}}"#, unique_email()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Logout / deny-list tests
// ---------------------------------------------------------------------------

/// Helper: sign up a fresh user and return (cloneable app, token).
async fn signup_and_get_token(state: AppState) -> (axum::Router, String) {
    let app = build_router(state);
    let email = unique_email();
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
    (app, token)
}

/// `POST /v1/auth/logout` must return 401 when no bearer token is supplied.
#[tokio::test]
async fn logout_requires_authentication() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let app = build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/logout")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// After logout the same token must be rejected on all subsequent authenticated requests.
#[tokio::test]
async fn logout_invalidates_the_current_token_for_subsequent_requests() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let (app, token) = signup_and_get_token(state).await;

    // Token is valid before logout.
    let pre = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/auth/me")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        pre.status(),
        StatusCode::OK,
        "token should be valid before logout"
    );

    // Logout — expect 200.
    let logout_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/logout")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        logout_resp.status(),
        StatusCode::OK,
        "logout should succeed"
    );

    // The same token must now be rejected.
    let post = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/me")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        post.status(),
        StatusCode::UNAUTHORIZED,
        "revoked token must be rejected even though signature and expiry are still valid"
    );
}

/// A token that has been deny-listed must be rejected by `authenticate` even when its
/// HS256 signature is valid and the `exp` claim has not yet passed.
///
/// This test inserts the token hash directly via `Store::denylist_token` (bypassing the logout
/// route) to prove the check in `authenticate` works independently of the handler.
#[tokio::test]
async fn denylisted_token_is_rejected_even_though_its_signature_and_expiry_are_still_valid() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL to run integration tests");
        return;
    };
    let (app, token) = signup_and_get_token(state.clone()).await;

    // Confirm the token is valid before we manually deny-list it.
    let before = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/auth/me")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        before.status(),
        StatusCode::OK,
        "token must be valid before deny-listing"
    );

    // Decode the token to get user_id and exp, then insert into deny-list directly.
    let claims =
        octo_api::auth::verify_token(state.jwt_secret(), &token).expect("token must be decodable");
    let user_id: uuid::Uuid = claims.sub.parse().unwrap();
    let expires_at =
        chrono::DateTime::from_timestamp(claims.exp, 0).unwrap_or_else(chrono::Utc::now);
    let token_hash = octo_api::auth::hash_token(&token);
    state
        .store()
        .denylist_token(&token_hash, user_id, expires_at)
        .await
        .expect("denylist_token must succeed");

    // Now the token must be rejected — signature and expiry are still valid.
    let after = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/me")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        after.status(),
        StatusCode::UNAUTHORIZED,
        "deny-listed token must be rejected regardless of signature/expiry validity"
    );
}
