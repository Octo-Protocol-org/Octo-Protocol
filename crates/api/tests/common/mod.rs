//! Shared helpers for integration tests. Not a test binary (tests/common/mod.rs convention).
#![allow(dead_code)]

use axum::body::Body;
use axum::http::Request;
use octo_api::AppState;
use stellar_base::crypto::DalekKeyPair;
use tower::ServiceExt;

/// Sign up a fresh user, verify via the captured OTP (`state`'s `EmailSender` must be
/// `new_captured()`), and return the bearer token. `email` should be unique per call.
pub async fn signup_and_verify(app: &axum::Router, state: &AppState, email: &str) -> String {
    signup_and_verify_full(app, state, email).await.0
}

/// Same as `signup_and_verify` but also returns the verified user's id.
pub async fn signup_and_verify_full(
    app: &axum::Router,
    state: &AppState,
    email: &str,
) -> (String, String) {
    let body = serde_json::json!({ "email": email, "password": "supersecret123" });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/signup")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let user_id = json["data"]["user_id"]
        .as_str()
        .expect("signup must return user_id");
    let code = state
        .email()
        .last_otp_for(email)
        .expect("otp must be captured");

    let verify_body = serde_json::json!({ "user_id": user_id, "code": code });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/verify-email")
                .header("content-type", "application/json")
                .body(Body::from(verify_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let token = json["data"]["token"]
        .as_str()
        .expect("verify-email must return a token")
        .to_string();
    let user_id = json["data"]["user"]["id"]
        .as_str()
        .expect("verify-email must return the user")
        .to_string();
    (token, user_id)
}

/// Fetch an ownership challenge for the authenticated user and sign it with `kp`.
/// Returns `(challenge, signature_b64)` ready for `POST /v1/wallets`.
pub async fn signed_challenge(
    app: &axum::Router,
    token: &str,
    kp: &DalekKeyPair,
) -> (String, String) {
    use base64::Engine as _;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/wallets/challenge")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "challenge fetch failed: {}",
        resp.status()
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let challenge = v["data"]["challenge"].as_str().unwrap().to_string();

    let signature =
        base64::engine::general_purpose::STANDARD.encode(kp.sign(challenge.as_bytes()).to_vec());
    (challenge, signature)
}

/// The full JSON body for a challenge-verified wallet registration of `kp`'s public account.
pub async fn wallet_body(app: &axum::Router, token: &str, kp: &DalekKeyPair) -> String {
    let account = kp.public_key().account_id();
    let (challenge, signature) = signed_challenge(app, token, kp).await;
    format!(r#"{{"public_key":"{account}","challenge":"{challenge}","signature":"{signature}"}}"#)
}
