//! Shared helpers for integration tests. Not a test binary (tests/common/mod.rs convention).
#![allow(dead_code)]

use axum::body::Body;
use axum::http::Request;
use stellar_base::crypto::DalekKeyPair;
use tower::ServiceExt;

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
