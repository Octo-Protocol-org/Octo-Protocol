//! Integration tests for the public API surface.
//!
//! These tests drive the real router (including middleware such as the rate
//! limiter) via `tower::ServiceExt::oneshot`, so they exercise the same code
//! path as production requests.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use api::build_router;

/// Build a login request from a fixed client IP so the rate limiter keys on a
/// stable bucket across repeated calls.
fn login_request() -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/auth/login")
        .header("content-type", "application/json")
        .header("x-forwarded-for", "203.0.113.7")
        .body(Body::from(r#"{"email":"user@example.com","password":"wrong"}"#))
        .expect("valid request")
}

#[tokio::test]
async fn rate_limited_response_includes_retry_after_header() {
    let app = build_router();

    // Hammer the login endpoint from the same IP until the limiter trips.
    let mut limited = None;
    for _ in 0..100 {
        let response = app
            .clone()
            .oneshot(login_request())
            .await
            .expect("router responds");
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            limited = Some(response);
            break;
        }
    }

    let response = limited.expect("expected the rate limiter to return 429");

    let retry_after = response
        .headers()
        .get("retry-after")
        .expect("429 response must include a Retry-After header")
        .to_str()
        .expect("Retry-After is valid ASCII");

    let seconds: u64 = retry_after
        .parse()
        .expect("Retry-After must be an integer number of seconds");
    assert!(seconds > 0, "Retry-After must be a positive integer");
}