//! Snapshot of the machine-readable error-code catalogue (#465).
//!
//! The codes are a public contract, so any change must show up as a diff to
//! `tests/snapshots/error_codes.snap`, `docs/api.md` and `docs/openapi.yaml` together.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use octo_api::{build_router, code_for_status, ApiError, AppState, ERROR_CODES};
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use serde_json::Value;
use std::collections::BTreeSet;
use tower::ServiceExt;

const SNAPSHOT: &str = include_str!("snapshots/error_codes.snap");

/// One sample per variant. The exhaustive match below fails to compile when a variant is added,
/// forcing this list (and the snapshot) to be updated with it.
fn every_variant() -> Vec<(&'static str, ApiError)> {
    fn _exhaustive(e: ApiError) {
        match e {
            ApiError::BadRequest(_)
            | ApiError::StaleSequence(_)
            | ApiError::Unauthorized
            | ApiError::Forbidden(_)
            | ApiError::NotFound
            | ApiError::Conflict
            | ApiError::ConflictWith(_)
            | ApiError::Gone(_)
            | ApiError::TooManyRequests(_)
            | ApiError::Internal
            | ApiError::GatewayTimeout(_)
            | ApiError::ServiceUnavailable(_) => {}
        }
    }
    vec![
        ("BadRequest", ApiError::BadRequest("x".into())),
        ("StaleSequence", ApiError::StaleSequence("x".into())),
        ("Unauthorized", ApiError::Unauthorized),
        ("Forbidden", ApiError::Forbidden("x".into())),
        ("NotFound", ApiError::NotFound),
        ("Conflict", ApiError::Conflict),
        ("ConflictWith", ApiError::ConflictWith("x".into())),
        ("Gone", ApiError::Gone("x".into())),
        ("TooManyRequests", ApiError::TooManyRequests("x".into())),
        ("Internal", ApiError::Internal),
        ("GatewayTimeout", ApiError::GatewayTimeout("x".into())),
        ("ServiceUnavailable", ApiError::ServiceUnavailable("x".into())),
    ]
}

fn snapshot_lines() -> Vec<String> {
    SNAPSHOT
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

#[test]
fn variant_codes_match_the_snapshot() {
    let actual: Vec<String> = every_variant()
        .into_iter()
        .map(|(name, e)| format!("{name} {} {}", e.parts().0.as_u16(), e.code()))
        .collect();
    assert_eq!(
        actual,
        snapshot_lines(),
        "error codes changed; this is a breaking API change (update the snapshot, docs/api.md \
         and docs/openapi.yaml only if intended)"
    );
}

#[test]
fn every_variant_code_is_catalogued_with_its_status() {
    for (name, e) in every_variant() {
        let status = e.parts().0.as_u16();
        assert!(
            ERROR_CODES.contains(&(e.code(), status, lookup_meaning(e.code()))),
            "{name} -> {} ({status}) missing from ERROR_CODES",
            e.code()
        );
    }
}

fn lookup_meaning(code: &str) -> &'static str {
    ERROR_CODES
        .iter()
        .find(|(c, _, _)| *c == code)
        .map(|(_, _, m)| *m)
        .unwrap_or("")
}

#[test]
fn catalogue_codes_are_unique_and_snake_case() {
    let mut seen = BTreeSet::new();
    for (code, _, meaning) in ERROR_CODES {
        assert!(seen.insert(*code), "duplicate code {code}");
        assert!(code.chars().all(|c| c.is_ascii_lowercase() || c == '_'), "{code}");
        assert!(!meaning.is_empty(), "{code} has no meaning");
    }
}

#[test]
fn status_fallback_codes_are_catalogued() {
    for status in [400, 401, 403, 404, 405, 409, 410, 413, 415, 422, 429, 500, 502, 503, 504] {
        let code = code_for_status(StatusCode::from_u16(status).unwrap());
        assert!(
            ERROR_CODES.iter().any(|(c, _, _)| *c == code),
            "{status} -> {code} missing from ERROR_CODES"
        );
    }
}

#[tokio::test]
async fn api_error_envelope_carries_the_code() {
    let resp = ApiError::ConflictWith("payment link is cancelled".into()).into_response();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["statusCode"], 409);
    assert_eq!(json["code"], "conflict");
    assert_eq!(json["message"], "payment link is cancelled");
    assert!(json["data"].is_null());
}

#[test]
fn openapi_documents_exactly_the_catalogue() {
    let yaml = std::fs::read_to_string("../../docs/openapi.yaml").expect("read openapi.yaml");
    let spec: Value = serde_yaml::from_str(&yaml).expect("parse openapi.yaml");
    let documented: BTreeSet<String> = spec
        .pointer("/components/schemas/ErrorResponse/properties/code/enum")
        .and_then(Value::as_array)
        .expect("ErrorResponse.code enum")
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    let catalogue: BTreeSet<String> = ERROR_CODES.iter().map(|(c, _, _)| c.to_string()).collect();
    assert_eq!(documented, catalogue);
}

#[test]
fn api_docs_list_every_code() {
    let docs = std::fs::read_to_string("../../docs/api.md").expect("read api.md");
    for (code, status, _) in ERROR_CODES {
        assert!(
            docs.contains(&format!("| `{code}` | {status} |")),
            "docs/api.md is missing the `{code}` row"
        );
    }
}

async fn test_state() -> Option<AppState> {
    let _ = dotenvy::dotenv();
    let url = std::env::var("DATABASE_URL").ok()?;
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    Some(AppState::new(
        store,
        [42u8; 32],
        StellarNetwork::Testnet,
        String::from("https://horizon-testnet.stellar.org"),
        None,
        octo_email::EmailSender::new_captured(),
    ))
}

/// Framework-generated errors (no handler ran, or an extractor rejected) still get a code.
#[tokio::test]
async fn framework_errors_are_wrapped_with_a_code() {
    let Some(state) = test_state().await else {
        return;
    };
    let app = build_router(state);
    let cases = [
        ("GET", "/v1/definitely-not-a-route", StatusCode::NOT_FOUND, "not_found"),
        ("DELETE", "/v1/auth/login", StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed"),
        ("GET", "/v1/pay/some-slug/payments/not-a-uuid", StatusCode::BAD_REQUEST, "bad_request"),
    ];
    for (method, uri, status, code) in cases {
        let resp = app
            .clone()
            .oneshot(Request::builder().method(method).uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), status, "{method} {uri}");
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).expect("error body is JSON");
        assert_eq!(json["statusCode"], status.as_u16(), "{method} {uri}");
        assert_eq!(json["code"], code, "{method} {uri}");
        assert!(json["message"].is_string());
        assert!(json["data"].is_null());
    }
}
