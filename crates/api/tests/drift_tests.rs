mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use jsonschema::Validator;
use octo_api::{build_router, AppState};
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use serde_json::Value;
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
    let master_key = [42u8; 32];
    Some(AppState::new(
        store,
        master_key,
        StellarNetwork::Testnet,
        String::from("https://horizon-testnet.stellar.org"),
        None,
    ))
}

fn load_openapi_spec() -> Value {
    let yaml_str =
        std::fs::read_to_string("../../docs/openapi.yaml").expect("Failed to read openapi.yaml");
    serde_yaml::from_str(&yaml_str).expect("Failed to parse YAML")
}

fn validate_response(spec: &Value, path: &str, method: &str, status: &str, response_body: &Value) {
    let schema = spec
        .pointer(&format!(
            "/paths/{}/{}/responses/{}/content/application~1json/schema",
            path, method, status
        ))
        .expect("Schema not found in OpenAPI spec");

    // The response schema is usually a `$ref` into `#/components/schemas/...`. Validating the
    // bare sub-schema leaves that pointer unresolvable, so splice it into a document that still
    // carries `components` and let the validator resolve the reference.
    let mut doc = schema.clone();
    if let (Some(obj), Some(components)) = (doc.as_object_mut(), spec.get("components")) {
        obj.insert("components".to_string(), components.clone());
    }
    let schema = &doc;

    let validator = Validator::new(schema).expect("Invalid JSON schema");
    let result = validator.validate(response_body);
    if let Err(errors) = result {
        println!("Validation error: {}", errors);
        panic!(
            "Response did not match OpenAPI schema for {} {} {}",
            method, path, status
        );
    }
}

/// Sign up a fresh user and return its bearer token. Every /v1/wallets route is authenticated,
/// so the drift test needs a real token or it only ever exercises the 401 path.
async fn auth_token(app: &axum::Router) -> String {
    let email = format!("drift-{}@octo.test", uuid::Uuid::new_v4().simple());
    let body = serde_json::json!({ "email": email, "password": "correct horse battery" });
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
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    json["data"]["token"]
        .as_str()
        .expect("signup must return a token")
        .to_string()
}

#[tokio::test]
async fn live_wallet_creation_response_matches_the_openapi_schema() {
    let state = match test_state().await {
        Some(s) => s,
        None => return,
    };
    let app = build_router(state);
    let spec = load_openapi_spec();
    let token = auth_token(&app).await;

    // 1. Success case: Create wallet.
    //
    // Non-custodial contract: the client generates the keypair and sends only the public key.
    // `public_key` is required — a body with just label/description is now a 400.
    let kp = stellar_base::crypto::DalekKeyPair::random().unwrap();
    let account = kp.public_key().account_id();
    let (challenge, signature) = common::signed_challenge(&app, &token, &kp).await;
    let req_body = serde_json::json!({
        "public_key": account,
        "challenge": challenge,
        "signature": signature,
        "label": "drift-test-wallet",
        "description": "testing schema drift"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/v1/wallets")
        .header("Content-Type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(req_body.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();

    // Validate the documented 201 response shape.
    validate_response(&spec, "~1v1~1wallets", "post", "201", &body_json);

    // 2. Error case: the withdraw endpoint must return a real error envelope matching the
    // documented ErrorResponse shape. This body carries no idempotency key, so it is rejected
    // with 400 before any Horizon call or signing attempt.
    let wallet_id = body_json["data"]["id"].as_str().unwrap();

    let withdraw_body = serde_json::json!({
        "destination": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        "amount_stroops": 100,
    });

    let withdraw_req = Request::builder()
        .method("POST")
        .uri(format!("/v1/wallets/{}/withdraw", wallet_id))
        .header("Content-Type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(withdraw_body.to_string()))
        .unwrap();

    let withdraw_res = app.clone().oneshot(withdraw_req).await.unwrap();
    assert_eq!(withdraw_res.status(), StatusCode::BAD_REQUEST);

    let w_bytes = axum::body::to_bytes(withdraw_res.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let w_json: Value = serde_json::from_slice(&w_bytes).unwrap();

    let error_schema = spec
        .pointer("/components/schemas/ErrorResponse")
        .expect("ErrorResponse schema not found");
    let error_validator = Validator::new(error_schema).expect("Invalid JSON schema");
    let result = error_validator.validate(&w_json);
    if let Err(errors) = result {
        println!("Validation error: {}", errors);
        panic!("Error response did not match the documented ErrorResponse schema");
    }

    // 3. Success case: Get wallet details
    let get_wallet_req = Request::builder()
        .method("GET")
        .uri(format!("/v1/wallets/{}", wallet_id))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let get_wallet_res = app.clone().oneshot(get_wallet_req).await.unwrap();
    assert_eq!(get_wallet_res.status(), StatusCode::OK);

    let g_bytes = axum::body::to_bytes(get_wallet_res.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let g_json: Value = serde_json::from_slice(&g_bytes).unwrap();

    validate_response(&spec, "~1v1~1wallets~1{id}", "get", "200", &g_json);
}
