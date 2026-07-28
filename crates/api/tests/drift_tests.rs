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

#[tokio::test]
async fn live_wallet_creation_response_matches_the_openapi_schema() {
    let state = match test_state().await {
        Some(s) => s,
        None => return,
    };
    let app = build_router(state);
    let spec = load_openapi_spec();

    // 1. Success case: Create wallet
    let req_body = serde_json::json!({
        "label": "drift-test-wallet",
        "description": "testing schema drift"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/v1/wallets")
        .header("Content-Type", "application/json")
        .body(Body::from(req_body.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();

    // Validate 200 response shape
    validate_response(&spec, "~1v1~1wallets", "post", "200", &body_json);

    // 2. Error case: Missing required fields or bad payload to an endpoint, e.g. withdrawing without funds
    let wallet_id = body_json["data"]["id"].as_str().unwrap();

    // Withdraw with missing required 'asset' code/issuer
    let withdraw_body = serde_json::json!({
        "destination": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        "amount_stroops": 100,
        "asset": {
            "code": "USDC" // missing issuer
        }
    });

    let withdraw_req = Request::builder()
        .method("POST")
        .uri(format!("/v1/wallets/{}/withdraw", wallet_id))
        .header("Content-Type", "application/json")
        .body(Body::from(withdraw_body.to_string()))
        .unwrap();

    let withdraw_res = app.clone().oneshot(withdraw_req).await.unwrap();
    assert_eq!(withdraw_res.status(), StatusCode::UNPROCESSABLE_ENTITY);

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
        panic!("Error response did not match OpenAPI schema for 422");
    }

    // 3. Success case: Get wallet details
    let get_wallet_req = Request::builder()
        .method("GET")
        .uri(format!("/v1/wallets/{}", wallet_id))
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
