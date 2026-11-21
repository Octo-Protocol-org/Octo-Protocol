use octo_api::horizon::Horizon;
use octo_api::ApiError;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Spawns the offline mock Horizon server (see `crates/mock-horizon`) on an
/// ephemeral port and returns a `Horizon` client pointed at it.
///
/// Fixtures served by the mock are documented in `crates/mock-horizon/README.md`.
async fn start_mock_horizon() -> (mock_horizon::MockHorizon, Horizon) {
    let server = mock_horizon::MockHorizon::start()
        .await
        .expect("failed to start mock Horizon server");
    let client = Horizon::new(server.uri());
    (server, client)
}

#[tokio::test]
async fn mock_horizon_serves_scripted_balances() {
    let (_server, client) = start_mock_horizon().await;

    let balances = client
        .balances(mock_horizon::fixtures::FUNDED_ACCOUNT)
        .await
        .expect("expected scripted balances for funded account");

    assert!(
        !balances.is_empty(),
        "expected at least one balance for funded account"
    );
}

#[tokio::test]
async fn mock_horizon_serves_scripted_account_sequence() {
    let (_server, client) = start_mock_horizon().await;

    let sequence = client
        .account_sequence(mock_horizon::fixtures::FUNDED_ACCOUNT)
        .await
        .expect("expected scripted sequence for funded account");

    assert_eq!(sequence, mock_horizon::fixtures::FUNDED_ACCOUNT_SEQUENCE);
}

#[tokio::test]
async fn mock_horizon_unknown_account_maps_to_not_found() {
    let (_server, client) = start_mock_horizon().await;

    let bal_res = client.balances(mock_horizon::fixtures::UNKNOWN_ACCOUNT).await;
    assert!(
        matches!(bal_res, Err(ApiError::NotFound)),
        "Expected ApiError::NotFound, got {:?}",
        bal_res
    );

    let seq_res = client
        .account_sequence(mock_horizon::fixtures::UNKNOWN_ACCOUNT)
        .await;
    assert!(
        matches!(seq_res, Err(ApiError::NotFound)),
        "Expected ApiError::NotFound, got {:?}",
        seq_res
    );
}

#[tokio::test]
async fn mock_horizon_scripted_submit_success() {
    let (_server, client) = start_mock_horizon().await;

    let res = client
        .submit_transaction(mock_horizon::fixtures::ACCEPTED_TRANSACTION_XDR)
        .await;

    assert!(
        res.is_ok(),
        "Expected scripted submit to succeed, got {:?}",
        res
    );
}

#[tokio::test]
async fn mock_horizon_scripted_submit_rejection_maps_to_bad_request() {
    let (_server, client) = start_mock_horizon().await;

    let res = client
        .submit_transaction(mock_horizon::fixtures::REJECTED_TRANSACTION_XDR)
        .await;

    assert!(
        matches!(res, Err(ApiError::BadRequest(_))),
        "Expected ApiError::BadRequest for scripted rejection, got {:?}",
        res
    );
}

#[tokio::test]
async fn horizon_404_maps_to_not_found_for_balances_and_sequence() {
    let mock_server = MockServer::start().await;
    let account = "GDEXAMPLE";

    Mock::given(method("GET"))
        .and(path(format!("/accounts/{}", account)))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let client = Horizon::new(mock_server.uri());

    let bal_res = client.balances(account).await;
    assert!(
        matches!(bal_res, Err(ApiError::NotFound)),
        "Expected ApiError::NotFound, got {:?}",
        bal_res
    );

    let seq_res = client.account_sequence(account).await;
    assert!(
        matches!(seq_res, Err(ApiError::NotFound)),
        "Expected ApiError::NotFound, got {:?}",
        seq_res
    );
}

#[tokio::test]
async fn horizon_5xx_maps_to_internal() {
    let mock_server = MockServer::start().await;
    let account = "GDEXAMPLE";

    Mock::given(method("GET"))
        .and(path(format!("/accounts/{}", account)))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let client = Horizon::new(mock_server.uri());

    let bal_res = client.balances(account).await;
    assert!(
        matches!(bal_res, Err(ApiError::Internal)),
        "Expected ApiError::Internal, got {:?}",
        bal_res
    );

    let seq_res = client.account_sequence(account).await;
    assert!(
        matches!(seq_res, Err(ApiError::Internal)),
        "Expected ApiError::Internal, got {:?}",
        seq_res
    );
}

#[tokio::test]
async fn horizon_malformed_json_maps_to_internal() {
    let mock_server = MockServer::start().await;
    let account = "GDEXAMPLE";

    // Returns a 200 OK with non-JSON body
    Mock::given(method("GET"))
        .and(path(format!("/accounts/{}", account)))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&mock_server)
        .await;

    let client = Horizon::new(mock_server.uri());

    let bal_res = client.balances(account).await;
    assert!(
        matches!(bal_res, Err(ApiError::Internal)),
        "Expected ApiError::Internal, got {:?}",
        bal_res
    );

    let seq_res = client.account_sequence(account).await;
    assert!(
        matches!(seq_res, Err(ApiError::Internal)),
        "Expected ApiError::Internal, got {:?}",
        seq_res
    );
}

#[tokio::test]
async fn submit_transaction_400_with_unparseable_body_maps_to_bad_request() {
    let mock_server = MockServer::start().await;

    // Returns 400 Bad Request with non-JSON body
    Mock::given(method("POST"))
        .and(path("/transactions"))
        .respond_with(ResponseTemplate::new(400).set_body_string("not json"))
        .mount(&mock_server)
        .await;

    let client = Horizon::new(mock_server.uri());

    let res = client.submit_transaction("some_xdr").await;
    assert!(
        matches!(res, Err(ApiError::BadRequest(ref m)) if m == "transaction rejected by network"),
        "Expected ApiError::BadRequest(\"transaction rejected by network\"), got {:?}",
        res
    );
}

#[tokio::test]
async fn submit_transaction_200_with_unparseable_body_maps_to_internal() {
    let mock_server = MockServer::start().await;

    // Returns 200 OK with non-JSON body
    Mock::given(method("POST"))
        .and(path("/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&mock_server)
        .await;

    let client = Horizon::new(mock_server.uri());

    let res = client.submit_transaction("some_xdr").await;
    assert!(
        matches!(res, Err(ApiError::Internal)),
        "Expected ApiError::Internal, got {:?}",
        res
    );
}

#[tokio::test]
async fn fee_stats_selected_fee_never_exceeds_configured_ceiling() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/fee_stats"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "fee_charged": { "p95": "2500" }
        })))
        .mount(&mock_server)
        .await;

    let client = Horizon::new(mock_server.uri());
    assert_eq!(client.recommended_fee_stroops(95, 100, 1_000).await, 1_000);
}

#[tokio::test]
async fn fee_stats_unavailable_falls_back_to_network_base_fee() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/fee_stats"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&mock_server)
        .await;

    let client = Horizon::new(mock_server.uri());
    assert_eq!(client.recommended_fee_stroops(50, 100, 1_000).await, 100);
}
