use octo_api::horizon::Horizon;
use octo_api::ApiError;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
