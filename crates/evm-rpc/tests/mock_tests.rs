//! Mock-server coverage for `EvmRpcClient`, in the style of
//! `crates/ingest/tests/horizon_mock_tests.rs`: JSON-RPC-error-as-HTTP-200 handling, provider
//! quirk classification (range-too-large), the startup chain-id assertion, hex-quantity edge
//! cases, and the response-body size cap. Retry/backoff/circuit-breaker fault injection lives in
//! `resilience_tests.rs` (mirroring `crates/api/tests/horizon_resilience_tests.rs`'s split).
//!
//! Uses a per-test `wiremock` server (no shared/global mock server across the test binary).

use octo_evm_rpc::{BlockTag, EvmRpcClient, RpcError};
use serde_json::json;
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client(url: &str) -> EvmRpcClient {
    EvmRpcClient::new(url, "eip155:1").expect("valid CAIP-2 chain id")
}

// ---------------------------------------------------------------------------
// JSON-RPC error arrives as HTTP 200 — must be treated as an error, not success.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_200_with_json_rpc_error_is_not_treated_as_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "eth_blockNumber" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": -32000, "message": "internal error" }
        })))
        .mount(&server)
        .await;

    let result = client(&server.uri()).eth_block_number().await;
    assert!(
        matches!(result, Err(RpcError::JsonRpc { code: -32000, .. })),
        "expected a JsonRpc error, got {result:?}"
    );
}

#[tokio::test]
async fn eth_block_number_decodes_a_successful_result() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "eth_blockNumber" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": "0x112a880"
        })))
        .mount(&server)
        .await;

    let result = client(&server.uri()).eth_block_number().await.unwrap();
    assert_eq!(result, ethnum::U256::from(0x112a880u32));
}

// ---------------------------------------------------------------------------
// Provider quirk classification: eth_getLogs range-too-large.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn eth_get_logs_range_too_large_is_surfaced_as_typed_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "eth_getLogs" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": -32602, "message": "eth_getLogs is limited to a 2000 range" }
        })))
        .mount(&server)
        .await;

    let filter = octo_evm_rpc::LogFilter {
        from_block: Some(BlockTag::Number(ethnum::U256::from(1u32))),
        to_block: Some(BlockTag::Latest),
        ..Default::default()
    };
    let result = client(&server.uri()).eth_get_logs(&filter).await;
    assert!(
        matches!(result, Err(RpcError::RangeTooLarge)),
        "expected RangeTooLarge, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Startup chain-id assertion.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn chain_id_mismatch_is_rejected_at_startup() {
    let server = MockServer::start().await;

    // Endpoint reports chain 5 (Goerli) while the client is configured for eip155:1 (mainnet).
    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "eth_chainId" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": "0x5"
        })))
        .mount(&server)
        .await;

    let result = client(&server.uri()).assert_chain_id().await;
    assert!(
        matches!(
            result,
            Err(RpcError::ChainIdMismatch {
                expected: 1,
                actual: 5
            })
        ),
        "expected a ChainIdMismatch(expected=1, actual=5), got {result:?}"
    );
}

#[tokio::test]
async fn matching_chain_id_passes_startup_assertion() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "eth_chainId" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": "0x1"
        })))
        .mount(&server)
        .await;

    let result = client(&server.uri()).assert_chain_id().await;
    assert!(result.is_ok(), "expected Ok(()), got {result:?}");
}

// ---------------------------------------------------------------------------
// Hex quantity parsing edge cases, over the wire.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn zero_quantity_decodes_correctly() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0", "id": 1, "result": "0x0"
        })))
        .mount(&server)
        .await;

    let result = client(&server.uri()).eth_block_number().await.unwrap();
    assert_eq!(result, ethnum::U256::ZERO);
}

#[tokio::test]
async fn value_above_u64_max_decodes_without_truncation() {
    let server = MockServer::start().await;
    // 2^64, one past u64::MAX — would silently truncate to 0 if parsed into a u64.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0", "id": 1, "result": "0x10000000000000000"
        })))
        .mount(&server)
        .await;

    let result = client(&server.uri()).eth_block_number().await.unwrap();
    assert_eq!(result, ethnum::U256::from(u64::MAX) + ethnum::U256::ONE);
}

#[tokio::test]
async fn malformed_quantity_is_a_decode_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0", "id": 1, "result": "not-a-hex-quantity"
        })))
        .mount(&server)
        .await;

    let result = client(&server.uri()).eth_block_number().await;
    assert!(matches!(result, Err(RpcError::Decode)), "got {result:?}");
}

#[tokio::test]
async fn malformed_json_body_is_a_decode_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json at all"))
        .mount(&server)
        .await;

    let result = client(&server.uri()).eth_block_number().await;
    assert!(matches!(result, Err(RpcError::Decode)), "got {result:?}");
}

// ---------------------------------------------------------------------------
// Response body size cap.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn response_body_exceeding_the_size_cap_is_rejected() {
    let server = MockServer::start().await;

    // A legitimate-looking but oversized JSON-RPC response.
    let padding = "a".repeat(4096);
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0", "id": 1, "result": format!("0x{padding}")
        })))
        .mount(&server)
        .await;

    let capped_client = EvmRpcClient::new(server.uri(), "eip155:1")
        .unwrap()
        .with_max_response_bytes(64);

    let result = capped_client.eth_block_number().await;
    assert!(
        matches!(result, Err(RpcError::ResponseTooLarge)),
        "got {result:?}"
    );
}

#[tokio::test]
async fn response_body_within_the_size_cap_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0", "id": 1, "result": "0x2a"
        })))
        .mount(&server)
        .await;

    let capped_client = EvmRpcClient::new(server.uri(), "eip155:1")
        .unwrap()
        .with_max_response_bytes(4096);

    let result = capped_client.eth_block_number().await.unwrap();
    assert_eq!(result, ethnum::U256::from(42u32));
}

// ---------------------------------------------------------------------------
// eth_sendRawTransaction: basic happy path (retry/no-retry semantics are in
// resilience_tests.rs).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn eth_send_raw_transaction_returns_tx_hash() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_partial_json(
            json!({ "method": "eth_sendRawTransaction" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": "0xabc123"
        })))
        .mount(&server)
        .await;

    let result = client(&server.uri())
        .eth_send_raw_transaction("0xdeadbeef")
        .await
        .unwrap();
    assert_eq!(result, "0xabc123");
}

#[tokio::test]
async fn eth_get_transaction_receipt_returns_none_when_not_yet_mined() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_partial_json(
            json!({ "method": "eth_getTransactionReceipt" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": null
        })))
        .mount(&server)
        .await;

    let result = client(&server.uri())
        .eth_get_transaction_receipt("0xabc123")
        .await
        .unwrap();
    assert!(
        result.is_none(),
        "a pending tx must decode to None, not a Decode error"
    );
}
