//! [`EvmRpcClient`]: a typed JSON-RPC 2.0 client for EVM chains, with the same resilience posture
//! as `crates/ingest/src/horizon.rs` / `crates/api/src/horizon.rs`.
//!
//! # Submit asymmetry (AD-5)
//!
//! `eth_sendRawTransaction` is submitted with [`CallKind::Submit`], exactly like Horizon's
//! `submit_transaction` (see that module's header comment for the full reasoning): a transport
//! timeout does not tell you whether the node already broadcast the transaction, so blindly
//! retrying risks a double-submission. Every other method here is [`CallKind::ReadOnly`] and goes
//! through retry-with-backoff.
//!
//! # JSON-RPC errors arrive as HTTP 200
//!
//! A JSON-RPC error is carried in the response *body* (an `error` member), not the HTTP status —
//! a client that only checks `resp.status().is_success()` will treat a body like
//! `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"..."}}` sent with `200 OK` as a
//! success. [`crate::types::require_result`] / [`crate::types::optional_result`] check the `error`
//! member explicitly, before ever looking at `result`.
//!
//! # Provider quirks this client accounts for
//!
//! - `eth_getLogs` block-range caps vary by provider and are not part of the JSON-RPC spec:
//!   Alchemy caps at ~2,000 blocks, Infura at ~10,000, others are unbounded. When the error
//!   message indicates a range-too-large rejection, [`crate::types::classify_json_rpc_error`]
//!   surfaces [`RpcError::RangeTooLarge`] instead of a generic [`RpcError::JsonRpc`], so a caller
//!   can bisect the range and retry with smaller windows.
//! - Rate-limit responses (HTTP 429, or a JSON-RPC error mentioning it) surface as
//!   [`RpcError::RateLimited`] with the `Retry-After` header value when present.
//! - A malicious or compromised RPC endpoint returning a huge body must not OOM the caller —
//!   [`read_capped_body`] streams the response and aborts once `max_response_bytes` is exceeded,
//!   rather than buffering the whole body first and checking after.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ethnum::U256;
use futures_util::StreamExt;
use octo_resilience::{execute, CallKind, CircuitBreaker, ResilienceError, RetryPolicy};
use reqwest::StatusCode;
use serde_json::json;

use crate::error::RpcError;
use crate::types::{
    optional_result, require_result, Block, BlockTag, CallRequest, FeeHistory, JsonRpcRequest,
    JsonRpcResponse, Log, LogFilter, TransactionReceipt,
};

/// Default cap on a single JSON-RPC response body: 10 MiB. Every method this crate exposes
/// returns a small, bounded structure (a block header, a page of logs, a receipt); nothing
/// legitimate should approach this, so it exists purely to bound a misbehaving endpoint.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

/// A typed JSON-RPC 2.0 client for one EVM chain endpoint.
///
/// Clones share circuit-breaker state (via the `Arc` inside [`CircuitBreaker`]) and the request-id
/// counter, matching `HorizonPayments`/`Horizon`'s `Clone` semantics.
#[derive(Clone)]
pub struct EvmRpcClient {
    http: reqwest::Client,
    url: String,
    /// CAIP-2 chain id this client is configured for, e.g. `"eip155:1"`. Parsed once at
    /// construction (see [`parse_caip2_eip155`]) so [`Self::assert_chain_id`] never needs to fail
    /// on a configuration error only at call time.
    expected_chain_id: u64,
    chain_id_label: String,
    circuit: CircuitBreaker,
    retry: RetryPolicy,
    max_response_bytes: usize,
    next_id: Arc<AtomicU64>,
}

// RPC URLs carry API keys (e.g. `https://eth-mainnet.g.alchemy.com/v2/<secret>`) and must never
// be logged — including accidentally, via a derived `Debug` impl reached by `tracing`/`{:?}` on a
// value that embeds this client. Redact it explicitly instead of deriving.
impl std::fmt::Debug for EvmRpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvmRpcClient")
            .field("url", &"<redacted>")
            .field("chain_id", &self.chain_id_label)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

impl EvmRpcClient {
    /// Create a new client with default resilience settings (mirrors
    /// `HorizonPayments::new`/`Horizon::new`: 3 attempts, circuit opens after 5 consecutive
    /// failures with a 30s cool-down).
    ///
    /// `chain_id` is the CAIP-2 chain id this endpoint is expected to serve, e.g. `"eip155:1"`.
    pub fn new(url: impl Into<String>, chain_id: impl Into<String>) -> Result<Self, RpcError> {
        Self::with_resilience(
            url,
            chain_id,
            RetryPolicy::default(),
            CircuitBreaker::new(5, Duration::from_secs(30)),
        )
    }

    /// Create a client with explicit resilience configuration. Used by `bin/server` (env-var
    /// config) and by tests (tight thresholds, zero backoff delay).
    pub fn with_resilience(
        url: impl Into<String>,
        chain_id: impl Into<String>,
        retry: RetryPolicy,
        circuit: CircuitBreaker,
    ) -> Result<Self, RpcError> {
        let chain_id_label = chain_id.into();
        let expected_chain_id = parse_caip2_eip155(&chain_id_label)?;
        Ok(Self {
            http: reqwest::Client::new(),
            url: url.into(),
            expected_chain_id,
            chain_id_label,
            circuit,
            retry,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            next_id: Arc::new(AtomicU64::new(1)),
        })
    }

    /// Override the response-body size cap (default [`DEFAULT_MAX_RESPONSE_BYTES`]).
    pub fn with_max_response_bytes(mut self, max: usize) -> Self {
        self.max_response_bytes = max;
        self
    }

    /// Assert that this endpoint's `eth_chainId` matches the chain id this client was configured
    /// for. **Call this once at startup**, before routing any real traffic through the client: an
    /// RPC URL pointed at the wrong chain (e.g. a mainnet-configured worker accidentally wired to
    /// a testnet endpoint, or vice versa) is a fund-loss bug — a transaction built and signed for
    /// one chain, broadcast to another, can be replayed or simply confuse balance accounting. This
    /// one check catches a misconfiguration before it does either.
    pub async fn assert_chain_id(&self) -> Result<(), RpcError> {
        let actual = self.eth_chain_id().await?;
        let expected = U256::from(self.expected_chain_id);
        if actual != expected {
            // actual is asserted above to differ from `expected`, which was built from a u64, but
            // a real endpoint could in principle report something outside u64 range; report 0
            // rather than truncating silently in that (essentially impossible) case.
            let actual_u64 = u64::try_from(actual).unwrap_or(0);
            return Err(RpcError::ChainIdMismatch {
                expected: self.expected_chain_id,
                actual: actual_u64,
            });
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Read-only methods
    // -----------------------------------------------------------------

    /// `eth_chainId`.
    pub async fn eth_chain_id(&self) -> Result<U256, RpcError> {
        self.call_quantity("eth_chainId", json!([])).await
    }

    /// `eth_blockNumber`.
    pub async fn eth_block_number(&self) -> Result<U256, RpcError> {
        self.call_quantity("eth_blockNumber", json!([])).await
    }

    /// `eth_getBlockByNumber`. Returns `None` if the block does not exist (yet).
    pub async fn eth_get_block_by_number(
        &self,
        block: BlockTag,
        full_transactions: bool,
    ) -> Result<Option<Block>, RpcError> {
        self.call_optional(
            "eth_getBlockByNumber",
            json!([block.to_param(), full_transactions]),
        )
        .await
    }

    /// `eth_getLogs`. On a range-too-large rejection, returns [`RpcError::RangeTooLarge`] rather
    /// than a generic protocol error — see the module docs.
    pub async fn eth_get_logs(&self, filter: &LogFilter) -> Result<Vec<Log>, RpcError> {
        self.call_required("eth_getLogs", json!([filter.to_param()]))
            .await
    }

    /// `eth_getTransactionReceipt`. Returns `None` when the transaction is not yet mined.
    pub async fn eth_get_transaction_receipt(
        &self,
        tx_hash: &str,
    ) -> Result<Option<TransactionReceipt>, RpcError> {
        self.call_optional("eth_getTransactionReceipt", json!([tx_hash]))
            .await
    }

    /// `eth_getTransactionCount` (the account nonce) at `block`.
    pub async fn eth_get_transaction_count(
        &self,
        address: &str,
        block: BlockTag,
    ) -> Result<U256, RpcError> {
        self.call_quantity(
            "eth_getTransactionCount",
            json!([address, block.to_param()]),
        )
        .await
    }

    /// `eth_call`: execute `call` against `block` without creating a transaction. Returns the
    /// hex-encoded return data. A revert surfaces as [`RpcError::Revert`].
    pub async fn eth_call(&self, call: &CallRequest, block: BlockTag) -> Result<String, RpcError> {
        self.call_required("eth_call", json!([call.to_param(), block.to_param()]))
            .await
    }

    /// `eth_estimateGas`.
    pub async fn eth_estimate_gas(&self, call: &CallRequest) -> Result<U256, RpcError> {
        self.call_quantity("eth_estimateGas", json!([call.to_param()]))
            .await
    }

    /// `eth_feeHistory`.
    pub async fn eth_fee_history(
        &self,
        block_count: u64,
        newest_block: BlockTag,
        reward_percentiles: &[f64],
    ) -> Result<FeeHistory, RpcError> {
        self.call_required(
            "eth_feeHistory",
            json!([
                crate::types::encode_quantity(U256::from(block_count)),
                newest_block.to_param(),
                reward_percentiles,
            ]),
        )
        .await
    }

    // -----------------------------------------------------------------
    // Submit (never retried — see module docs)
    // -----------------------------------------------------------------

    /// `eth_sendRawTransaction`: broadcast a signed, RLP-encoded transaction (`0x`-hex). Returns
    /// the transaction hash.
    ///
    /// **Not retried.** A transport failure here does not mean the transaction wasn't broadcast —
    /// see the module docs and `octo_resilience`'s submit-asymmetry documentation. The circuit
    /// breaker still applies: if the endpoint is clearly down, this fails fast instead of piling
    /// up independent timeouts.
    pub async fn eth_send_raw_transaction(&self, signed_tx_hex: &str) -> Result<String, RpcError> {
        self.call(
            "eth_sendRawTransaction",
            json!([signed_tx_hex]),
            CallKind::Submit,
        )
        .await
        .and_then(require_result)
    }

    // -----------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------

    async fn call_required<T>(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> Result<T, RpcError>
    where
        T: serde::de::DeserializeOwned,
    {
        self.call(method, params, CallKind::ReadOnly)
            .await
            .and_then(require_result)
    }

    /// Like [`Self::call_required`], for methods whose `result` is a bare hex-quantity string
    /// rather than a struct — `U256` itself doesn't implement `Deserialize` (there's no single
    /// "right" wire format for it in general), so this goes through [`crate::types::QuantityWire`],
    /// which decodes specifically the JSON-RPC hex-quantity format this crate expects everywhere.
    async fn call_quantity(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> Result<U256, RpcError> {
        self.call_required::<crate::types::QuantityWire>(method, params)
            .await
            .map(|w| w.0)
    }

    async fn call_optional<T>(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> Result<Option<T>, RpcError>
    where
        T: serde::de::DeserializeOwned,
    {
        self.call(method, params, CallKind::ReadOnly)
            .await
            .and_then(optional_result)
    }

    /// Send one JSON-RPC request and return the decoded envelope (caller extracts `result`/`error`
    /// via [`require_result`]/[`optional_result`]) — the shared plumbing under every `eth_*`
    /// method above: resilience wiring, the capped body read, and JSON-RPC-error-as-HTTP-200
    /// handling.
    async fn call<T>(
        &self,
        method: &'static str,
        params: serde_json::Value,
        kind: CallKind,
    ) -> Result<JsonRpcResponse<T>, RpcError>
    where
        T: serde::de::DeserializeOwned,
    {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = JsonRpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id,
        };
        let http = self.http.clone();
        let url = self.url.clone();
        let cap = self.max_response_bytes;

        let result = execute(&self.circuit, &self.retry, kind, || {
            let http = http.clone();
            let url = url.clone();
            let body = body.clone();
            async move {
                let resp = http
                    .post(&url)
                    .json(&body)
                    .send()
                    .await
                    .map_err(|_| RpcError::Transport)?;

                let status = resp.status();
                if status == StatusCode::TOO_MANY_REQUESTS {
                    let retry_after = resp
                        .headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok());
                    return Err(RpcError::RateLimited { retry_after });
                }

                let bytes = read_capped_body(resp, cap).await?;

                match serde_json::from_slice::<JsonRpcResponse<T>>(&bytes) {
                    Ok(parsed) => Ok(parsed),
                    Err(_) => {
                        // A 5xx that didn't parse as JSON-RPC (a proxy error page, an empty body,
                        // ...) is transient; anything else with an unparseable body is a settled
                        // decode failure, not worth retrying.
                        if status.is_server_error() {
                            Err(RpcError::Transport)
                        } else {
                            Err(RpcError::Decode)
                        }
                    }
                }
            }
        })
        .await;

        map_resilience_result(result)
    }
}

/// Read `resp`'s body incrementally, aborting with [`RpcError::ResponseTooLarge`] the moment the
/// accumulated size would exceed `cap` — rather than buffering the full body (via
/// `reqwest::Response::bytes()`) and checking its length only afterward, which would already have
/// let an unbounded body exhaust memory before the check ever ran.
async fn read_capped_body(resp: reqwest::Response, cap: usize) -> Result<Vec<u8>, RpcError> {
    let mut buf = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| RpcError::Transport)?;
        if buf.len() + chunk.len() > cap {
            return Err(RpcError::ResponseTooLarge);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

fn map_resilience_result<T>(r: Result<T, ResilienceError<RpcError>>) -> Result<T, RpcError> {
    match r {
        Ok(v) => Ok(v),
        Err(ResilienceError::Circuit) => Err(RpcError::CircuitOpen),
        Err(ResilienceError::Exhausted(e)) => Err(e),
    }
}

/// Parse a CAIP-2 chain id string of the form `"eip155:<decimal chain id>"`.
fn parse_caip2_eip155(chain_id: &str) -> Result<u64, RpcError> {
    let (namespace, reference) = chain_id
        .split_once(':')
        .ok_or_else(|| RpcError::InvalidChainId(chain_id.to_string()))?;
    if namespace != "eip155" {
        return Err(RpcError::InvalidChainId(chain_id.to_string()));
    }
    reference
        .parse::<u64>()
        .map_err(|_| RpcError::InvalidChainId(chain_id.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_caip2_eip155() {
        assert_eq!(parse_caip2_eip155("eip155:1").unwrap(), 1);
        assert_eq!(parse_caip2_eip155("eip155:11155111").unwrap(), 11_155_111);
    }

    #[test]
    fn rejects_non_eip155_namespace() {
        assert!(matches!(
            parse_caip2_eip155("cosmos:cosmoshub-4"),
            Err(RpcError::InvalidChainId(_))
        ));
    }

    #[test]
    fn rejects_malformed_caip2() {
        for bad in ["eip155", "eip155:", "eip155:abc", "", ":1", "eip155:1:2"] {
            assert!(
                matches!(parse_caip2_eip155(bad), Err(RpcError::InvalidChainId(_))),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn constructor_rejects_invalid_chain_id_before_any_network_call() {
        let result = EvmRpcClient::new("http://127.0.0.1:1", "not-a-caip2-id");
        assert!(matches!(result, Err(RpcError::InvalidChainId(_))));
    }

    #[test]
    fn debug_impl_redacts_url() {
        let client = EvmRpcClient::new(
            "https://eth-mainnet.example/v2/super-secret-key",
            "eip155:1",
        )
        .unwrap();
        let debug = format!("{client:?}");
        assert!(
            !debug.contains("super-secret-key"),
            "Debug output must never contain the RPC URL: {debug}"
        );
        assert!(debug.contains("<redacted>"));
    }
}
