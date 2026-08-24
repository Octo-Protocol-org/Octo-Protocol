//! Minimal EVM JSON-RPC client for the confirmation tracker.
//!
//! Per the workspace ADR (`docs/architecture.md`: narrow primitives over alloy, MSRV 1.84.1),
//! this speaks raw JSON-RPC over `reqwest` rather than pulling in a full EVM client crate — the
//! confirmation tracker only ever needs the chain tip and a handful of block headers, not a
//! general-purpose provider.
//!
//! # Resilience
//!
//! Every call here is read-only, so (mirroring [`crate::horizon::HorizonPayments`]) each is
//! wrapped with retry-with-backoff and a circuit breaker from `octo_resilience`.

use octo_resilience::{execute, CallKind, CircuitBreaker, ResilienceError, RetryPolicy};
use serde::Deserialize;
use serde_json::json;

/// Errors talking to an EVM JSON-RPC endpoint.
#[derive(Debug, thiserror::Error)]
pub enum EvmRpcError {
    #[error("evm rpc request failed")]
    Request,
    #[error("evm rpc returned an unexpected response")]
    Decode,
    #[error("evm rpc circuit breaker open")]
    CircuitOpen,
}

/// The header fields the confirmation tracker needs: enough to chain blocks by parent hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub number: i64,
    /// `0x`-prefixed hash, lowercased, as returned by the node.
    pub hash: String,
    /// `0x`-prefixed parent hash, lowercased.
    pub parent_hash: String,
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcErrorBody>,
}

#[derive(Debug, Deserialize)]
struct RpcErrorBody {
    #[allow(dead_code)]
    code: i64,
    #[allow(dead_code)]
    message: String,
}

#[derive(Debug, Deserialize)]
struct RawBlock {
    number: String,
    hash: String,
    #[serde(rename = "parentHash")]
    parent_hash: String,
}

/// A thin EVM JSON-RPC client with retry-with-backoff and circuit-breaker protection.
///
/// Clones share the same circuit-breaker state (via `Arc` inside [`CircuitBreaker`]).
#[derive(Clone)]
pub struct EvmRpcClient {
    http: reqwest::Client,
    url: String,
    circuit: CircuitBreaker,
    retry: RetryPolicy,
}

impl EvmRpcClient {
    /// Create a new client with default resilience settings.
    pub fn new(url: impl Into<String>) -> Self {
        Self::with_resilience(
            url,
            RetryPolicy::default(),
            CircuitBreaker::new(5, std::time::Duration::from_secs(30)),
        )
    }

    /// Create a client with explicit resilience configuration.
    pub fn with_resilience(url: impl Into<String>, retry: RetryPolicy, circuit: CircuitBreaker) -> Self {
        Self {
            http: reqwest::Client::new(),
            url: url.into(),
            circuit,
            retry,
        }
    }

    /// The current chain tip, as a full header (`eth_getBlockByNumber("latest", false)`) — a
    /// number alone isn't enough since the tracker needs the tip's hash too.
    pub async fn latest_block(&self) -> Result<BlockHeader, EvmRpcError> {
        self.block_by_tag("latest")
            .await?
            .ok_or(EvmRpcError::Decode)
    }

    /// A block by its `finalized` or `safe` tag (post-Merge), where the provider supports it — a
    /// stronger finality signal than depth-counting, per the issue's "consider" note. Returns
    /// `None` if the node has no block for that tag yet (e.g. a very young chain), rather than
    /// erroring, since that is a legitimate transient state, not a malformed response.
    pub async fn block_by_tag(&self, tag: &str) -> Result<Option<BlockHeader>, EvmRpcError> {
        self.get_block(json!(tag)).await
    }

    /// A block by its number.
    pub async fn block_by_number(&self, number: i64) -> Result<Option<BlockHeader>, EvmRpcError> {
        self.get_block(json!(format!("0x{:x}", number))).await
    }

    async fn get_block(&self, param: serde_json::Value) -> Result<Option<BlockHeader>, EvmRpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getBlockByNumber",
            "params": [param, false],
        });

        let http = self.http.clone();
        let url = self.url.clone();
        let result = execute(&self.circuit, &self.retry, CallKind::ReadOnly, || {
            let url = url.clone();
            let http = http.clone();
            let body = body.clone();
            async move {
                let resp = http
                    .post(&url)
                    .json(&body)
                    .send()
                    .await
                    .map_err(|_| EvmRpcFetchError::Transport)?;

                if resp.status().is_server_error() {
                    return Err(EvmRpcFetchError::Transport); // retriable
                }
                if !resp.status().is_success() {
                    return Err(EvmRpcFetchError::Permanent);
                }
                let parsed: RpcResponse<Option<RawBlock>> =
                    resp.json().await.map_err(|_| EvmRpcFetchError::Decode)?;
                if parsed.error.is_some() {
                    return Err(EvmRpcFetchError::Permanent);
                }
                match parsed.result.flatten() {
                    Some(raw) => {
                        let number = i64::from_str_radix(raw.number.trim_start_matches("0x"), 16)
                            .map_err(|_| EvmRpcFetchError::Decode)?;
                        Ok(Some(BlockHeader {
                            number,
                            hash: raw.hash.to_lowercase(),
                            parent_hash: raw.parent_hash.to_lowercase(),
                        }))
                    }
                    None => Ok(None),
                }
            }
        })
        .await;

        match result {
            Ok(header) => Ok(header),
            Err(ResilienceError::Circuit) => Err(EvmRpcError::CircuitOpen),
            Err(ResilienceError::Exhausted(EvmRpcFetchError::Decode)) => Err(EvmRpcError::Decode),
            Err(ResilienceError::Exhausted(_)) => Err(EvmRpcError::Request),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum EvmRpcFetchError {
    Transport,
    Decode,
    Permanent,
}

impl octo_resilience::Retriable for EvmRpcFetchError {
    fn is_retriable(&self) -> bool {
        matches!(self, EvmRpcFetchError::Transport)
    }
}

impl std::fmt::Display for EvmRpcFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport => write!(f, "transport error"),
            Self::Decode => write!(f, "decode error"),
            Self::Permanent => write!(f, "permanent error"),
        }
    }
}
