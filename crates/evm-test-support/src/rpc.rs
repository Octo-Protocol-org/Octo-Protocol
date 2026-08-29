//! A deliberately minimal JSON-RPC 2.0 client — just enough to drive Anvil from the test harness.
//! Not the resilient, typed client the `octo-evm-rpc` epic will eventually build; that one adds
//! retry/circuit-breaking and per-chain policy on top of the same trap this client already avoids:
//! a JSON-RPC error arrives as HTTP 200 with an `error` member, so checking HTTP status alone
//! would read every failure as success.

use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("transport error calling {method}: {source}")]
    Transport {
        method: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("JSON-RPC error calling {method}: code {code}, {message}")]
    JsonRpc {
        method: String,
        code: i64,
        message: String,
    },
    #[error("malformed JSON-RPC response: {0}")]
    Malformed(String),
}

#[derive(Clone)]
pub struct RpcClient {
    http: reqwest::Client,
    url: String,
}

impl RpcClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            url: url.into(),
        }
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let response = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|source| RpcError::Transport {
                method: method.to_string(),
                source,
            })?;

        let value: Value = response
            .json()
            .await
            .map_err(|source| RpcError::Transport {
                method: method.to_string(),
                source,
            })?;

        if let Some(error) = value.get("error") {
            let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            return Err(RpcError::JsonRpc {
                method: method.to_string(),
                code,
                message,
            });
        }

        value
            .get("result")
            .cloned()
            .ok_or_else(|| RpcError::Malformed(format!("missing `result` field calling {method}")))
    }
}

/// Parses a `0x`-prefixed hex quantity into a `u64`. Panics on malformed input — every call site
/// here is parsing a value that just came back from Anvil itself, not untrusted external input.
pub fn hex_to_u64(hex: &str) -> u64 {
    u64::from_str_radix(hex.trim_start_matches("0x"), 16)
        .unwrap_or_else(|e| panic!("malformed hex quantity {hex:?}: {e}"))
}

pub fn u64_to_hex(value: u64) -> String {
    format!("0x{value:x}")
}
