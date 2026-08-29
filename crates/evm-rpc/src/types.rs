//! JSON-RPC 2.0 envelope types, the hex-quantity codec, and the EVM domain types this crate's
//! methods return.
//!
//! # Quantities are always `U256`, never `u64`/`f64`
//!
//! Every numeric field in the `eth_*` JSON-RPC API (block numbers, balances, gas, nonces, fee
//! history entries, ...) is transmitted as a `0x`-prefixed, minimal-length hex **string** — not a
//! JSON number — specifically because on-chain values (wei balances especially) routinely exceed
//! `u64::MAX` and JSON numbers cannot represent large integers exactly. Parsing into `u64` silently
//! truncates; parsing into `f64` silently loses precision. Every quantity in this module is an
//! [`ethnum::U256`], decoded with [`parse_quantity`].

use ethnum::U256;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::RpcError;

// ---------------------------------------------------------------------------
// JSON-RPC envelope
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub(crate) struct JsonRpcRequest {
    pub jsonrpc: &'static str,
    pub method: &'static str,
    pub params: serde_json::Value,
    pub id: u64,
}

#[derive(Debug, Deserialize)]
// Without this, serde's derive conservatively adds a `T: Default` bound to the whole impl because
// of the `#[serde(default)]` below — even though `Option<T>: Default` needs no bound on `T` at
// all. The explicit bound overrides that inference with the one actually required.
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub(crate) struct JsonRpcResponse<T> {
    #[serde(default)]
    pub result: Option<T>,
    #[serde(default)]
    pub error: Option<JsonRpcErrorObj>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonRpcErrorObj {
    pub code: i64,
    pub message: String,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

/// Turn a JSON-RPC error object into the most specific [`RpcError`] variant its `code`/`message`
/// indicate, falling back to the generic [`RpcError::JsonRpc`].
///
/// Provider error text is not standardised across the ecosystem (see the module docs on
/// [`crate::client`] for the specific Alchemy/Infura strings this was built against), so this is
/// necessarily a best-effort text match rather than a fixed error-code table.
pub(crate) fn classify_json_rpc_error(err: JsonRpcErrorObj) -> RpcError {
    let msg_lower = err.message.to_ascii_lowercase();

    if msg_lower.contains("block range")
        || msg_lower.contains("limited to a")
        || msg_lower.contains("returned more than")
        || msg_lower.contains("query returned more than")
        || msg_lower.contains("range should work")
    {
        return RpcError::RangeTooLarge;
    }

    if msg_lower.contains("rate limit") || msg_lower.contains("too many requests") {
        return RpcError::RateLimited { retry_after: None };
    }

    // Common revert signalling: code 3 is the de-facto convention (geth, and others that copied
    // it) for "execution reverted"; some nodes only set the message.
    if err.code == 3 || msg_lower.contains("revert") {
        let data = err.data.map(|d| match d {
            serde_json::Value::String(s) => s,
            other => other.to_string(),
        });
        return RpcError::Revert { data };
    }

    RpcError::JsonRpc {
        code: err.code,
        message: err.message,
    }
}

// ---------------------------------------------------------------------------
// Hex quantity codec
// ---------------------------------------------------------------------------

/// Parse a JSON-RPC quantity string (`"0x..."`) into a [`U256`].
///
/// Accepts `"0x0"` for zero and tolerates non-minimal (leading-zero) hex, since not every
/// real-world endpoint is spec-strict — but requires the `0x` prefix, at least one hex digit, only
/// hex digits, and a value that fits in 256 bits (64 hex digits after the prefix).
pub fn parse_quantity(s: &str) -> Result<U256, RpcError> {
    let hex_part = s.strip_prefix("0x").ok_or(RpcError::Decode)?;
    if hex_part.is_empty() || hex_part.len() > 64 {
        return Err(RpcError::Decode);
    }
    U256::from_str_hex(&format!("0x{hex_part}")).map_err(|_| RpcError::Decode)
}

/// Encode a [`U256`] as a minimal-length `0x`-prefixed hex quantity string, per the JSON-RPC spec.
pub fn encode_quantity(value: U256) -> String {
    format!("{value:#x}")
}

pub(crate) fn deserialize_quantity<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse_quantity(&s).map_err(serde::de::Error::custom)
}

mod quantity_opt {
    use super::{encode_quantity, parse_quantity, U256};
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(dead_code)] // symmetry with the non-optional codec; not every caller needs both halves
    pub(crate) fn serialize<S>(value: &Option<U256>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(v) => serializer.serialize_str(&encode_quantity(*v)),
            None => serializer.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Option<U256>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<String>::deserialize(deserializer)? {
            Some(s) => parse_quantity(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

/// Send a JSON-RPC request body and decode a non-null `result` field. Used internally by
/// [`crate::client::EvmRpcClient`]; kept here alongside the types it decodes into.
pub(crate) fn require_result<T>(resp: JsonRpcResponse<T>) -> Result<T, RpcError>
where
    T: DeserializeOwned,
{
    if let Some(err) = resp.error {
        return Err(classify_json_rpc_error(err));
    }
    resp.result.ok_or(RpcError::Decode)
}

/// Same as [`require_result`] but treats a `null`/absent `result` as a legitimate `None` rather
/// than a decode error — used by methods where the JSON-RPC spec defines `null` as a real answer
/// (e.g. `eth_getTransactionReceipt` before the transaction is mined).
pub(crate) fn optional_result<T>(resp: JsonRpcResponse<T>) -> Result<Option<T>, RpcError>
where
    T: DeserializeOwned,
{
    if let Some(err) = resp.error {
        return Err(classify_json_rpc_error(err));
    }
    Ok(resp.result)
}

// ---------------------------------------------------------------------------
// Block tags / filters / requests
// ---------------------------------------------------------------------------

/// A block reference: an explicit number, or one of the standard EVM tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockTag {
    Number(U256),
    Latest,
    Earliest,
    Pending,
    Safe,
    Finalized,
}

impl BlockTag {
    pub(crate) fn to_param(self) -> serde_json::Value {
        match self {
            BlockTag::Number(n) => serde_json::Value::String(encode_quantity(n)),
            BlockTag::Latest => serde_json::Value::String("latest".to_string()),
            BlockTag::Earliest => serde_json::Value::String("earliest".to_string()),
            BlockTag::Pending => serde_json::Value::String("pending".to_string()),
            BlockTag::Safe => serde_json::Value::String("safe".to_string()),
            BlockTag::Finalized => serde_json::Value::String("finalized".to_string()),
        }
    }
}

/// Parameters for `eth_getLogs`.
#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    pub from_block: Option<BlockTag>,
    pub to_block: Option<BlockTag>,
    /// Contract address(es) to filter by. Empty means "any address".
    pub address: Vec<String>,
    /// Topic filter, positional: `topics[0]` matches the event signature, etc. `None` at a
    /// position means "any value"; an inner `Vec` at a position is an OR over those values.
    pub topics: Vec<Option<Vec<String>>>,
}

impl LogFilter {
    pub(crate) fn to_param(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        if let Some(from) = self.from_block {
            obj.insert("fromBlock".to_string(), from.to_param());
        }
        if let Some(to) = self.to_block {
            obj.insert("toBlock".to_string(), to.to_param());
        }
        match self.address.len() {
            0 => {}
            1 => {
                obj.insert(
                    "address".to_string(),
                    serde_json::Value::String(self.address[0].clone()),
                );
            }
            _ => {
                obj.insert(
                    "address".to_string(),
                    serde_json::Value::Array(
                        self.address
                            .iter()
                            .map(|a| serde_json::Value::String(a.clone()))
                            .collect(),
                    ),
                );
            }
        }
        if !self.topics.is_empty() {
            let topics: Vec<serde_json::Value> = self
                .topics
                .iter()
                .map(|t| match t {
                    None => serde_json::Value::Null,
                    Some(values) if values.len() == 1 => {
                        serde_json::Value::String(values[0].clone())
                    }
                    Some(values) => serde_json::Value::Array(
                        values
                            .iter()
                            .map(|v| serde_json::Value::String(v.clone()))
                            .collect(),
                    ),
                })
                .collect();
            obj.insert("topics".to_string(), serde_json::Value::Array(topics));
        }
        serde_json::Value::Object(obj)
    }
}

/// Parameters for `eth_call` / `eth_estimateGas`.
#[derive(Debug, Clone, Default)]
pub struct CallRequest {
    pub from: Option<String>,
    pub to: Option<String>,
    pub gas: Option<U256>,
    pub gas_price: Option<U256>,
    pub value: Option<U256>,
    /// Call data, hex-encoded (`0x`-prefixed).
    pub data: Option<String>,
}

impl CallRequest {
    pub(crate) fn to_param(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        if let Some(v) = &self.from {
            obj.insert("from".to_string(), serde_json::Value::String(v.clone()));
        }
        if let Some(v) = &self.to {
            obj.insert("to".to_string(), serde_json::Value::String(v.clone()));
        }
        if let Some(v) = self.gas {
            obj.insert(
                "gas".to_string(),
                serde_json::Value::String(encode_quantity(v)),
            );
        }
        if let Some(v) = self.gas_price {
            obj.insert(
                "gasPrice".to_string(),
                serde_json::Value::String(encode_quantity(v)),
            );
        }
        if let Some(v) = self.value {
            obj.insert(
                "value".to_string(),
                serde_json::Value::String(encode_quantity(v)),
            );
        }
        if let Some(v) = &self.data {
            obj.insert("data".to_string(), serde_json::Value::String(v.clone()));
        }
        serde_json::Value::Object(obj)
    }
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// The subset of `eth_getBlockByNumber`'s fields this crate needs.
#[derive(Debug, Clone, Deserialize)]
pub struct Block {
    #[serde(deserialize_with = "deserialize_quantity")]
    pub number: U256,
    pub hash: Option<String>,
    #[serde(deserialize_with = "deserialize_quantity")]
    pub timestamp: U256,
    #[serde(default, with = "quantity_opt")]
    pub base_fee_per_gas: Option<U256>,
    #[serde(default)]
    pub transactions: Vec<serde_json::Value>,
}

/// One entry from `eth_getLogs`.
#[derive(Debug, Clone, Deserialize)]
pub struct Log {
    pub address: String,
    pub topics: Vec<String>,
    /// Hex-encoded event data.
    pub data: String,
    #[serde(default, with = "quantity_opt")]
    pub block_number: Option<U256>,
    pub transaction_hash: Option<String>,
    #[serde(default, with = "quantity_opt")]
    pub log_index: Option<U256>,
    #[serde(default)]
    pub removed: bool,
}

/// `eth_getTransactionReceipt`'s result.
#[derive(Debug, Clone, Deserialize)]
pub struct TransactionReceipt {
    pub transaction_hash: String,
    #[serde(default, with = "quantity_opt")]
    pub block_number: Option<U256>,
    pub block_hash: Option<String>,
    /// `"0x1"` (success) / `"0x0"` (failure) on post-Byzantium chains; absent pre-Byzantium.
    #[serde(default, with = "quantity_opt")]
    pub status: Option<U256>,
    #[serde(deserialize_with = "deserialize_quantity")]
    pub gas_used: U256,
    pub contract_address: Option<String>,
    #[serde(default)]
    pub logs: Vec<Log>,
}

impl TransactionReceipt {
    /// `true` when `status` reports success (`0x1`). `false` for an on-chain revert *or* a
    /// pre-Byzantium chain with no `status` field — callers on such chains must inspect
    /// `gas_used` against the call's gas limit themselves.
    pub fn succeeded(&self) -> bool {
        self.status == Some(U256::ONE)
    }
}

/// `eth_feeHistory`'s result.
#[derive(Debug, Clone, Deserialize)]
pub struct FeeHistory {
    #[serde(deserialize_with = "deserialize_quantity")]
    pub oldest_block: U256,
    #[serde(default)]
    pub base_fee_per_gas: Vec<QuantityWire>,
    #[serde(default)]
    pub gas_used_ratio: Vec<f64>,
    #[serde(default)]
    pub reward: Vec<Vec<QuantityWire>>,
}

/// A `U256` that deserializes from the hex-quantity wire format, for use inside `Vec<_>`/nested
/// positions where `#[serde(with = "...")]` cannot be applied to the element type directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuantityWire(pub U256);

impl<'de> Deserialize<'de> for QuantityWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_quantity(deserializer).map(QuantityWire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // Hex quantity parsing edge cases.
    // ---------------------------------------------------------------------

    #[test]
    fn parses_zero() {
        assert_eq!(parse_quantity("0x0").unwrap(), U256::ZERO);
    }

    #[test]
    fn parses_value_above_u64_max() {
        // u64::MAX + 1, i.e. 2^64.
        let parsed = parse_quantity("0x10000000000000000").unwrap();
        assert_eq!(parsed, U256::from(u64::MAX) + U256::ONE);
    }

    #[test]
    fn parses_max_u256() {
        let max_hex = format!("0x{}", "f".repeat(64));
        assert_eq!(parse_quantity(&max_hex).unwrap(), U256::MAX);
    }

    #[test]
    fn rejects_missing_prefix() {
        assert!(matches!(parse_quantity("123"), Err(RpcError::Decode)));
    }

    #[test]
    fn rejects_empty_after_prefix() {
        assert!(matches!(parse_quantity("0x"), Err(RpcError::Decode)));
    }

    #[test]
    fn rejects_malformed_hex() {
        assert!(matches!(parse_quantity("0xzz"), Err(RpcError::Decode)));
        assert!(matches!(
            parse_quantity("not hex at all"),
            Err(RpcError::Decode)
        ));
        assert!(matches!(parse_quantity(""), Err(RpcError::Decode)));
    }

    #[test]
    fn rejects_value_wider_than_256_bits() {
        let too_wide = format!("0x{}", "1".repeat(65));
        assert!(matches!(parse_quantity(&too_wide), Err(RpcError::Decode)));
    }

    #[test]
    fn tolerates_non_minimal_leading_zeros() {
        // Not spec-minimal, but real-world endpoints occasionally send it; must not hard-fail.
        assert_eq!(parse_quantity("0x00").unwrap(), U256::ZERO);
        assert_eq!(parse_quantity("0x007b").unwrap(), U256::from(123u32));
    }

    #[test]
    fn encode_round_trips_through_parse() {
        for v in [U256::ZERO, U256::ONE, U256::from(u64::MAX), U256::MAX] {
            let encoded = encode_quantity(v);
            assert!(encoded.starts_with("0x"));
            assert_eq!(parse_quantity(&encoded).unwrap(), v);
        }
    }

    #[test]
    fn encode_is_minimal_length() {
        assert_eq!(encode_quantity(U256::ZERO), "0x0");
        assert_eq!(encode_quantity(U256::from(123u32)), "0x7b");
    }

    // ---------------------------------------------------------------------
    // JSON-RPC error classification.
    // ---------------------------------------------------------------------

    #[test]
    fn classifies_range_too_large_from_alchemy_style_message() {
        let err = JsonRpcErrorObj {
            code: -32602,
            message: "eth_getLogs is limited to a 2000 range".to_string(),
            data: None,
        };
        assert!(matches!(
            classify_json_rpc_error(err),
            RpcError::RangeTooLarge
        ));
    }

    #[test]
    fn classifies_range_too_large_from_infura_style_message() {
        let err = JsonRpcErrorObj {
            code: -32005,
            message: "query returned more than 10000 results".to_string(),
            data: None,
        };
        assert!(matches!(
            classify_json_rpc_error(err),
            RpcError::RangeTooLarge
        ));
    }

    #[test]
    fn classifies_revert_by_code() {
        let err = JsonRpcErrorObj {
            code: 3,
            message: "execution reverted: insufficient balance".to_string(),
            data: Some(serde_json::Value::String("0xdeadbeef".to_string())),
        };
        match classify_json_rpc_error(err) {
            RpcError::Revert { data } => assert_eq!(data.as_deref(), Some("0xdeadbeef")),
            other => panic!("expected Revert, got {other:?}"),
        }
    }

    #[test]
    fn classifies_generic_error_as_json_rpc() {
        let err = JsonRpcErrorObj {
            code: -32601,
            message: "method not found".to_string(),
            data: None,
        };
        match classify_json_rpc_error(err) {
            RpcError::JsonRpc { code, message } => {
                assert_eq!(code, -32601);
                assert_eq!(message, "method not found");
            }
            other => panic!("expected JsonRpc, got {other:?}"),
        }
    }

    #[test]
    fn optional_result_treats_null_as_none_not_decode_error() {
        let resp: JsonRpcResponse<TransactionReceipt> = JsonRpcResponse {
            result: None,
            error: None,
        };
        assert!(matches!(optional_result(resp), Ok(None)));
    }

    #[test]
    fn require_result_treats_missing_result_as_decode_error() {
        let resp: JsonRpcResponse<QuantityWire> = JsonRpcResponse {
            result: None,
            error: None,
        };
        assert!(matches!(require_result(resp), Err(RpcError::Decode)));
    }

    #[test]
    fn http_200_with_error_member_is_an_error_not_a_success() {
        // The exact trap the module docs warn about: a JSON-RPC error arrives inside a 200 OK
        // body. require_result/optional_result must surface it as Err regardless of `result`.
        let resp: JsonRpcResponse<QuantityWire> = JsonRpcResponse {
            result: Some(QuantityWire(U256::from(42u32))),
            error: Some(JsonRpcErrorObj {
                code: -32000,
                message: "boom".to_string(),
                data: None,
            }),
        };
        assert!(matches!(
            require_result(resp),
            Err(RpcError::JsonRpc { code: -32000, .. })
        ));
    }

    proptest::proptest! {
        #[test]
        fn quantity_round_trips_for_any_u256(hi in proptest::prelude::any::<u128>(), lo in proptest::prelude::any::<u128>()) {
            let v = (U256::from(hi) << 128) | U256::from(lo);
            let encoded = encode_quantity(v);
            proptest::prop_assert_eq!(parse_quantity(&encoded).unwrap(), v);
        }
    }
}
