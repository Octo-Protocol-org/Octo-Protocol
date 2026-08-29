//! A typed JSON-RPC 2.0 client for EVM chains (`octo-evm-rpc`), the EVM counterpart of
//! `crates/ingest/src/horizon.rs` / `crates/api/src/horizon.rs`.
//!
//! # Submit asymmetry (AD-5)
//!
//! `eth_call`, `eth_getLogs`, `eth_blockNumber`, `eth_getTransactionReceipt`, and every other
//! read-only method go through retry-with-backoff and a circuit breaker
//! ([`octo_resilience::CallKind::ReadOnly`]). `eth_sendRawTransaction` does not — it is submitted
//! with [`octo_resilience::CallKind::Submit`], attempted exactly once, because a transport failure
//! on submission does not tell the caller whether the node already broadcast the transaction.
//! Retrying it risks double-submission. See [`client`]'s module docs and the header comment on
//! `crates/ingest/src/horizon.rs` for the full reasoning (this crate deliberately does not
//! duplicate it at length a third time).
//!
//! # JSON-RPC errors are a trap
//!
//! A JSON-RPC error arrives as HTTP `200 OK` with an `error` member in the body — not as an HTTP
//! error status. A client that only checks `resp.status().is_success()` will treat every
//! JSON-RPC-level failure (bad params, execution revert, method not found, ...) as a success and
//! hand the caller a meaningless `null`/absent result. [`types::require_result`] /
//! [`types::optional_result`] check the `error` member explicitly before ever consulting `result`.
//!
//! # Quantities are `U256`, never `u64`/`f64`
//!
//! Every numeric JSON-RPC field is a `0x`-prefixed hex string precisely because on-chain values
//! can exceed `u64::MAX` and JSON numbers cannot represent large integers exactly. This crate
//! parses every quantity into [`ethnum::U256`] — see [`types::parse_quantity`].
//!
//! # Security
//!
//! RPC URLs embed API keys (e.g. `.../v2/<secret>`). [`client::EvmRpcClient`]'s `Debug` impl
//! redacts the URL explicitly (not derived) so it can never leak through `{:?}`/`tracing`. Response
//! bodies are read under a hard size cap ([`client::DEFAULT_MAX_RESPONSE_BYTES`] by default) so a
//! malicious or compromised RPC endpoint cannot OOM the caller by returning an unbounded body.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod client;
mod error;
pub mod types;

pub use client::{EvmRpcClient, DEFAULT_MAX_RESPONSE_BYTES};
pub use error::RpcError;
pub use types::{
    encode_quantity, parse_quantity, Block, BlockTag, CallRequest, FeeHistory, Log, LogFilter,
    QuantityWire, TransactionReceipt,
};
