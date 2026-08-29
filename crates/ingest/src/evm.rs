//! EVM deposit detection via ERC-20 Transfer logs.
//!
//! Scans `eth_getLogs` for registered ERC-20 token contracts with a block-number cursor,
//! advancing only after a log is durably processed so a crash resumes exactly-once — the
//! same guarantee the Horizon path gives via its paging-token cursor.
//!
//! # Security: contract address verification
//!
//! **The most important invariant in this module:** logs are matched on the *emitting contract
//! address* (`log.address`), not on topics alone. Any contract can emit a `Transfer` event with
//! arbitrary topics — including a deposit address in the `to` topic and a huge value in the data
//! field. Attributing on topics alone would let an attacker mint balances for free by deploying a
//! hostile contract that emits fake `Transfer` events.
//!
//! Before attributing a log, `EvmIngestor::process_log` verifies that `log.address` matches one
//! of the registered token contracts. If it does not, the log is `Skipped` regardless of its
//! topic contents.
//!
//! # Native ETH deposits
//!
//! Native ETH transfers emit **no logs**. They are only detectable by inspecting block
//! transactions (`eth_getBlockByNumber`) or via `debug_traceBlock`, both of which are
//! significantly more expensive than a targeted `eth_getLogs` filter. For v1, **native ETH
//! deposits are out of scope**. This worker detects ERC-20 stablecoin transfers only.
//!
//! This is an explicit, documented decision rather than a silent omission: a customer sending
//! ETH directly to their deposit address will not have it credited. Operators should communicate
//! this to their users, and the `docs/ingest-integration.md` documents it in the EVM section.
//!
//! # Unregistered tokens (quarantine)
//!
//! A `Transfer` to a known deposit address for a token that is not in the registry is recorded
//! with `address_id = NULL` rather than attributed or dropped. This preserves auditability while
//! preventing unregistered (potentially fee-on-transfer or rebasing) tokens from creating
//! spendable balances.
//!
//! # EVM deposit confirmation
//!
//! Deposits are recorded as `unconfirmed`. Crediting is gated on `#222`. Merging this worker
//! before `#222` lands must not create spendable balances — this is enforced at the DB level:
//! `Store::record_evm_deposit` always inserts `status = 'unconfirmed'`.

#![forbid(unsafe_code)]

use octo_store::{NewEvmDeposit, Store};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::time::Duration;
use uuid::Uuid;

use crate::Processed;

// ---------------------------------------------------------------------------
// Transfer(address,address,uint256) event signature.
// keccak256("Transfer(address,address,uint256)")
// ---------------------------------------------------------------------------
const TRANSFER_TOPIC: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

/// Maximum block range per `eth_getLogs` request before we start bisecting.
///
/// This is deliberately conservative. Different providers have different caps:
/// - Alchemy: 2 000 blocks
/// - Infura: 10 000 blocks
/// - Quicknode: varies
/// - Self-hosted Geth/Reth: unlimited but bounded by memory
///
/// We start at 2 000 to be safe across all providers and let the adaptive bisection grow or
/// shrink the range based on actual `RangeTooLarge` responses.
const DEFAULT_BLOCK_RANGE: u64 = 2_000;

/// Minimum block range after bisection. Below this the log scan cannot make progress.
const MIN_BLOCK_RANGE: u64 = 1;

/// Maximum consecutive `RangeTooLarge` bisections before returning an error rather than
/// spinning into an infinite loop.
const MAX_BISECTIONS: u32 = 16;

// ---------------------------------------------------------------------------
// JSON-RPC types
// ---------------------------------------------------------------------------

/// A JSON-RPC 2.0 log entry from `eth_getLogs`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmLog {
    /// The contract address that emitted this log (`0x`-prefixed, EIP-55 checksummed by
    /// well-behaved nodes, but may be all-lowercase from others — always compare
    /// case-insensitively).
    pub address: String,
    /// The transaction hash containing this log.
    pub transaction_hash: String,
    /// Topics: `[topic0, topic1, topic2, ...]`. For an ERC-20 `Transfer`:
    /// - `topics[0]` = `Transfer` signature hash
    /// - `topics[1]` = `from` address (left-padded to 32 bytes)
    /// - `topics[2]` = `to` address (left-padded to 32 bytes)
    pub topics: Vec<String>,
    /// ABI-encoded log data: for ERC-20 `Transfer`, this is the `uint256` value.
    pub data: String,
    /// The block number containing this log (`0x`-prefixed hex).
    pub block_number: String,
    /// Index of this log entry within the transaction (0-based, `0x`-prefixed hex).
    pub log_index: String,
    /// Whether the log was removed by a reorg. Logs with `removed: true` must be ignored.
    #[serde(default)]
    pub removed: bool,
}

impl EvmLog {
    /// The `to` address from an ERC-20 Transfer event's indexed `topics[2]`, normalised to a
    /// 20-byte (40-hex-char) lowercase address without `0x` prefix.
    ///
    /// EVM topics are left-padded to 32 bytes. An `address` topic looks like:
    /// `0x000000000000000000000000<20-byte-address>`.
    /// We strip the `0x` prefix and the 24 zero-padding characters, leaving the 40-char address,
    /// then normalise to lowercase.
    pub fn to_address(&self) -> Option<String> {
        let raw = self.topics.get(2)?.strip_prefix("0x")?;
        // 32 bytes = 64 hex chars; 24 of those are leading zeros for an address topic.
        if raw.len() != 64 {
            return None;
        }
        let addr = &raw[24..]; // last 40 chars = 20 bytes
        Some(format!("0x{}", addr.to_lowercase()))
    }

    /// The `from` address from `topics[1]`, same normalisation as `to_address`.
    pub fn from_address(&self) -> Option<String> {
        let raw = self.topics.get(1)?.strip_prefix("0x")?;
        if raw.len() != 64 {
            return None;
        }
        let addr = &raw[24..];
        Some(format!("0x{}", addr.to_lowercase()))
    }

    /// The transfer amount from `data` as an `i64`. ERC-20 amounts are `uint256`, but for
    /// practical deposit amounts (stablecoins, bounded by reasonable custodial limits) they
    /// fit in `i64`. Values that overflow are logged and skipped.
    ///
    /// `data` for an ERC-20 Transfer is the ABI-encoded `uint256`: 32 bytes = 64 hex chars,
    /// `0x`-prefixed.
    pub fn amount_i64(&self) -> Option<i64> {
        let hex = self.data.strip_prefix("0x")?;
        if hex.len() > 16 {
            // If the upper bytes are non-zero, the value exceeds u64::MAX. We skip those rather
            // than truncating silently — an overflow here would misattribute the amount.
            let upper = &hex[..hex.len().saturating_sub(16)];
            if upper.chars().any(|c| c != '0') {
                return None;
            }
        }
        let lower = &hex[hex.len().saturating_sub(16)..];
        let v = u64::from_str_radix(lower, 16).ok()?;
        i64::try_from(v).ok()
    }

    /// Block number as `u64`, parsed from `0x`-prefixed hex.
    pub fn block_number_u64(&self) -> Option<u64> {
        parse_hex_u64(&self.block_number)
    }

    /// Log index as `u32`, parsed from `0x`-prefixed hex.
    pub fn log_index_u32(&self) -> Option<u32> {
        parse_hex_u64(&self.log_index).and_then(|v| u32::try_from(v).ok())
    }
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let hex = s.strip_prefix("0x")?;
    u64::from_str_radix(hex, 16).ok()
}

// ---------------------------------------------------------------------------
// EVM JSON-RPC errors
// ---------------------------------------------------------------------------

/// Typed errors returned by the EVM JSON-RPC client.
#[derive(Debug, thiserror::Error)]
pub enum EvmRpcError {
    /// The requested block range is too large for this provider. The ingestor will bisect and
    /// retry.
    #[error("eth_getLogs block range too large (provider limit exceeded)")]
    RangeTooLarge,

    /// HTTP transport failure.
    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// JSON-RPC protocol-level error (HTTP 200 with an `error` member).
    #[error("JSON-RPC error {code}: {message}")]
    JsonRpc { code: i64, message: String },

    /// Unexpected response shape (missing fields, wrong types).
    #[error("unexpected RPC response: {0}")]
    UnexpectedResponse(String),
}

// ---------------------------------------------------------------------------
// Low-level RPC client
// ---------------------------------------------------------------------------

/// A minimal EVM JSON-RPC client using the workspace `reqwest`.
///
/// This is intentionally narrow — it covers only `eth_blockNumber` and `eth_getLogs`, the two
/// methods the ingest worker needs. A full client is the responsibility of `#218` (`octo-evm-rpc`).
///
/// **Security:** the RPC URL may contain an API key. It is never logged.
pub struct EvmRpcClient {
    client: Client,
    /// The EVM JSON-RPC endpoint URL. Never logged (may contain an API key).
    rpc_url: String,
}

impl EvmRpcClient {
    /// Create a new client. `rpc_url` is stored but never logged.
    pub fn new(rpc_url: impl Into<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            // Cap response bodies to 64 MiB so a malicious or malfunctioning RPC cannot OOM the
            // worker by returning an unbounded stream.
            .build()
            .expect("reqwest client build should not fail with valid config");
        Self {
            client,
            rpc_url: rpc_url.into(),
        }
    }

    /// Call any JSON-RPC method and return the `result` field as a raw `Value`.
    async fn call(&self, method: &str, params: Value) -> Result<Value, EvmRpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let resp = self
            .client
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;

        // JSON-RPC errors arrive as HTTP 200 with an `error` member — status-only checking
        // would treat every RPC-level failure as success.
        let json: Value = resp.json().await?;
        if let Some(err) = json.get("error") {
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
            let message = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown")
                .to_string();

            // Detect range-too-large by message heuristics (providers phrase this differently).
            let lower = message.to_lowercase();
            if lower.contains("range")
                || lower.contains("block range")
                || lower.contains("log response size")
                || lower.contains("too large")
                || lower.contains("too many blocks")
                || lower.contains("exceed")
                || lower.contains("limit")
            {
                return Err(EvmRpcError::RangeTooLarge);
            }

            return Err(EvmRpcError::JsonRpc { code, message });
        }

        json.get("result")
            .cloned()
            .ok_or_else(|| EvmRpcError::UnexpectedResponse("missing `result` field".into()))
    }

    /// `eth_blockNumber` — returns the latest block number.
    pub async fn block_number(&self) -> Result<u64, EvmRpcError> {
        let result = self.call("eth_blockNumber", json!([])).await?;
        let hex = result
            .as_str()
            .ok_or_else(|| EvmRpcError::UnexpectedResponse("eth_blockNumber not a string".into()))?;
        parse_hex_u64(hex).ok_or_else(|| {
            EvmRpcError::UnexpectedResponse(format!(
                "eth_blockNumber: could not parse hex block number '{hex}'"
            ))
        })
    }

    /// `eth_getLogs` filtered by the given block range and address list.
    ///
    /// Only returns `Transfer(address,address,uint256)` events (topic0 filter). Removed logs
    /// (from reorgs) are filtered out by the caller via `log.removed`.
    ///
    /// Returns `Err(EvmRpcError::RangeTooLarge)` when the provider rejects the range, which
    /// triggers adaptive bisection in the caller.
    pub async fn get_logs(
        &self,
        from_block: u64,
        to_block: u64,
        addresses: &[&str],
    ) -> Result<Vec<EvmLog>, EvmRpcError> {
        let result = self
            .call(
                "eth_getLogs",
                json!([{
                    "fromBlock": format!("0x{from_block:x}"),
                    "toBlock":   format!("0x{to_block:x}"),
                    "address":   addresses,
                    "topics":    [TRANSFER_TOPIC],
                }]),
            )
            .await?;

        let logs: Vec<EvmLog> = serde_json::from_value(result).map_err(|e| {
            EvmRpcError::UnexpectedResponse(format!("eth_getLogs deserialization failed: {e}"))
        })?;

        Ok(logs)
    }
}

// ---------------------------------------------------------------------------
// Registered token
// ---------------------------------------------------------------------------

/// A registered ERC-20 token that the ingestor will credit.
///
/// The registry is the defence against fee-on-transfer and rebasing tokens: only tokens
/// explicitly registered here are credited. The token contract address is the key used
/// to verify that a log was emitted by the correct contract.
#[derive(Debug, Clone)]
pub struct RegisteredToken {
    /// EIP-55 checksummed contract address. Comparisons are case-insensitive.
    pub contract_address: String,
    /// Ticker symbol (e.g. `"USDC"`, `"DAI"`).
    pub symbol: String,
    /// Decimal places (e.g. 6 for USDC, 18 for DAI). Stored for documentation; the ingestor
    /// does not interpret the value — it stores raw base units and lets the crediting layer
    /// (#222) handle human-readable conversion.
    pub decimals: u8,
}

// ---------------------------------------------------------------------------
// EvmIngestor
// ---------------------------------------------------------------------------

/// The EVM deposit ingest worker for one (wallet, chain) pair.
///
/// Mirrors `Ingestor`'s shape and contract:
/// - `poll_once`: scan one block range, process each log, advance the cursor.
/// - `process_log`: attribute and record one Transfer log (or skip/quarantine it).
/// - Returns `Processed` values that are the same variants as the Stellar path.
///
/// # Crash safety
///
/// The cursor advances **only after** a log is durably recorded in the database, matching the
/// guarantee documented in `crates/ingest/src/lib.rs`. A crash mid-batch resumes from the
/// last-committed block without missing or double-processing logs.
pub struct EvmIngestor {
    store: Store,
    rpc: EvmRpcClient,
    wallet_id: Uuid,
    /// CAIP-2 chain identifier (e.g. `"eip155:1"`, `"eip155:11155111"`).
    chain_id: String,
    /// Deposit addresses for this wallet on this chain (lowercase hex with `0x` prefix).
    /// Only Transfer events whose `to` topic matches one of these addresses are attributed.
    deposit_addresses: HashSet<String>,
    /// Registered token contracts. Only logs emitted by one of these contracts are processed.
    registered_tokens: Vec<RegisteredToken>,
    /// Maximum block range for `eth_getLogs`. Starts at `DEFAULT_BLOCK_RANGE` and may be
    /// bisected down if the provider returns `RangeTooLarge`.
    max_block_range: u64,
}

impl EvmIngestor {
    /// Create a new `EvmIngestor`.
    ///
    /// - `rpc_url`: the EVM JSON-RPC endpoint. May contain an API key — never logged.
    /// - `deposit_addresses`: hex addresses (case-insensitive) belonging to this wallet on this
    ///   chain.
    /// - `registered_tokens`: the token registry for this chain. Only tokens listed here are
    ///   credited; all others are quarantined.
    pub fn new(
        store: Store,
        rpc_url: impl Into<String>,
        wallet_id: Uuid,
        chain_id: impl Into<String>,
        deposit_addresses: impl IntoIterator<Item = String>,
        registered_tokens: Vec<RegisteredToken>,
    ) -> Self {
        Self {
            store,
            rpc: EvmRpcClient::new(rpc_url),
            wallet_id,
            chain_id: chain_id.into(),
            deposit_addresses: deposit_addresses
                .into_iter()
                .map(|a| a.to_lowercase())
                .collect(),
            registered_tokens,
            max_block_range: DEFAULT_BLOCK_RANGE,
        }
    }

    /// Poll once: scan the next block range for Transfer logs, process each, and persist the
    /// cursor. Returns the number of logs processed (including quarantined ones).
    ///
    /// Adaptively bisects the block range if the provider returns `RangeTooLarge`.
    pub async fn poll_once(&mut self) -> Result<usize, EvmIngestError> {
        let latest = self
            .rpc
            .block_number()
            .await
            .map_err(EvmIngestError::Rpc)?;

        let from = self
            .store
            .get_evm_cursor(self.wallet_id, &self.chain_id)
            .await
            .map_err(EvmIngestError::Store)?
            .map(|b| b + 1) // resume from the block after the last one we processed
            .unwrap_or(latest.saturating_sub(self.max_block_range));

        if from > latest {
            // Cursor is already at the tip; nothing to do.
            return Ok(0);
        }

        let contract_addrs: Vec<&str> = self
            .registered_tokens
            .iter()
            .map(|t| t.contract_address.as_str())
            .collect();

        // Adaptive bisection: if the provider returns RangeTooLarge, halve the range and retry.
        let mut range = (latest - from + 1).min(self.max_block_range);
        let mut bisections = 0;

        loop {
            let to = (from + range - 1).min(latest);

            let logs = match self.rpc.get_logs(from, to, &contract_addrs).await {
                Ok(logs) => logs,
                Err(EvmRpcError::RangeTooLarge) => {
                    bisections += 1;
                    if bisections > MAX_BISECTIONS {
                        return Err(EvmIngestError::RangeTooLargeExhausted { from, to });
                    }
                    range = (range / 2).max(MIN_BLOCK_RANGE);
                    tracing::debug!(
                        wallet = %self.wallet_id,
                        chain = %self.chain_id,
                        from,
                        to,
                        new_range = range,
                        "RangeTooLarge: bisecting block range"
                    );
                    continue;
                }
                Err(e) => return Err(EvmIngestError::Rpc(e)),
            };

            let count = self.process_range(from, to, logs).await?;
            return Ok(count);
        }
    }

    /// Process all logs in a fetched range, advancing the cursor block-by-block after each
    /// confirmed record.
    async fn process_range(
        &self,
        _from: u64,
        to: u64,
        logs: Vec<EvmLog>,
    ) -> Result<usize, EvmIngestError> {
        let mut count = 0;

        for log in &logs {
            // Reorged logs must never be processed — they represent a chain state that has been
            // superseded. A log with `removed: true` is a reorg reversal notification.
            if log.removed {
                tracing::debug!(
                    wallet = %self.wallet_id,
                    tx = %log.transaction_hash,
                    "skipping removed (reorged) log"
                );
                continue;
            }

            self.process_log(log).await?;
            count += 1;

            // Advance the cursor after each log so a crash resumes cleanly.
            // We use the log's own block number as the cursor, not `to`, so partial-block
            // progress is preserved on crash.
            if let Some(block_num) = log.block_number_u64() {
                self.store
                    .set_evm_cursor(self.wallet_id, &self.chain_id, block_num)
                    .await
                    .map_err(EvmIngestError::Store)?;
            }
        }

        // Even if there were no logs (or all were removed), advance the cursor to `to` so we
        // don't re-scan the same empty range on the next poll.
        if logs.is_empty() || logs.iter().all(|l| l.removed) {
            self.store
                .set_evm_cursor(self.wallet_id, &self.chain_id, to)
                .await
                .map_err(EvmIngestError::Store)?;
        }

        Ok(count)
    }

    /// Process one ERC-20 Transfer log.
    ///
    /// # Security: contract address verification
    ///
    /// This is the critical security check. We verify that `log.address` (the *emitting*
    /// contract) is a registered token contract **before** reading any topic. An attacker can
    /// deploy a contract that emits a Transfer event with any topics — a deposit address in
    /// `topics[2]` and a huge value in `data`. If we attributed on topics alone, that would
    /// credit the attacker's address. Checking `log.address` first prevents this.
    pub async fn process_log(&self, log: &EvmLog) -> Result<Processed, EvmIngestError> {
        // ----------------------------------------------------------------
        // Step 1: Verify the log was emitted by a registered token contract.
        //         This is the single most important security check in this module.
        // ----------------------------------------------------------------
        let token = self
            .registered_tokens
            .iter()
            .find(|t| t.contract_address.eq_ignore_ascii_case(&log.address));

        let token = match token {
            Some(t) => t,
            None => {
                // The log was emitted by an unregistered contract. Even if its topics look like a
                // Transfer to a deposit address, we must not credit it — doing so would let any
                // attacker mint balances by emitting fake Transfer events.
                tracing::debug!(
                    wallet = %self.wallet_id,
                    chain = %self.chain_id,
                    contract = %log.address,
                    "skipping Transfer from unregistered contract"
                );
                return Ok(Processed::Skipped);
            }
        };

        // ----------------------------------------------------------------
        // Step 2: Decode Transfer topics. topic0 must be the Transfer sig;
        //         topics[1] = from, topics[2] = to.
        // ----------------------------------------------------------------
        if log.topics.first().map(String::as_str) != Some(TRANSFER_TOPIC) {
            return Ok(Processed::Skipped);
        }

        let to_addr = match log.to_address() {
            Some(a) => a,
            None => {
                tracing::warn!(
                    tx = %log.transaction_hash,
                    "Transfer log missing valid `to` topic — skipping"
                );
                return Ok(Processed::Skipped);
            }
        };

        // ----------------------------------------------------------------
        // Step 3: Check whether `to` is one of our deposit addresses.
        //         Transfers to non-deposit addresses are irrelevant.
        // ----------------------------------------------------------------
        if !self.deposit_addresses.contains(&to_addr) {
            return Ok(Processed::Skipped);
        }

        // ----------------------------------------------------------------
        // Step 4: Decode the amount.
        // ----------------------------------------------------------------
        let amount = match log.amount_i64() {
            Some(a) if a > 0 => a,
            _ => {
                tracing::warn!(
                    tx = %log.transaction_hash,
                    data = %log.data,
                    "Transfer log has invalid or overflow amount — skipping"
                );
                return Ok(Processed::Skipped);
            }
        };

        let from_addr = log.from_address().unwrap_or_default();
        let tx_hash = &log.transaction_hash;
        let log_index = log.log_index_u32().unwrap_or(0);

        // ----------------------------------------------------------------
        // Step 5: Attribute to a customer address.
        // ----------------------------------------------------------------
        let address_row = self
            .store
            .evm_address_by_hex(self.wallet_id, &to_addr)
            .await
            .map_err(EvmIngestError::Store)?;

        let address_id = address_row.as_ref().map(|a| a.id);
        let attributed = address_id.is_some();

        // If the address is known but the token is registered, we record it.
        // (The contract check above already ensured the token is registered.)

        // ----------------------------------------------------------------
        // Step 6: Record idempotently. The (chain_id, tx_hash, log_index) unique index
        //         in the DB ensures replays are no-ops.
        // ----------------------------------------------------------------
        let dep = NewEvmDeposit {
            wallet_id: self.wallet_id,
            address_id,
            chain_id: &self.chain_id,
            token_symbol: &token.symbol,
            token_contract: &token.contract_address,
            amount_base_units: amount,
            from_address: &from_addr,
            to_address: &to_addr,
            tx_hash,
            log_index,
        };

        match self
            .store
            .record_evm_deposit(&dep)
            .await
            .map_err(EvmIngestError::Store)?
        {
            Some(_tx) => {
                tracing::debug!(
                    wallet = %self.wallet_id,
                    chain = %self.chain_id,
                    token = %token.symbol,
                    to = %to_addr,
                    amount,
                    attributed,
                    "EVM deposit recorded (unconfirmed)"
                );
                Ok(Processed::Recorded { attributed })
            }
            None => Ok(Processed::Duplicate),
        }
    }

    /// Run forever, polling every `interval`. Errors are logged and retried.
    pub async fn run(mut self, interval: Duration) {
        loop {
            match self.poll_once().await {
                Ok(n) if n > 0 => tracing::debug!(
                    wallet = %self.wallet_id,
                    chain = %self.chain_id,
                    processed = n,
                    "EVM ingest poll"
                ),
                Ok(_) => {}
                Err(e) => tracing::warn!(
                    wallet = %self.wallet_id,
                    chain = %self.chain_id,
                    error = ?e,
                    "EVM ingest poll failed; will retry"
                ),
            }
            let _ = self
                .store
                .mark_evm_polled(self.wallet_id, &self.chain_id)
                .await;
            tokio::time::sleep(interval).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the EVM ingest worker.
#[derive(Debug, thiserror::Error)]
pub enum EvmIngestError {
    #[error("store error: {0}")]
    Store(#[from] octo_store::StoreError),

    #[error("EVM RPC error: {0}")]
    Rpc(#[from] EvmRpcError),

    /// The block range was bisected down to `MIN_BLOCK_RANGE` and the provider still returned
    /// `RangeTooLarge`. This indicates a misconfigured provider or a very constrained endpoint.
    #[error("RangeTooLarge persisted after {MAX_BISECTIONS} bisections (from={from}, to={to})")]
    RangeTooLargeExhausted { from: u64, to: u64 },
}

// ---------------------------------------------------------------------------
// Unit tests (pure logic, no DB)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_log(
        address: &str,
        topic0: &str,
        topic1_from: &str,
        topic2_to: &str,
        data: &str,
        block: &str,
        log_index: &str,
    ) -> EvmLog {
        EvmLog {
            address: address.to_string(),
            transaction_hash: "0xabc".to_string(),
            topics: vec![
                topic0.to_string(),
                topic1_from.to_string(),
                topic2_to.to_string(),
            ],
            data: data.to_string(),
            block_number: block.to_string(),
            log_index: log_index.to_string(),
            removed: false,
        }
    }

    const TOKEN: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"; // USDC mainnet
    const DEPOSIT_ADDR: &str = "0xdeadbeef00000000000000000000000000000001";
    const RANDOM_ADDR: &str = "0x1234567890000000000000000000000000000002";

    /// Pad a 20-byte address to 32-byte topic format.
    fn as_topic(addr: &str) -> String {
        let hex = addr.strip_prefix("0x").unwrap_or(addr);
        format!("0x{:0>64}", hex)
    }

    /// Encode a u64 as a 32-byte ABI uint256 data field.
    fn as_data(value: u64) -> String {
        format!("0x{value:0>64x}")
    }

    #[test]
    fn to_address_extracts_correctly() {
        let log = make_log(
            TOKEN,
            TRANSFER_TOPIC,
            &as_topic(RANDOM_ADDR),
            &as_topic(DEPOSIT_ADDR),
            &as_data(1_000_000),
            "0x1",
            "0x0",
        );
        assert_eq!(
            log.to_address(),
            Some(format!("0x{}", DEPOSIT_ADDR.strip_prefix("0x").unwrap().to_lowercase()))
        );
    }

    #[test]
    fn from_address_extracts_correctly() {
        let log = make_log(
            TOKEN,
            TRANSFER_TOPIC,
            &as_topic(RANDOM_ADDR),
            &as_topic(DEPOSIT_ADDR),
            &as_data(1_000_000),
            "0x1",
            "0x0",
        );
        assert_eq!(
            log.from_address(),
            Some(format!("0x{}", RANDOM_ADDR.strip_prefix("0x").unwrap().to_lowercase()))
        );
    }

    #[test]
    fn amount_i64_parses_usdc_6_decimals() {
        // 1.000000 USDC = 1_000_000 base units
        let log = make_log(
            TOKEN,
            TRANSFER_TOPIC,
            &as_topic(RANDOM_ADDR),
            &as_topic(DEPOSIT_ADDR),
            &as_data(1_000_000),
            "0x1",
            "0x0",
        );
        assert_eq!(log.amount_i64(), Some(1_000_000));
    }

    #[test]
    fn amount_i64_parses_dai_18_decimals() {
        // 1.0 DAI = 1_000_000_000_000_000_000 base units (1e18)
        // This fits in i64 (max ~9.2e18)
        let amount: u64 = 1_000_000_000_000_000_000;
        let log = make_log(
            TOKEN,
            TRANSFER_TOPIC,
            &as_topic(RANDOM_ADDR),
            &as_topic(DEPOSIT_ADDR),
            &as_data(amount),
            "0x1",
            "0x0",
        );
        assert_eq!(log.amount_i64(), Some(amount as i64));
    }

    #[test]
    fn amount_i64_rejects_overflow() {
        // 10 ETH = 10_000_000_000_000_000_000 > i64::MAX (~9.22e18) — overflow
        let too_big: &str = "0x0000000000000000000000000000000000000000000000008ac7230489e80000";
        let log = EvmLog {
            address: TOKEN.to_string(),
            transaction_hash: "0xabc".to_string(),
            topics: vec![
                TRANSFER_TOPIC.to_string(),
                as_topic(RANDOM_ADDR),
                as_topic(DEPOSIT_ADDR),
            ],
            data: too_big.to_string(),
            block_number: "0x1".to_string(),
            log_index: "0x0".to_string(),
            removed: false,
        };
        assert_eq!(log.amount_i64(), None);
    }

    #[test]
    fn block_number_u64_parses_hex() {
        let log = make_log(
            TOKEN,
            TRANSFER_TOPIC,
            &as_topic(RANDOM_ADDR),
            &as_topic(DEPOSIT_ADDR),
            &as_data(1),
            "0x1a2b3c",
            "0x5",
        );
        assert_eq!(log.block_number_u64(), Some(0x1a2b3c));
        assert_eq!(log.log_index_u32(), Some(5));
    }

    #[test]
    fn removed_log_is_flagged() {
        let mut log = make_log(
            TOKEN,
            TRANSFER_TOPIC,
            &as_topic(RANDOM_ADDR),
            &as_topic(DEPOSIT_ADDR),
            &as_data(1),
            "0x1",
            "0x0",
        );
        log.removed = true;
        assert!(log.removed);
    }

    #[test]
    fn parse_hex_u64_handles_edge_cases() {
        assert_eq!(parse_hex_u64("0x0"), Some(0));
        assert_eq!(parse_hex_u64("0x1"), Some(1));
        assert_eq!(parse_hex_u64("0xffffffffffffffff"), Some(u64::MAX));
        assert_eq!(parse_hex_u64(""), None);
        assert_eq!(parse_hex_u64("0xgg"), None);
    }
}
