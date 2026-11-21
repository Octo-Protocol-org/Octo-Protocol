//! Minimal Horizon + friendbot client used by the API for funding and balance reads.
//!
//! # Resilience
//!
//! Read-only calls (`balances`, `account_sequence`) are wrapped with:
//! - **Retry-with-exponential-backoff** via [`octo_resilience::RetryPolicy`] — transient
//!   connection errors, timeouts, and 5xx responses are retried up to `max_attempts` times.
//! - **Circuit breaker** via [`octo_resilience::CircuitBreaker`] — after `failure_threshold`
//!   consecutive failures the circuit opens and calls return immediately with an internal error,
//!   preventing every concurrent request from queuing up its own timeout against an already-
//!   struggling Horizon instance.
//!
//! `submit_transaction` is deliberately excluded from automatic retry. See
//! [`octo_resilience`]'s module documentation for the full rationale; the short version is:
//! a network timeout on submission does NOT mean the transaction was rejected — it may have
//! already landed on-chain. Retrying would risk a double-submission. The caller must instead
//! query the ledger by hash to determine what actually happened.
//!
//! `friendbot_fund` runs with a separate small retry pass (friendbot is idempotent on testnet —
//! re-funding an already-funded account is a no-op).

use crate::error::ApiError;
use octo_resilience::{execute, CallKind, CircuitBreaker, ResilienceError, RetryPolicy};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Timeout for balance/sequence reads and friendbot funding — these are simple GETs against a
/// Horizon-like endpoint and should be fast; a hung connection here must not block a request
/// handler indefinitely.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// Signed-transaction submission may legitimately take longer than a simple read (Horizon can hold
/// the connection while the tx is validated/applied), so it gets a longer per-request override
/// instead of raising the client's default for every call.
const SUBMIT_TIMEOUT: Duration = Duration::from_secs(30);
/// Fee suggestions must not stall signing-info requests when Horizon's auxiliary endpoint is slow.
const FEE_STATS_TIMEOUT: Duration = Duration::from_secs(2);

/// A single balance line from a Horizon account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balance {
    /// Decimal string, e.g. "100.0000000".
    pub balance: String,
    /// "native" for XLM, else "credit_alphanum4" / "credit_alphanum12".
    pub asset_type: String,
    #[serde(default)]
    pub asset_code: Option<String>,
    #[serde(default)]
    pub asset_issuer: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AccountResponse {
    balances: Vec<Balance>,
    /// Account sequence number (Horizon returns it as a string).
    #[serde(default)]
    sequence: String,
    #[serde(default)]
    subentry_count: i64,
    #[serde(default)]
    num_sponsoring: i64,
    #[serde(default)]
    num_sponsored: i64,
}

#[derive(Debug, Deserialize)]
struct FeeStatsResponse {
    #[serde(default)]
    fee_charged: HashMap<String, serde_json::Value>,
}

/// Everything the withdrawal pre-flight checks need about the source account, fetched in a
/// single Horizon call (balances + sequence + reserve inputs).
#[derive(Debug, Clone)]
pub struct AccountInfo {
    pub balances: Vec<Balance>,
    pub sequence: i64,
    /// Number of subentries (trustlines, offers, data entries, signers) — drives the minimum
    /// reserve requirement alongside the 2 base entries every account carries.
    pub subentry_count: i64,
    pub num_sponsoring: i64,
    pub num_sponsored: i64,
}

/// The Stellar protocol's base reserve, in stroops. This is a network-wide ledger parameter that
/// has been stable at 0.5 XLM since the 2019 fee/reserve protocol upgrade; we hardcode it rather
/// than fetch `/ledgers` on every withdrawal (an extra Horizon round trip) since a live change
/// would be a rare, widely-announced network event.
pub const BASE_RESERVE_STROOPS: i64 = 5_000_000;

impl AccountInfo {
    /// Minimum native XLM balance this account must maintain, per the standard reserve formula:
    /// `base_reserve * (2 + subentry_count + num_sponsoring - num_sponsored)`.
    pub fn min_reserve_stroops(&self) -> i64 {
        let entries = 2 + self.subentry_count + self.num_sponsoring - self.num_sponsored;
        BASE_RESERVE_STROOPS * entries.max(0)
    }

    pub fn native_balance_stroops(&self) -> i64 {
        self.balances
            .iter()
            .find(|b| b.asset_type == "native")
            .and_then(|b| parse_amount_stroops(&b.balance))
            .unwrap_or(0)
    }

    /// Balance of a specific credit asset, or `None` if there is no trustline for it.
    pub fn asset_balance_stroops(&self, code: &str, issuer: &str) -> Option<i64> {
        self.balances
            .iter()
            .find(|b| {
                b.asset_code.as_deref() == Some(code) && b.asset_issuer.as_deref() == Some(issuer)
            })
            .and_then(|b| parse_amount_stroops(&b.balance))
    }
}

/// Whether `balances` (as returned for some account) includes a trustline for the given credit
/// asset. Pulled out of the withdrawal route so the matching rule is unit-testable without a
/// live Horizon call.
pub fn has_trustline(balances: &[Balance], code: &str, issuer: &str) -> bool {
    balances
        .iter()
        .any(|b| b.asset_code.as_deref() == Some(code) && b.asset_issuer.as_deref() == Some(issuer))
}

/// Parse a Horizon decimal amount string (e.g. `"100.0000000"`) into integer stroops without
/// going through floating point (avoids rounding error near balance/reserve boundaries).
fn parse_amount_stroops(s: &str) -> Option<i64> {
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    let whole: i64 = whole.parse().ok()?;
    let mut frac = frac.to_string();
    while frac.len() < 7 {
        frac.push('0');
    }
    frac.truncate(7);
    let frac: i64 = frac.parse().ok()?;
    Some(whole * 10_000_000 + frac)
}

/// How long a `/fee_stats` snapshot is reused (~2 ledgers), so estimate traffic can't hammer Horizon.
pub const FEE_STATS_TTL: Duration = Duration::from_secs(10);

/// Per-operation fee figures from Horizon `/fee_stats`, in stroops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FeeStats {
    /// The network minimum base fee per operation in the last closed ledger.
    pub last_ledger_base_fee: i64,
    /// Median per-operation fee actually charged over recent ledgers.
    pub fee_charged_p50: i64,
    /// 90th-percentile per-operation fee actually charged — what to bid to land promptly.
    pub fee_charged_p90: i64,
}

#[derive(Debug, Deserialize)]
struct FeeStatsResponse {
    last_ledger_base_fee: String,
    fee_charged: FeeDistribution,
}

#[derive(Debug, Deserialize)]
struct FeeDistribution {
    p50: String,
    p90: String,
}

impl FeeStatsResponse {
    /// Horizon reports every figure as a decimal string; any unparseable one is a bad response.
    fn parse(&self) -> Option<FeeStats> {
        Some(FeeStats {
            last_ledger_base_fee: self.last_ledger_base_fee.parse().ok()?,
            fee_charged_p50: self.fee_charged.p50.parse().ok()?,
            fee_charged_p90: self.fee_charged.p90.parse().ok()?,
        })
    }
}

/// A single value reused until `ttl` elapses. Time is passed in so expiry is unit-testable.
#[derive(Debug)]
pub(crate) struct TtlCache<T> {
    ttl: Duration,
    slot: Mutex<Option<(Instant, T)>>,
}

impl<T: Clone> TtlCache<T> {
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            slot: Mutex::new(None),
        }
    }

    /// The cached value if it was stored less than `ttl` before `now`.
    pub(crate) fn get(&self, now: Instant) -> Option<T> {
        let slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        match &*slot {
            Some((at, v)) if now.saturating_duration_since(*at) < self.ttl => Some(v.clone()),
            _ => None,
        }
    }

    pub(crate) fn put(&self, now: Instant, value: T) {
        *self.slot.lock().unwrap_or_else(|e| e.into_inner()) = Some((now, value));
    }
}

/// The result of submitting a transaction to Horizon.
#[derive(Debug, Clone)]
pub struct SubmitResult {
    pub hash: String,
    pub successful: bool,
    pub ledger: Option<i64>,
    /// Horizon result codes when the tx failed, e.g. `("tx_failed", ["op_low_reserve"])`.
    /// Empty on success or when Horizon didn't return them.
    pub transaction_code: Option<String>,
    pub operation_codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SubmitResponse {
    #[serde(default)]
    hash: String,
    #[serde(default)]
    successful: bool,
    #[serde(default)]
    ledger: Option<i64>,
    #[serde(default)]
    extras: Option<SubmitExtras>,
}

#[derive(Debug, Default, Deserialize)]
struct SubmitExtras {
    #[serde(default)]
    result_codes: Option<ResultCodes>,
}

#[derive(Debug, Default, Deserialize)]
struct ResultCodes {
    #[serde(default)]
    transaction: Option<String>,
    #[serde(default)]
    operations: Vec<String>,
}

/// The result of looking a transaction up by hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxLookup {
    /// Horizon has ingested the transaction; `successful` is its on-chain result.
    Found { successful: bool, ledger: Option<i64> },
    /// Horizon has no record of the hash (never submitted, expired, or not yet ingested).
    NotFound,
}

#[derive(Debug, Deserialize)]
struct TxRecord {
    #[serde(default)]
    successful: bool,
    #[serde(default)]
    ledger: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct LedgerPage {
    #[serde(rename = "_embedded")]
    embedded: LedgerRecords,
}

#[derive(Debug, Deserialize)]
struct LedgerRecords {
    records: Vec<LedgerRecord>,
}

#[derive(Debug, Deserialize)]
struct LedgerRecord {
    closed_at: String,
}

/// A thin Horizon client with retry/backoff and circuit-breaker protection.
///
/// The circuit breaker and retry policy are shared across all calls through this client instance
/// so failures on any call type count toward opening the circuit.
///
/// # Cloning
///
/// [`Horizon`] is `Clone`; clones share the **same** circuit-breaker state (via `Arc` inside
/// [`CircuitBreaker`]) so all clones participate in the same failure window.
#[derive(Clone)]
pub struct Horizon {
    http: reqwest::Client,
    base_url: String,
    circuit: CircuitBreaker,
    retry: RetryPolicy,
    /// Shared across clones, like the circuit breaker, so every handler reuses one snapshot.
    fee_stats_cache: Arc<TtlCache<FeeStats>>,
}

impl Horizon {
    /// Create a new client with default resilience settings.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_resilience(
            base_url,
            RetryPolicy::default(),
            CircuitBreaker::new(5, std::time::Duration::from_secs(30)),
        )
    }

    /// Create a client with explicit resilience configuration.
    /// Used by `bin/server` (to wire env-var config) and by tests (to inject tight thresholds).
    pub fn with_resilience(
        base_url: impl Into<String>,
        retry: RetryPolicy,
        circuit: CircuitBreaker,
    ) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(DEFAULT_TIMEOUT)
                .build()
                .unwrap_or_default(),
            base_url: base_url.into(),
            circuit,
            retry,
            fee_stats_cache: Arc::new(TtlCache::new(FEE_STATS_TTL)),
        }
    }

    /// Current network fee figures from `/fee_stats`, cached for [`FEE_STATS_TTL`]. Retried on
    /// transient failures; a failed fetch is not cached.
    #[tracing::instrument(
        name = "horizon_fee_stats",
        skip(self),
        fields(call_type = "fee_stats", outcome = tracing::field::Empty)
    )]
    pub async fn fee_stats(&self) -> Result<FeeStats, ApiError> {
        let span = tracing::Span::current();
        if let Some(stats) = self.fee_stats_cache.get(Instant::now()) {
            span.record("outcome", "cached");
            return Ok(stats);
        }
        let url = format!("{}/fee_stats", self.base_url.trim_end_matches('/'));
        let http = self.http.clone();
        let result = execute(&self.circuit, &self.retry, CallKind::ReadOnly, || {
            let url = url.clone();
            let http = http.clone();
            async move {
                let resp = http
                    .get(&url)
                    .send()
                    .await
                    .map_err(|_| FetchError::Transport)?;
                if resp.status().is_server_error() {
                    return Err(FetchError::Transport); // retriable
                }
                if !resp.status().is_success() {
                    return Err(FetchError::Permanent);
                }
                let body: FeeStatsResponse =
                    resp.json().await.map_err(|_| FetchError::Permanent)?;
                body.parse().ok_or(FetchError::Permanent)
            }
        })
        .await;

        match &result {
            Ok(_) => span.record("outcome", "success"),
            Err(ResilienceError::Circuit) => span.record("outcome", "circuit_open"),
            Err(ResilienceError::Exhausted(_)) => span.record("outcome", "failure"),
        };

        let stats = map_result(result)?;
        self.fee_stats_cache.put(Instant::now(), stats);
        Ok(stats)
    }

    /// Fetch an account's balances. Retried on transient failures (transport errors, 5xx).
    /// Returns `NotFound` if the account does not exist on-chain yet.
    #[tracing::instrument(
        name = "horizon_balances",
        skip(self),
        fields(call_type = "balances", account_g = %account_g, outcome = tracing::field::Empty)
    )]
    pub async fn balances(&self, account_g: &str) -> Result<Vec<Balance>, ApiError> {
        let span = tracing::Span::current();
        let url = format!(
            "{}/accounts/{}",
            self.base_url.trim_end_matches('/'),
            account_g
        );
        let http = self.http.clone();
        // Captured here, inside the instrumented span, so retries share one parent context.
        let trace = trace_headers();
        let result = execute(&self.circuit, &self.retry, CallKind::ReadOnly, || {
            let url = url.clone();
            let http = http.clone();
            let trace = trace.clone();
            async move {
                let resp = http
                    .get(&url)
                    .headers(trace)
                    .send()
                    .await
                    .map_err(|_| FetchError::Transport)?;

                if resp.status() == reqwest::StatusCode::NOT_FOUND {
                    return Err(FetchError::NotFound);
                }
                if resp.status().is_server_error() {
                    return Err(FetchError::Transport); // retriable
                }
                if !resp.status().is_success() {
                    return Err(FetchError::Permanent);
                }
                let account: AccountResponse =
                    resp.json().await.map_err(|_| FetchError::Permanent)?;
                Ok(account.balances)
            }
        })
        .await;

        match &result {
            Ok(_) => span.record("outcome", "success"),
            Err(ResilienceError::Circuit) => span.record("outcome", "circuit_open"),
            Err(ResilienceError::Exhausted(FetchError::NotFound)) => {
                span.record("outcome", "not_found")
            }
            Err(ResilienceError::Exhausted(_)) => span.record("outcome", "failure"),
        };

        map_result(result)
    }

    /// Fetch an account's current sequence number. Retried on transient failures.
    /// Returns `NotFound` if the account doesn't exist.
    #[tracing::instrument(
        name = "horizon_account_sequence",
        skip(self),
        fields(call_type = "account_sequence", account_g = %account_g, outcome = tracing::field::Empty)
    )]
    pub async fn account_sequence(&self, account_g: &str) -> Result<i64, ApiError> {
        let span = tracing::Span::current();
        let res = self.account_info(account_g).await.map(|a| a.sequence);
        match &res {
            Ok(_) => span.record("outcome", "success"),
            Err(ApiError::NotFound) => span.record("outcome", "not_found"),
            Err(_) => span.record("outcome", "failure"),
        };
        res
    }

    /// Fetch balances, sequence, and reserve inputs for an account in a single Horizon call.
    /// `NotFound` if the account does not exist on-chain yet.
    #[tracing::instrument(
        name = "horizon_account_info",
        skip(self),
        fields(call_type = "account_info", account_g = %account_g, outcome = tracing::field::Empty)
    )]
    pub async fn account_info(&self, account_g: &str) -> Result<AccountInfo, ApiError> {
        // This is a read-only call, so it goes through the same retry + circuit-breaker path as
        // `balances`. (It previously issued a bare, unwrapped GET, so a transient 5xx from
        // Horizon failed immediately instead of being retried.)
        let span = tracing::Span::current();
        let url = format!(
            "{}/accounts/{}",
            self.base_url.trim_end_matches('/'),
            account_g
        );
        let http = self.http.clone();
        // Captured here, inside the instrumented span, so retries share one parent context.
        let trace = trace_headers();

        let result = execute(&self.circuit, &self.retry, CallKind::ReadOnly, || {
            let url = url.clone();
            let http = http.clone();
            let trace = trace.clone();
            async move {
                let resp = http
                    .get(&url)
                    .headers(trace)
                    .send()
                    .await
                    .map_err(|_| FetchError::Transport)?;

                if resp.status() == reqwest::StatusCode::NOT_FOUND {
                    return Err(FetchError::NotFound);
                }
                if resp.status().is_server_error() {
                    return Err(FetchError::Transport); // retriable
                }
                if !resp.status().is_success() {
                    return Err(FetchError::Permanent);
                }

                let account: AccountResponse =
                    resp.json().await.map_err(|_| FetchError::Permanent)?;
                let sequence = account
                    .sequence
                    .parse::<i64>()
                    .map_err(|_| FetchError::Permanent)?;
                Ok(AccountInfo {
                    balances: account.balances,
                    sequence,
                    subentry_count: account.subentry_count,
                    num_sponsoring: account.num_sponsoring,
                    num_sponsored: account.num_sponsored,
                })
            }
        })
        .await;

        match &result {
            Ok(_) => span.record("outcome", "success"),
            Err(ResilienceError::Circuit) => span.record("outcome", "circuit_open"),
            Err(ResilienceError::Exhausted(FetchError::NotFound)) => {
                span.record("outcome", "not_found")
            }
            Err(ResilienceError::Exhausted(_)) => span.record("outcome", "failure"),
        };

        match result {
            Ok(info) => Ok(info),
            Err(ResilienceError::Circuit) => Err(ApiError::Internal),
            Err(ResilienceError::Exhausted(FetchError::NotFound)) => Err(ApiError::NotFound),
            Err(ResilienceError::Exhausted(_)) => Err(ApiError::Internal),
        }
    }

    /// Choose a per-operation fee from Horizon's configured percentile, bounded by `ceiling`.
    /// Missing, malformed, or unavailable fee stats fall back to the network base fee.
    pub async fn recommended_fee_stroops(
        &self,
        percentile: u8,
        base_fee_stroops: i64,
        ceiling_stroops: i64,
    ) -> i64 {
        debug_assert!(ceiling_stroops >= base_fee_stroops);
        let fee = self
            .fee_stats_percentile(percentile)
            .await
            .filter(|fee| *fee > 0)
            .unwrap_or(base_fee_stroops)
            .max(base_fee_stroops);
        fee.min(ceiling_stroops)
    }

    async fn fee_stats_percentile(&self, percentile: u8) -> Option<i64> {
        let key = format!("p{percentile}");
        let url = format!("{}/fee_stats", self.base_url.trim_end_matches('/'));
        let http = self.http.clone();
        tokio::time::timeout(FEE_STATS_TIMEOUT, async move {
            let response = http.get(url).send().await.ok()?;
            if !response.status().is_success() {
                return None;
            }
            let stats: FeeStatsResponse = response.json().await.ok()?;
            let value = stats.fee_charged.get(&key)?;
            value
                .as_str()
                .and_then(|raw| raw.parse::<i64>().ok())
                .or_else(|| value.as_i64())
        })
        .await
        .ok()
        .flatten()
    }

    /// Submit a signed transaction (base64 XDR envelope) to Horizon.
    ///
    /// **Not retried** — see the module-level documentation and [`octo_resilience`] for the full
    /// rationale. TL;DR: a transport timeout does not mean the tx was rejected; it may have
    /// already landed on-chain, so a retry risks double-submission. The circuit breaker still
    /// applies: if Horizon is clearly down we fail fast rather than queuing up timeouts.
    ///
    /// Returns the result even when the transaction failed on-chain (`successful == false`) so the
    /// caller can record the failure; only transport/HTTP errors return `Err`.
    #[tracing::instrument(
        name = "horizon_submit_transaction",
        skip(self, envelope_xdr),
        fields(call_type = "submit", outcome = tracing::field::Empty)
    )]
    pub async fn submit_transaction(&self, envelope_xdr: &str) -> Result<SubmitResult, ApiError> {
        // NOTE: an eager, unwrapped POST used to sit here ahead of the resilience-wrapped call
        // below. It fired a *duplicate* submission on every call and referenced `http`/`xdr`
        // locals that were never bound (so this did not compile). Removed — the single submit
        // now happens inside `execute`, with SUBMIT_TIMEOUT applied to that request.
        let span = tracing::Span::current();
        let url = format!("{}/transactions", self.base_url.trim_end_matches('/'));
        let http = self.http.clone();
        // Captured here, inside the instrumented span, so retries share one parent context.
        let trace = trace_headers();
        let xdr = envelope_xdr.to_string();

        let result = execute(&self.circuit, &self.retry, CallKind::Submit, || {
            let url = url.clone();
            let http = http.clone();
            let trace = trace.clone();
            let xdr = xdr.clone();
            async move {
                let resp = http
                    .post(&url)
                    .headers(trace)
                    .form(&[("tx", &xdr)])
                    .timeout(SUBMIT_TIMEOUT)
                    .send()
                    .await
                    .map_err(|_| FetchError::Transport)?;

                // Horizon returns 400 with a problem document when the tx is rejected (e.g. bad
                // seq, no reserve). Parse it either way so we can surface the specific result
                // codes — with client-signed transactions the caller needs to know *why* it
                // failed in order to correct and re-sign.
                let status = resp.status();
                let body: SubmitResponse = match resp.json().await {
                    Ok(b) => b,
                    Err(_) => {
                        if status.is_success() {
                            return Err(FetchError::Transport);
                        }
                        return Err(FetchError::TxRejected);
                    }
                };
                let (transaction_code, operation_codes) = body
                    .extras
                    .and_then(|e| e.result_codes)
                    .map(|rc| (rc.transaction, rc.operations))
                    .unwrap_or((None, Vec::new()));
                Ok(SubmitResult {
                    hash: body.hash,
                    successful: body.successful,
                    ledger: body.ledger,
                    transaction_code,
                    operation_codes,
                })
            }
        })
        .await;

        match &result {
            Ok(r) => {
                if r.successful {
                    span.record("outcome", "success");
                } else {
                    span.record("outcome", "tx_failed");
                }
            }
            Err(ResilienceError::Circuit) => span.record("outcome", "circuit_open"),
            Err(ResilienceError::Exhausted(FetchError::TxRejected)) => {
                span.record("outcome", "rejected")
            }
            Err(ResilienceError::Exhausted(_)) => span.record("outcome", "failure"),
        };

        match result {
            Ok(r) => Ok(r),
            Err(ResilienceError::Circuit) => Err(ApiError::Internal),
            Err(ResilienceError::Exhausted(FetchError::TxRejected)) => Err(ApiError::BadRequest(
                "transaction rejected by network".into(),
            )),
            Err(ResilienceError::Exhausted(_)) => Err(ApiError::Internal),
        }
    }

    /// Look a transaction up by its hash. Retried on transient failures; a 404 is a settled
    /// `NotFound` answer, not an error. This is the "query the ledger" path that
    /// [`octo_resilience`] prescribes after an ambiguous submit.
    pub async fn transaction_by_hash(&self, hash: &str) -> Result<TxLookup, ApiError> {
        // The hash is interpolated into a URL path; only a 32-byte hex digest is acceptable.
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ApiError::BadRequest("transaction hash is malformed".into()));
        }
        let url = format!(
            "{}/transactions/{}",
            self.base_url.trim_end_matches('/'),
            hash
        );
        let http = self.http.clone();
        let result = execute(&self.circuit, &self.retry, CallKind::ReadOnly, || {
            let (url, http) = (url.clone(), http.clone());
            async move {
                let resp = http.get(&url).send().await.map_err(|_| FetchError::Transport)?;
                if resp.status() == reqwest::StatusCode::NOT_FOUND {
                    return Err(FetchError::NotFound);
                }
                if resp.status().is_server_error() {
                    return Err(FetchError::Transport);
                }
                if !resp.status().is_success() {
                    return Err(FetchError::Permanent);
                }
                resp.json::<TxRecord>().await.map_err(|_| FetchError::Permanent)
            }
        })
        .await;
        match result {
            Ok(r) => Ok(TxLookup::Found {
                successful: r.successful,
                ledger: r.ledger,
            }),
            Err(ResilienceError::Exhausted(FetchError::NotFound)) => Ok(TxLookup::NotFound),
            Err(_) => Err(ApiError::Internal),
        }
    }

    /// Close time (unix seconds) of Horizon's newest ingested ledger. A transaction missing from
    /// Horizon whose `max_time` precedes this can never be applied.
    pub async fn latest_ledger_close_time(&self) -> Result<i64, ApiError> {
        let url = format!(
            "{}/ledgers?order=desc&limit=1",
            self.base_url.trim_end_matches('/')
        );
        let http = self.http.clone();
        let result = execute(&self.circuit, &self.retry, CallKind::ReadOnly, || {
            let (url, http) = (url.clone(), http.clone());
            async move {
                let resp = http.get(&url).send().await.map_err(|_| FetchError::Transport)?;
                if resp.status().is_server_error() {
                    return Err(FetchError::Transport);
                }
                if !resp.status().is_success() {
                    return Err(FetchError::Permanent);
                }
                let page: LedgerPage = resp.json().await.map_err(|_| FetchError::Permanent)?;
                let closed_at = page.embedded.records.first().ok_or(FetchError::Permanent)?;
                chrono::DateTime::parse_from_rfc3339(&closed_at.closed_at)
                    .map(|t| t.timestamp())
                    .map_err(|_| FetchError::Permanent)
            }
        })
        .await;
        map_result(result)
    }

    // Probe Horizon root endpoint to verify node reachability.
    pub async fn check_reachability(&self) -> Result<(), String> {
        let url = self.base_url.trim_end_matches('/');
        let resp = self
            .http
            .get(url)
            .headers(trace_headers())
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .map_err(|e| format!("horizon unreachable: {e}"))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("horizon returned HTTP {}", resp.status()))
        }
    }
}

/// Trace-context headers for the current span; empty unless trace export is enabled.
fn trace_headers() -> reqwest::header::HeaderMap {
    octo_resilience::trace_headers()
        .into_iter()
        .filter_map(|(k, v)| {
            let name = reqwest::header::HeaderName::from_bytes(k.as_bytes()).ok()?;
            Some((name, reqwest::header::HeaderValue::from_str(&v).ok()?))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Internal fetch-error type
// ---------------------------------------------------------------------------

/// Errors from inside retry closures. `Transport` = transient (retriable on read-only calls);
/// others are permanent.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FetchError {
    /// Network error, timeout, or 5xx — transient.
    Transport,
    /// Horizon returned 404 — account not found. Permanent.
    NotFound,
    /// Any other non-success status. Permanent.
    Permanent,
    /// `POST /transactions` returned no parseable hash — tx rejected. Permanent.
    TxRejected,
}

impl octo_resilience::Retriable for FetchError {
    fn is_retriable(&self) -> bool {
        // Only transport-level failures (network error, timeout, 5xx) are worth another attempt.
        // 404 / other 4xx / a rejected tx are settled answers — retrying them would also let a
        // few of them trip the circuit breaker and mask the real error.
        matches!(self, FetchError::Transport)
    }
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport => write!(f, "transport error"),
            Self::NotFound => write!(f, "account not found"),
            Self::Permanent => write!(f, "permanent error"),
            Self::TxRejected => write!(f, "transaction rejected"),
        }
    }
}

/// Map a resilience `Result` (read-only calls) to an `ApiError`.
fn map_result<T>(r: Result<T, ResilienceError<FetchError>>) -> Result<T, ApiError> {
    match r {
        Ok(v) => Ok(v),
        Err(ResilienceError::Circuit) => Err(ApiError::Internal),
        Err(ResilienceError::Exhausted(FetchError::NotFound)) => Err(ApiError::NotFound),
        Err(ResilienceError::Exhausted(_)) => Err(ApiError::Internal),
    }
}

// ---------------------------------------------------------------------------
// Friendbot
// ---------------------------------------------------------------------------

/// Fund a testnet account via friendbot. Best-effort; a single retry is safe because friendbot
/// is idempotent (re-funding an already-funded account is a no-op on testnet).
#[tracing::instrument(
    name = "horizon_friendbot_fund",
    skip(friendbot_url),
    fields(call_type = "friendbot", account_g = %account_g, outcome = tracing::field::Empty)
)]
pub async fn friendbot_fund(friendbot_url: &str, account_g: &str) -> Result<(), ApiError> {
    let span = tracing::Span::current();
    let res = friendbot_fund_with_timeout(friendbot_url, account_g, DEFAULT_TIMEOUT).await;
    match &res {
        Ok(_) => span.record("outcome", "success"),
        Err(_) => span.record("outcome", "failure"),
    };
    res
}

async fn friendbot_fund_with_timeout(
    friendbot_url: &str,
    account_g: &str,
    timeout: Duration,
) -> Result<(), ApiError> {
    let url = format!(
        "{}/?addr={}",
        friendbot_url.trim_end_matches('/'),
        account_g
    );
    let resp = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .unwrap_or_default()
        .get(&url)
        .send()
        .await
        .map_err(|_| ApiError::Internal)?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(ApiError::Internal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Binds an ephemeral listener that accepts a connection and then holds it open forever
    /// without reading or writing, so callers get no response and only the client's own timeout
    /// ends the request. Returns the base URL to hit.
    async fn hanging_server() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((_socket, _)) = listener.accept().await {
                std::future::pending::<()>().await;
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn horizon_client_times_out_and_maps_to_internal_error() {
        let base_url = hanging_server().await;
        let horizon = Horizon {
            http: reqwest::Client::builder()
                .timeout(Duration::from_millis(200))
                .build()
                .unwrap(),
            base_url,
            // This test exercises the transport timeout, so keep resilience out of the way:
            // a single attempt and a breaker that won't trip within the test.
            retry: RetryPolicy {
                max_attempts: 1,
                ..Default::default()
            },
            circuit: CircuitBreaker::new(u32::MAX, Duration::from_secs(60)),
            fee_stats_cache: Arc::new(TtlCache::new(FEE_STATS_TTL)),
        };

        let result = horizon.balances("GABCDEFGHIJKLMNOPQRSTUVWXYZ").await;
        assert!(matches!(result, Err(ApiError::Internal)));
    }

    #[tokio::test]
    async fn friendbot_fund_times_out_and_returns_an_error() {
        let base_url = hanging_server().await;

        let result = friendbot_fund_with_timeout(
            &base_url,
            "GABCDEFGHIJKLMNOPQRSTUVWXYZ",
            Duration::from_millis(200),
        )
        .await;

        assert!(matches!(result, Err(ApiError::Internal)));
    }

    // Asserts that every Horizon call type emits its distinct named tracing span.
    #[tokio::test]
    async fn horizon_calls_emit_named_tracing_spans() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::layer::SubscriberExt;

        let recorded_spans = Arc::new(Mutex::new(Vec::<String>::new()));
        let spans_clone = recorded_spans.clone();

        struct SpanRecorder(Arc<Mutex<Vec<String>>>);
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpanRecorder {
            fn on_new_span(
                &self,
                attrs: &tracing::span::Attributes<'_>,
                _id: &tracing::span::Id,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                self.0.lock().unwrap().push(attrs.metadata().name().to_string());
            }
        }

        let subscriber = tracing_subscriber::registry().with(SpanRecorder(spans_clone));
        let _guard = tracing::subscriber::set_default(subscriber);

        let base_url = hanging_server().await;
        let horizon = Horizon {
            http: reqwest::Client::builder()
                .timeout(Duration::from_millis(50))
                .build()
                .unwrap(),
            base_url: base_url.clone(),
            retry: RetryPolicy {
                max_attempts: 1,
                ..Default::default()
            },
            circuit: CircuitBreaker::new(u32::MAX, Duration::from_secs(60)),
            fee_stats_cache: Arc::new(TtlCache::new(FEE_STATS_TTL)),
        };

        let _ = horizon.balances("GABCDEFGHIJKLMNOPQRSTUVWXYZ").await;
        let _ = horizon.account_sequence("GABCDEFGHIJKLMNOPQRSTUVWXYZ").await;
        let _ = horizon.submit_transaction("AAAA").await;
        let _ = friendbot_fund("http://127.0.0.1:1", "GABCDEFGHIJKLMNOPQRSTUVWXYZ").await;

        let spans = recorded_spans.lock().unwrap().clone();
        assert!(spans.contains(&"horizon_balances".to_string()));
        assert!(spans.contains(&"horizon_account_sequence".to_string()));
        assert!(spans.contains(&"horizon_account_info".to_string()));
        assert!(spans.contains(&"horizon_submit_transaction".to_string()));
        assert!(spans.contains(&"horizon_friendbot_fund".to_string()));
    }

    #[test]
    fn ttl_cache_serves_until_expiry_then_misses() {
        let cache = TtlCache::new(Duration::from_secs(10));
        let t0 = Instant::now();
        assert_eq!(cache.get(t0), None);
        cache.put(t0, 7);
        assert_eq!(cache.get(t0), Some(7));
        assert_eq!(cache.get(t0 + Duration::from_millis(9_999)), Some(7));
        // Exactly at the TTL the snapshot is stale.
        assert_eq!(cache.get(t0 + Duration::from_secs(10)), None);
        // A refresh restarts the window.
        let t1 = t0 + Duration::from_secs(11);
        cache.put(t1, 8);
        assert_eq!(cache.get(t1 + Duration::from_secs(5)), Some(8));
    }

    #[test]
    fn fee_stats_response_parses_horizon_strings() {
        let body = r#"{"last_ledger_base_fee":"100","ledger_capacity_usage":"0.97",
            "fee_charged":{"max":"5000","min":"100","mode":"100","p10":"100","p50":"120",
            "p90":"900","p99":"5000"}}"#;
        let parsed: FeeStatsResponse = serde_json::from_str(body).unwrap();
        assert_eq!(
            parsed.parse(),
            Some(FeeStats {
                last_ledger_base_fee: 100,
                fee_charged_p50: 120,
                fee_charged_p90: 900,
            })
        );
    }

    #[tokio::test]
    async fn fee_stats_are_cached_between_calls() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/fee_stats"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "last_ledger_base_fee": "100",
                "fee_charged": { "p50": "100", "p90": "250" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let horizon = Horizon::new(server.uri());
        let first = horizon.fee_stats().await.unwrap();
        let second = horizon.clone().fee_stats().await.unwrap();
        assert_eq!(first, second);
        assert_eq!(first.fee_charged_p90, 250);
        // `expect(1)` is verified when the mock server drops: the clone hit the shared cache.
    }
}
