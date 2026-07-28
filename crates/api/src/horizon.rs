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
use std::time::Duration;

/// Timeout for balance/sequence reads and friendbot funding — these are simple GETs against a
/// Horizon-like endpoint and should be fast; a hung connection here must not block a request
/// handler indefinitely.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// Signed-transaction submission may legitimately take longer than a simple read (Horizon can hold
/// the connection while the tx is validated/applied), so it gets a longer per-request override
/// instead of raising the client's default for every call.
const SUBMIT_TIMEOUT: Duration = Duration::from_secs(30);

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
///
/// Delegates to the shared `wallet-core` helper rather than re-deriving the digit-by-digit
/// parse: that implementation uses checked arithmetic (an absurdly large balance string yields
/// `None` instead of overflowing) and rejects negatives and over-precise input outright. Every
/// caller here treats `None` as "no usable balance", so malformed input fails closed into a
/// rejected withdrawal rather than a bogus stroops figure.
fn parse_amount_stroops(s: &str) -> Option<i64> {
    octo_wallet_core::amount::to_stroops(s)
}

/// The result of submitting a transaction to Horizon.
#[derive(Debug, Clone)]
pub struct SubmitResult {
    pub hash: String,
    pub successful: bool,
    pub ledger: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct SubmitResponse {
    hash: String,
    #[serde(default)]
    successful: bool,
    #[serde(default)]
    ledger: Option<i64>,
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
        }
    }

    /// Fetch an account's balances. Retried on transient failures (transport errors, 5xx).
    /// Returns `NotFound` if the account does not exist on-chain yet.
    pub async fn balances(&self, account_g: &str) -> Result<Vec<Balance>, ApiError> {
        let url = format!(
            "{}/accounts/{}",
            self.base_url.trim_end_matches('/'),
            account_g
        );
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

        map_result(result)
    }

    /// Fetch an account's current sequence number. Retried on transient failures.
    /// Returns `NotFound` if the account doesn't exist.
    pub async fn account_sequence(&self, account_g: &str) -> Result<i64, ApiError> {
        self.account_info(account_g).await.map(|a| a.sequence)
    }

    /// Fetch balances, sequence, and reserve inputs for an account in a single Horizon call.
    /// `NotFound` if the account does not exist on-chain yet.
    pub async fn account_info(&self, account_g: &str) -> Result<AccountInfo, ApiError> {
        let url = format!(
            "{}/accounts/{}",
            self.base_url.trim_end_matches('/'),
            account_g
        );
        let http = self.http.clone();
        // Retried on transient 5xx/transport failures under the same circuit breaker as
        // `balances` — the withdrawal pre-flight depends on this call, so a blip on the way to
        // fetching balances/sequence shouldn't fail the whole withdrawal on the first try.
        let result = execute(&self.circuit, &self.retry, CallKind::ReadOnly, || {
            let url = url.clone();
            let http = http.clone();
            async move {
                let resp = http
                    .get(&url)
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

        map_result(result)
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
    pub async fn submit_transaction(&self, envelope_xdr: &str) -> Result<SubmitResult, ApiError> {
        let url = format!("{}/transactions", self.base_url.trim_end_matches('/'));
        let http = self.http.clone();
        let xdr = envelope_xdr.to_string();

        let result = execute(&self.circuit, &self.retry, CallKind::Submit, || {
            let url = url.clone();
            let http = http.clone();
            let xdr = xdr.clone();
            async move {
                let resp = http
                    .post(&url)
                    .form(&[("tx", &xdr)])
                    .timeout(SUBMIT_TIMEOUT)
                    .send()
                    .await
                    .map_err(|_| FetchError::Transport)?;

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
                Ok(SubmitResult {
                    hash: body.hash,
                    successful: body.successful,
                    ledger: body.ledger,
                })
            }
        })
        .await;

        match result {
            Ok(r) => Ok(r),
            Err(ResilienceError::Circuit) => Err(ApiError::Internal),
            Err(ResilienceError::Exhausted(FetchError::TxRejected)) => Err(ApiError::BadRequest(
                "transaction rejected by network".into(),
            )),
            Err(ResilienceError::Exhausted(_)) => Err(ApiError::Internal),
        }
    }
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

impl octo_resilience::Retriable for FetchError {
    fn is_retriable(&self) -> bool {
        // Only transient transport/5xx failures are worth retrying. A 404, an unparseable body,
        // or a network-rejected transaction are definitive answers — retrying them (and counting
        // them as circuit failures) would spuriously open the breaker.
        matches!(self, FetchError::Transport)
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
pub async fn friendbot_fund(friendbot_url: &str, account_g: &str) -> Result<(), ApiError> {
    friendbot_fund_with_timeout(friendbot_url, account_g, DEFAULT_TIMEOUT).await
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

    fn balance(
        asset_type: &str,
        code: Option<&str>,
        issuer: Option<&str>,
        amount: &str,
    ) -> Balance {
        Balance {
            asset_type: asset_type.to_string(),
            asset_code: code.map(|c| c.to_string()),
            asset_issuer: issuer.map(|i| i.to_string()),
            balance: amount.to_string(),
        }
    }

    fn account_with(balances: Vec<Balance>) -> AccountInfo {
        AccountInfo {
            balances,
            sequence: 1,
            subentry_count: 0,
            num_sponsoring: 0,
            num_sponsored: 0,
        }
    }

    /// A balance string large enough to overflow `whole * 10_000_000` must yield "no usable
    /// balance" rather than overflowing. The pre-flight check reads this as a zero balance and
    /// rejects the withdrawal, which is the safe direction.
    #[test]
    fn absurd_balance_string_fails_closed_instead_of_overflowing() {
        let acct = account_with(vec![balance("native", None, None, "922337203685477.5808")]);
        assert_eq!(acct.native_balance_stroops(), 0);
    }

    /// Horizon should never report a negative balance, but if it does it must not parse into a
    /// plausible-looking positive-ish figure the reserve arithmetic would then trust.
    #[test]
    fn negative_balance_string_fails_closed() {
        let acct = account_with(vec![balance("native", None, None, "-1.5000000")]);
        assert_eq!(acct.native_balance_stroops(), 0);
    }

    /// Over-precise input is rejected outright rather than silently truncated to 7 decimals.
    #[test]
    fn over_precise_balance_string_fails_closed() {
        let acct = account_with(vec![balance("native", None, None, "1.23456789")]);
        assert_eq!(acct.native_balance_stroops(), 0);
    }

    #[test]
    fn well_formed_balances_still_parse() {
        let acct = account_with(vec![
            balance("native", None, None, "100.0000000"),
            balance("credit_alphanum4", Some("USDC"), Some("GISSUER"), "42.5"),
        ]);
        assert_eq!(acct.native_balance_stroops(), 1_000_000_000);
        assert_eq!(
            acct.asset_balance_stroops("USDC", "GISSUER"),
            Some(425_000_000)
        );
        assert_eq!(acct.asset_balance_stroops("USDC", "GOTHER"), None);
    }

    /// The reserve formula: 2 base entries + subentries, at 0.5 XLM each.
    #[test]
    fn min_reserve_tracks_subentry_count() {
        let mut acct = account_with(vec![]);
        assert_eq!(acct.min_reserve_stroops(), 10_000_000);
        acct.subentry_count = 2;
        assert_eq!(acct.min_reserve_stroops(), 20_000_000);
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
            // A single attempt + fresh breaker keeps this timeout test fast and focused on the
            // transport-timeout -> ApiError::Internal mapping (no retry/backoff involved).
            circuit: CircuitBreaker::new(5, Duration::from_secs(30)),
            retry: RetryPolicy {
                max_attempts: 1,
                base_delay_ms: 0,
                max_delay_ms: 0,
                multiplier: 1.0,
                jitter_factor: 0.0,
            },
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
}
