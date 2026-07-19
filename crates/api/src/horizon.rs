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
            .find(|b| b.asset_code.as_deref() == Some(code) && b.asset_issuer.as_deref() == Some(issuer))
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
            http: reqwest::Client::new(),
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
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|_| ApiError::Internal)?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(ApiError::NotFound);
        }
        if !resp.status().is_success() {
            return Err(ApiError::Internal);
        }
        let account: AccountResponse = resp.json().await.map_err(|_| ApiError::Internal)?;
        let sequence = account
            .sequence
            .parse::<i64>()
            .map_err(|_| ApiError::Internal)?;
        Ok(AccountInfo {
            balances: account.balances,
            sequence,
            subentry_count: account.subentry_count,
            num_sponsoring: account.num_sponsoring,
            num_sponsored: account.num_sponsored,
        })
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
            Err(ResilienceError::Exhausted(FetchError::TxRejected)) => {
                Err(ApiError::BadRequest("transaction rejected by network".into()))
            }
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
    let url = format!(
        "{}/?addr={}",
        friendbot_url.trim_end_matches('/'),
        account_g
    );
    let policy = RetryPolicy {
        max_attempts: 2,
        base_delay_ms: 500,
        max_delay_ms: 1_000,
        ..Default::default()
    };
    // Friendbot uses its own isolated circuit breaker so friendbot failures don't bleed
    // into the main Horizon circuit.
    let circuit = CircuitBreaker::new(3, std::time::Duration::from_secs(30));
    let http = reqwest::Client::new();

    let result = execute(&circuit, &policy, CallKind::ReadOnly, || {
        let url = url.clone();
        let http = http.clone();
        async move {
            let resp = http
                .get(&url)
                .send()
                .await
                .map_err(|_| FetchError::Transport)?;
            if resp.status().is_success() {
                Ok(())
            } else if resp.status().is_server_error() {
                Err(FetchError::Transport)
            } else {
                Err(FetchError::Permanent)
            }
        }
    })
    .await;

    match result {
        Ok(()) => Ok(()),
        Err(_) => Err(ApiError::Internal),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native(balance: &str) -> Balance {
        Balance {
            balance: balance.to_string(),
            asset_type: "native".to_string(),
            asset_code: None,
            asset_issuer: None,
        }
    }

    fn credit(balance: &str, code: &str, issuer: &str) -> Balance {
        Balance {
            balance: balance.to_string(),
            asset_type: "credit_alphanum4".to_string(),
            asset_code: Some(code.to_string()),
            asset_issuer: Some(issuer.to_string()),
        }
    }

    #[test]
    fn parses_decimal_amounts_into_exact_stroops() {
        assert_eq!(parse_amount_stroops("100.0000000"), Some(1_000_000_000));
        assert_eq!(parse_amount_stroops("0.0000001"), Some(1));
        assert_eq!(parse_amount_stroops("5"), Some(50_000_000));
        assert_eq!(parse_amount_stroops("0.1"), Some(1_000_000));
    }

    #[test]
    fn min_reserve_grows_with_subentries_and_sponsorship() {
        let base = AccountInfo {
            balances: vec![],
            sequence: 0,
            subentry_count: 0,
            num_sponsoring: 0,
            num_sponsored: 0,
        };
        assert_eq!(base.min_reserve_stroops(), 2 * BASE_RESERVE_STROOPS);

        let with_trustlines = AccountInfo {
            subentry_count: 3,
            ..base.clone()
        };
        assert_eq!(with_trustlines.min_reserve_stroops(), 5 * BASE_RESERVE_STROOPS);

        let sponsored = AccountInfo {
            num_sponsoring: 1,
            num_sponsored: 1,
            ..base
        };
        // num_sponsoring - num_sponsored cancels out, back to the 2-entry floor.
        assert_eq!(sponsored.min_reserve_stroops(), 2 * BASE_RESERVE_STROOPS);
    }

    #[test]
    fn native_and_asset_balance_lookups() {
        let info = AccountInfo {
            balances: vec![
                native("42.5000000"),
                credit("10.0000000", "USDC", "GISSUER"),
            ],
            sequence: 0,
            subentry_count: 1,
            num_sponsoring: 0,
            num_sponsored: 0,
        };
        assert_eq!(info.native_balance_stroops(), 425_000_000);
        assert_eq!(
            info.asset_balance_stroops("USDC", "GISSUER"),
            Some(100_000_000)
        );
        assert_eq!(info.asset_balance_stroops("USDC", "GOTHER"), None);
        assert_eq!(info.asset_balance_stroops("EUR", "GISSUER"), None);
    }

    #[test]
    fn destination_trustline_matching() {
        let dest_balances = vec![native("0.0000000"), credit("0.0000000", "USDC", "GISSUER")];
        assert!(has_trustline(&dest_balances, "USDC", "GISSUER"));
        assert!(!has_trustline(&dest_balances, "USDC", "GOTHER"));
        assert!(!has_trustline(&dest_balances, "EUR", "GISSUER"));
        assert!(!has_trustline(&[], "USDC", "GISSUER"));
    }
}
