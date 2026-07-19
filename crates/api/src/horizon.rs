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
                    return Err(FetchError::Transport);
                }
                if !resp.status().is_success() {
                    return Err(FetchError::Permanent);
                }
                let account: AccountResponse =
                    resp.json().await.map_err(|_| FetchError::Permanent)?;
                account
                    .sequence
                    .parse::<i64>()
                    .map_err(|_| FetchError::Permanent)
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
