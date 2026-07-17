//! Minimal Horizon + friendbot client used by the API for funding and balance reads.
//!
//! Only the few endpoints octo needs are implemented. Network errors map to `ApiError::Internal`
//! (logged by the caller); a missing account maps to `ApiError::NotFound`.

use crate::error::ApiError;
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

/// A thin Horizon client (one shared reqwest client).
#[derive(Clone)]
pub struct Horizon {
    http: reqwest::Client,
    base_url: String,
}

impl Horizon {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(DEFAULT_TIMEOUT)
                .build()
                .unwrap_or_default(),
            base_url: base_url.into(),
        }
    }

    /// Fetch an account's balances. Returns `NotFound` if the account does not exist on-chain yet.
    pub async fn balances(&self, account_g: &str) -> Result<Vec<Balance>, ApiError> {
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
        Ok(account.balances)
    }

    /// Fetch an account's current sequence number. `NotFound` if the account doesn't exist.
    pub async fn account_sequence(&self, account_g: &str) -> Result<i64, ApiError> {
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
        account
            .sequence
            .parse::<i64>()
            .map_err(|_| ApiError::Internal)
    }

    /// Submit a signed transaction (base64 XDR envelope) to Horizon.
    ///
    /// Returns the result even when the transaction failed on-chain (`successful == false`) so the
    /// caller can record the failure; only transport/HTTP errors return `Err`.
    pub async fn submit_transaction(&self, envelope_xdr: &str) -> Result<SubmitResult, ApiError> {
        let url = format!("{}/transactions", self.base_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .form(&[("tx", envelope_xdr)])
            .timeout(SUBMIT_TIMEOUT)
            .send()
            .await
            .map_err(|_| ApiError::Internal)?;

        // Horizon returns 400 with a problem document when the tx is rejected (e.g. bad seq, no
        // balance). Treat a parseable hash as "submitted but failed"; otherwise it's an error.
        let status = resp.status();
        let body: SubmitResponse = match resp.json().await {
            Ok(b) => b,
            Err(_) => {
                if status.is_success() {
                    return Err(ApiError::Internal);
                }
                // Rejected with no parseable hash → surface as a bad-request to the caller.
                return Err(ApiError::BadRequest(
                    "transaction rejected by network".into(),
                ));
            }
        };
        Ok(SubmitResult {
            hash: body.hash,
            successful: body.successful,
            ledger: body.ledger,
        })
    }
}

/// Fund a testnet account via friendbot. Best-effort: returns `Ok(())` on success, and a logged
/// error otherwise (the caller decides whether funding is required).
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

    #[tokio::test]
    async fn horizon_client_times_out_and_maps_to_internal_error() {
        let base_url = hanging_server().await;
        let horizon = Horizon {
            http: reqwest::Client::builder()
                .timeout(Duration::from_millis(200))
                .build()
                .unwrap(),
            base_url,
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
