#![forbid(unsafe_code)]

//! # horizon-mock
//!
//! A small, offline mock of the Stellar Horizon API used for local development
//! and tests. It serves scripted fixtures for a handful of endpoints so that
//! ingest flows and integration tests can run without network access.
//!
//! ## Endpoints
//!
//! - `GET /accounts/{id}` — returns the account record (balances + sequence).
//! - `GET /accounts/{id}/payments` — returns paged payment records honoring
//!   `order`, `limit` and `cursor` query parameters.
//! - `POST /transactions` — returns a scripted submit response.
//!
//! ## Fixtures
//!
//! The mock ships with a small set of documented fixtures:
//!
//! ### Accounts
//!
//! | Account ID | Sequence | Balances |
//! |------------|----------|----------|
//! | `GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF` | `1` | native `100.0000000` |
//! | `GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB` | `2` | native `50.0000000`, `USD` `25.0000000` |
//!
//! Any other account ID returns a `404` with a Horizon-style error body.
//!
//! ### Payments
//!
//! Each account has a fixed list of payment records (see [`fixtures`]). The
//! list is returned in ascending order by default; pass `order=desc` to reverse
//! it. `limit` caps the number of records (default `10`, max `200`). `cursor`
//! returns records strictly after the given payment id (ascending) or strictly
//! before it (descending), matching Horizon semantics.
//!
//! ### Submit
//!
//! `POST /transactions` returns a scripted successful submit response. If the
//! request body contains the marker `"fail"` the mock returns a `400` with a
//! Horizon-style `transaction_failed` error, which is useful for exercising
//! error paths.
//!
//! ## Usage
//!
//! From tests:
//!
//! ```no_run
//! # async fn run() {
//! let addr = horizon_mock::serve("127.0.0.1:0").await.unwrap();
//! println!("mock horizon listening on {addr}");
//! # }
//! ```
//!
//! From docker-compose, run the `horizon-mock` binary (see the crate's
//! `main.rs`); it reads `HORIZON_MOCK_ADDR` (default `0.0.0.0:8000`). The
//! binary installs a `tracing` subscriber, so server errors (including bind
//! failures) are reported through `tracing` rather than raw stderr output.

use std::net::SocketAddr;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Default bind address used by [`serve`] and the binary.
pub const DEFAULT_ADDR: &str = "0.0.0.0:8000";

/// Documented fixture data served by the mock.
pub mod fixtures {
    use super::*;

    /// A single balance entry on an account.
    #[derive(Debug, Clone, Serialize)]
    pub struct Balance {
        pub balance: String,
        pub asset_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub asset_code: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub asset_issuer: Option<String>,
    }

    /// A scripted account fixture.
    #[derive(Debug, Clone)]
    pub struct Account {
        pub id: &'static str,
        pub sequence: &'static str,
        pub balances: Vec<Balance>,
    }

    /// A scripted payment record fixture.
    #[derive(Debug, Clone, Serialize)]
    pub struct Payment {
        pub id: String,
        pub paging_token: String,
        pub transaction_hash: String,
        #[serde(rename = "type")]
        pub kind: String,
        pub from: String,
        pub to: String,
        pub amount: String,
        pub asset_type: String,
        #[serde(skip_serializing_if = "Option::is_native")]
        pub asset_code: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub asset_issuer: Option<String>,
    }

    trait IsNative {
        fn is_native(&self) -> bool;
    }

    impl IsNative for Option<String> {
        fn is_native(&self) -> bool {
            self.is_none()
        }
    }

    const ACCOUNT_A: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const ACCOUNT_B: &str = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    /// Returns the scripted accounts keyed by account id.
    pub fn accounts() -> Vec<Account> {
        vec![
            Account {
                id: ACCOUNT_A,
                sequence: "1",
                balances: vec![Balance {
                    balance: "100.0000000".to_string(),
                    asset_type: "native".to_string(),
                    asset_code: None,
                    asset_issuer: None,
                }],
            },
            Account {
                id: ACCOUNT_B,
                sequence: "2",
                balances: vec![
                    Balance {
                        balance: "50.0000000".to_string(),
                        asset_type: "native".to_string(),
                        asset_code: None,
                        asset_issuer: None,
                    },
                    Balance {
                        balance: "25.0000000".to_string(),
                        asset_type: "credit_alphanum4".to_string(),
                        asset_code: Some("USD".to_string()),
                        asset_issuer: Some(
                            "GCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_string(),
                        ),
                    },
                ],
            },
        ]
    }

    /// Returns the scripted payments for the given account id, in ascending
    /// order by id. Returns an empty list for unknown accounts.
    pub fn payments(account_id: &str) -> Vec<Payment> {
        match account_id {
            ACCOUNT_A => vec![
                Payment {
                    id: "1".to_string(),
                    paging_token: "1".to_string(),
                    transaction_hash: "aa00000000000000000000000000000000000000000000000000000000000001".to_string(),
                    kind: "payment".to_string(),
                    from: ACCOUNT_A.to_string(),
                    to: ACCOUNT_B.to_string(),
                    amount: "10.0000000".to_string(),
                    asset_type: "native".to_string(),
                    asset_code: None,
                    asset_issuer: None,
                },
                Payment {
                    id: "2".to_string(),
                    paging_token: "2".to_string(),
                    transaction_hash: "aa00000000000000000000000000000000000000000000000000000000000002".to_string(),
                    kind: "payment".to_string(),
                    from: ACCOUNT_B.to_string(),
                    to: ACCOUNT_A.to_string(),
                    amount: "5.0000000".to_string(),
                    asset_type: "native".to_string(),
                    asset_code: None,
                    asset_issuer: None,
                },
                Payment {
                    id: "3".to_string(),
                    paging_token: "3".to_string(),
                    transaction_hash: "aa00000000000000000000000000000000000000000000000000000000000003".to_string(),
                    kind: "payment".to_string(),
                    from: ACCOUNT_A.to_string(),
                    to: ACCOUNT_B.to_string(),
                    amount: "2.5000000".to_string(),
                    asset_type: "credit_alphanum4".to_string(),
                    asset_code: Some("USD".to_string()),
                    asset_issuer: Some(
                        "GCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_string(),
                    ),
                },
            ],
            ACCOUNT_B => vec![
                Payment {
                    id: "1".to_string(),
                    paging_token: "1".to_string(),
                    transaction_hash: "bb00000000000000000000000000000000000000000000000000000000000001".to_string(),
                    kind: "payment".to_string(),
                    from: ACCOUNT_A.to_string(),
                    to: ACCOUNT_B.to_string(),
                    amount: "10.0000000".to_string(),
                    asset_type: "native".to_string(),
                    asset_code: None,
                    asset_issuer: None,
                },
                Payment {
                    id: "2".to_string(),
                    paging_token: "2".to_string(),
                    transaction_hash: "bb00000000000000000000000000000000000000000000000000000000000002".to_string(),
                    kind: "payment".to_string(),
                    from: ACCOUNT_B.to_string(),
                    to: ACCOUNT_A.to_string(),
                    amount: "5.0000000".to_string(),
                    asset_type: "native".to_string(),
                    asset_code: None,
                    asset_issuer: None,
                },
            ],
            _ => Vec::new(),
        }
    }
}

/// Shared state for the router. Currently stateless but kept for future
/// extension (e.g. mutable fixtures).
#[derive(Clone, Default)]
pub struct MockState;

/// Builds the mock Horizon [`Router`].
pub fn router() -> Router {
    Router::new()
        .route("/accounts/:id", get(get_account))
        .route("/accounts/:id/payments", get(get_payments))
        .route("/transactions", post(submit_transaction))
        .with_state(MockState)
}

/// Binds to `addr` and serves the mock Horizon API until the process exits.
///
/// Returns the actual bound [`SocketAddr`] (useful when binding to port `0`).
pub async fn serve(addr: impl Into<String>) -> std::io::Result<SocketAddr> {
    let addr = addr.into();
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let local_addr = listener.local_addr()?;
    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, router()).await {
            tracing::error!(error = %err, "horizon-mock server error");
        }
    });
    Ok(local_addr)
}

fn horizon_error(status: StatusCode, title: &str, detail: &str) -> Response {
    let body = json!({
        "type": "https://stellar.org/horizon-errors/error",
        "title": title,
        "status": status.as_u16(),
        "detail": detail,
    });
    (status, Json(body)).into_response()
}

async fn get_account(Path(id): Path<String>, State(_): State<MockState>) -> Response {
    match fixtures::accounts().into_iter().find(|a| a.id == id) {
        Some(account) => {
            let body = json!({
                "id": account.id,
                "account_id": account.id,
                "sequence": account.sequence,
                "subentry_count": 0,
                "balances": account.balances,
                "signers": [],
                "data": {},
                "thresholds": {
                    "low_threshold": 0,
                    "med_threshold": 0,
                    "high_threshold": 0,
                },
                "flags": {
                    "auth_required": false,
                    "auth_revocable": false,
                    "auth_immutable": false,
                },
            });
            (StatusCode::OK, Json(body)).into_response()
        }
        None => horizon_error(
            StatusCode::NOT_FOUND,
            "Resource Missing",
            &format!("account {id} not found"),
        ),
    }
}

#[derive(Debug, Deserialize)]
struct PaymentsQuery {
    order: Option<String>,
    limit: Option<u32>,
    cursor: Option<String>,
}

async fn get_payments(
    Path(id): Path<String>,
    Query(query): Query<PaymentsQuery>,
    State(_): State<MockState>,
) -> Response {
    let known = fixtures::accounts().into_iter().any(|a| a.id == id);
    if !known {
        return horizon_error(
            StatusCode::NOT_FOUND,
            "Resource Missing",
            &format!("account {id} not found"),
        );
    }

    let descending = matches!(query.order.as_deref(), Some("desc"));
    let limit = query.limit.unwrap_or(10).min(200) as usize;

    let mut records = fixtures::payments(&id);

    // Apply cursor: strictly after (ascending) or strictly before (descending).
    if let Some(cursor) = query.cursor.as_deref() {
        if let Ok(cursor_id) = cursor.parse::<u64>() {
            records.retain(|p| {
                let pid = p.id.parse::<u64>().unwrap_or(0);
                if descending {
                    pid < cursor_id
                } else {
                    pid > cursor_id
                }
            });
        }
    }

    if descending {
        records.reverse();
    }

    records.truncate(limit);

    let body = json!({
        "_embedded": {
            "records": records,
        },
    });
    (StatusCode::OK, Json(body)).into_response()
}

async fn submit_transaction(
    State(_): State<MockState>,
    body: String,
) -> Response {
    if body.contains("fail") {
        return horizon_error(
            StatusCode::BAD_REQUEST,
            "Transaction Failed",
            "The transaction failed with a scripted error.",
        );
    }

    let response = json!({
        "hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "ledger": 1,
        "successful": true,
        "envelope_xdr": "",
        "result_xdr": "",
        "result_meta_xdr": "",
    });
    (StatusCode::OK, Json(response)).into_response()
}

/// Convenience helper returning the mock as a JSON [`Value`] for a given
/// account id, mirroring the `GET /accounts/{id}` response. Useful in tests
/// that want to assert against fixtures without spinning up a server.
pub fn account_fixture(id: &str) -> Option<Value> {
    fixtures::accounts().into_iter().find(|a| a.id == id).map(|account| {
        json!({
            "id": account.id,
            "account_id": account.id,
            "sequence": account.sequence,
            "balances": account.balances,
        })
    })
}