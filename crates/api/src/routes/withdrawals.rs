//! Tombstone for the custodial withdrawal endpoint.
//!
//! Removed in the non-custodial cutover: the server no longer holds user wallet keys, so it
//! cannot sign a payment on the user's behalf. Clients build + sign locally (dashboard/SDK) and
//! relay through `POST /v1/wallets/:id/submit-signed`.

use crate::error::{ApiError, ApiResult};
use axum::extract::Path;
use axum::response::Response;
use uuid::Uuid;

/// `POST /v1/wallets/:id/withdraw` — 410 Gone.
pub async fn withdraw(Path(_wallet_id): Path<Uuid>) -> ApiResult<Response> {
    Err(ApiError::Gone(
        "custodial withdrawals were removed: sign the payment client-side and POST it to \
         /v1/wallets/:id/submit-signed"
            .into(),
    ))
}
