//! Tombstone for the custodial trustline endpoint.
//!
//! Removed in the non-custodial cutover: the server no longer holds user wallet keys, so it
//! cannot sign a ChangeTrust on the user's behalf. Clients build + sign the ChangeTrust locally
//! (dashboard/SDK) and relay through `POST /v1/wallets/:id/submit-signed`.

use crate::error::{ApiError, ApiResult};
use axum::extract::Path;
use axum::response::Response;
use uuid::Uuid;

/// `POST /v1/wallets/:id/trustlines` — 410 Gone.
pub async fn add_trustline(Path(_wallet_id): Path<Uuid>) -> ApiResult<Response> {
    Err(ApiError::Gone(
        "custodial trustlines were removed: sign the ChangeTrust client-side and POST it to \
         /v1/wallets/:id/submit-signed"
            .into(),
    ))
}
