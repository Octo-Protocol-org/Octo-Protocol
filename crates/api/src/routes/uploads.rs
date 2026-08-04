//! Signed Cloudinary upload parameters for client-side image uploads.
//!
//! The browser cannot hold the Cloudinary API secret, and routing image bytes through this API
//! would mean multipart handling and a much larger body limit. Instead the client asks for a
//! short-lived signature here and uploads directly to Cloudinary with it — the secret stays
//! server-side and only the resulting URL is ever sent back to Octo.

use crate::auth::authenticate;
use crate::error::{ApiError, ApiResult, Envelope};
use crate::state::AppState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Folder every payment-link image lands in, so uploads can't scatter across the account.
const UPLOAD_FOLDER: &str = "octo/payment-links";

#[derive(Debug, Serialize)]
pub struct UploadSignature {
    pub cloud_name: String,
    pub api_key: String,
    pub timestamp: i64,
    pub folder: String,
    pub signature: String,
}

/// `GET /v1/uploads/signature` — signed params for a direct-to-Cloudinary image upload.
///
/// Login required: an open signature endpoint would let anyone upload into the account.
pub async fn upload_signature(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<UploadSignature>>> {
    authenticate(&headers, &state).await?;

    let cfg = state.cloudinary().ok_or_else(|| {
        ApiError::BadRequest(
            "image uploads are not configured on this server (set CLOUDINARY_CLOUD_NAME, \
             CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET)"
                .into(),
        )
    })?;

    let timestamp = crate::auth::now_secs();

    // Cloudinary's signature: every upload param except file/cloud_name/resource_type/api_key,
    // sorted by key, joined as `k=v` with `&`, then the API secret appended with no delimiter.
    // Cloudinary validates both SHA-1 (its SDK default) and SHA-256; SHA-256 is used here as the
    // stronger option — the client must not send any param that isn't signed below, or the
    // signature check fails, which is exactly what pins uploads to this folder.
    let to_sign = format!(
        "folder={}&timestamp={}{}",
        UPLOAD_FOLDER, timestamp, cfg.api_secret
    );
    let signature = hex::encode(Sha256::digest(to_sign.as_bytes()));

    Ok(Envelope::ok(UploadSignature {
        cloud_name: cfg.cloud_name,
        api_key: cfg.api_key,
        timestamp,
        folder: UPLOAD_FOLDER.to_string(),
        signature,
    }))
}
