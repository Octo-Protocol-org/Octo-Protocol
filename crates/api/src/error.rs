//! API error type and the standard JSON response envelope.
//!
//! Every response (success or error) is `{ statusCode, message, data }`; errors add a stable
//! machine-readable `code` (see [`ERROR_CODES`]). Errors never leak internal detail (DB messages,
//! key material, stack traces) — they map to coarse, safe messages.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use serde_json::json;

/// The uniform API result type.
pub type ApiResult<T> = Result<T, ApiError>;

/// Errors that map to HTTP responses.
#[derive(Debug)]
pub enum ApiError {
    /// 400 — the request was malformed (bad address, bad network, etc.).
    BadRequest(String),
    /// 401 — missing or invalid authentication.
    Unauthorized,
    /// 403 — the request is valid but the server refuses to act on it (e.g. sponsorship disabled).
    Forbidden(String),
    /// 404 — resource not found.
    NotFound,
    /// 409 — conflict (e.g. duplicate idempotency key / already exists).
    Conflict,
    /// 409 — a conflict with a specific, actionable message for the client.
    ConflictWith(String),
    /// 410 — the endpoint was removed (custodial signing paths, post non-custodial cutover).
    Gone(String),
    /// 429 — a rate limit or budget would be exceeded. Carries the remaining window (seconds),
    /// emitted as a `Retry-After` header.
    TooManyRequests {
        message: String,
        retry_after_secs: u64,
    },
    /// 400 — inner transaction sequence number does not match current on-chain sequence.
    StaleSequence(String),
    /// 500 — an internal error. The detail is logged, never returned to the client.
    Internal,
    /// 504 — an upstream dependency (e.g. Horizon) did not answer within the route's time budget.
    GatewayTimeout(String),
    /// 503 — a dependency needed to make a safe decision (e.g. Horizon) is unavailable.
    ServiceUnavailable(String),
}

/// The public error-code catalogue: `(code, HTTP status, meaning)`. Codes are a stable contract —
/// never rename or reuse one; add new ones here, in `docs/api.md` and in `docs/openapi.yaml`.
pub const ERROR_CODES: &[(&str, u16, &str)] = &[
    ("bad_request", 400, "The request was malformed or failed validation."),
    ("stale_sequence", 400, "The transaction's sequence number is stale; refresh signing info and rebuild."),
    ("unauthorized", 401, "Missing, invalid or revoked credentials."),
    ("forbidden", 403, "Authenticated, but the server refuses this action for this resource."),
    ("not_found", 404, "The resource or route does not exist, or is not visible to this caller."),
    ("method_not_allowed", 405, "The route exists but not for this HTTP method."),
    ("already_exists", 409, "A resource with this identity already exists (duplicate)."),
    ("conflict", 409, "The resource's current state does not allow this change."),
    ("gone", 410, "The endpoint or resource has been permanently removed or closed."),
    ("payload_too_large", 413, "The request body exceeds the 64 KiB limit."),
    ("unsupported_media_type", 415, "The request body has an unsupported Content-Type."),
    ("too_many_requests", 429, "A rate limit or budget would be exceeded."),
    ("internal_error", 500, "An internal error occurred; details are logged, never returned."),
    ("upstream_timeout", 504, "An upstream dependency (e.g. Horizon) did not answer in time."),
    ("service_unavailable", 503, "A dependency needed to make a safe decision is unavailable."),
];

/// Code for an error raised outside [`ApiError`] (extractor rejections, unknown routes, body limit).
pub fn code_for_status(status: StatusCode) -> &'static str {
    match status.as_u16() {
        401 => "unauthorized",
        403 => "forbidden",
        404 => "not_found",
        405 => "method_not_allowed",
        409 => "conflict",
        410 => "gone",
        413 => "payload_too_large",
        415 => "unsupported_media_type",
        429 => "too_many_requests",
        503 => "service_unavailable",
        504 => "upstream_timeout",
        s if s >= 500 => "internal_error",
        _ => "bad_request",
    }
}

/// Build the standard error envelope: `{ statusCode, code, message, data: null }`.
pub fn error_response(status: StatusCode, code: &'static str, message: String) -> Response {
    let body = Json(json!({
        "statusCode": status.as_u16(),
        "code": code,
        "message": message,
        "data": serde_json::Value::Null,
    }));
    (status, body).into_response()
}

impl ApiError {
    /// Stable machine-readable code for this variant — one per variant, listed in [`ERROR_CODES`].
    pub fn code(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "bad_request",
            ApiError::Unauthorized => "unauthorized",
            ApiError::Forbidden(_) => "forbidden",
            ApiError::NotFound => "not_found",
            ApiError::Conflict => "already_exists",
            ApiError::ConflictWith(_) => "conflict",
            ApiError::Gone(_) => "gone",
            ApiError::TooManyRequests { .. } => "too_many_requests",
            ApiError::StaleSequence(_) => "stale_sequence",
            ApiError::Internal => "internal_error",
            ApiError::GatewayTimeout(_) => "upstream_timeout",
            ApiError::ServiceUnavailable(_) => "service_unavailable",
        }
    }

    /// HTTP status and client-safe message.
    pub fn parts(&self) -> (StatusCode, String) {
        match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, m.clone()),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".into()),
            ApiError::Conflict => (StatusCode::CONFLICT, "already exists".into()),
            ApiError::ConflictWith(m) => (StatusCode::CONFLICT, m.clone()),
            ApiError::Gone(m) => (StatusCode::GONE, m.clone()),
            ApiError::TooManyRequests { message, .. } => {
                (StatusCode::TOO_MANY_REQUESTS, message.clone())
            }
            ApiError::StaleSequence(m) => (StatusCode::BAD_REQUEST, m.clone()),
            ApiError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal server error".into(),
            ),
            ApiError::GatewayTimeout(m) => (StatusCode::GATEWAY_TIMEOUT, m.clone()),
            ApiError::ServiceUnavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, m.clone()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Capture the back-off hint before `parts()` consumes the error.
        let retry_after = match &self {
            ApiError::TooManyRequests {
                retry_after_secs, ..
            } => Some((*retry_after_secs).max(1)),
            _ => None,
        };
        let (status, message) = self.parts();
        let mut response = error_response(status, self.code(), message);
        if let Some(secs) = retry_after {
            if let Ok(value) = axum::http::HeaderValue::from_str(&secs.to_string()) {
                response
                    .headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, value);
            }
        }
        response
    }
}

/// Log the cause of an internal failure and map it to the opaque [`ApiError::Internal`].
///
/// Only the error's `Debug` representation is logged — never request bodies, tokens, API keys or
/// addresses — and the client response stays the generic "internal server error".
pub(crate) fn internal(e: impl std::fmt::Debug) -> ApiError {
    tracing::error!(error = ?e, "internal error");
    ApiError::Internal
}

/// Map store errors to API errors without leaking DB internals.
impl From<octo_store::StoreError> for ApiError {
    fn from(e: octo_store::StoreError) -> Self {
        match e {
            octo_store::StoreError::Conflict => ApiError::Conflict,
            octo_store::StoreError::NotFound => ApiError::NotFound,
            octo_store::StoreError::WalletArchived => {
                ApiError::Forbidden("wallet is archived".into())
            }
            octo_store::StoreError::InvalidMemoId => {
                ApiError::BadRequest("memo id must be nonnegative".into())
            }
            octo_store::StoreError::BudgetExceeded => ApiError::TooManyRequests {
                message: "daily sponsorship budget exceeded".into(),
                retry_after_secs: 60,
            },
            octo_store::StoreError::DuplicateCustomerRef => {
                ApiError::ConflictWith("customer_ref already in use for this wallet".into())
            }
            // Database/migration errors are logged by the caller; never echoed.
            _ => ApiError::Internal,
        }
    }
}

/// Map wallet-core errors. Bad inputs become 400; secret/crypto failures become 500 (opaque).
impl From<octo_wallet_core::WalletError> for ApiError {
    fn from(e: octo_wallet_core::WalletError) -> Self {
        use octo_wallet_core::WalletError as W;
        match e {
            W::InvalidMnemonic
            | W::InvalidChecksum
            | W::InvalidAddress
            | W::InvalidAssetCode
            | W::InvalidAmount
            | W::InvalidDerivationPath
            | W::InvalidXdr
            | W::InvalidSignature
            | W::InvalidSeedLength
            | W::WeakSeed
            | W::MnemonicAccountMismatch => ApiError::BadRequest("invalid input".into()),
            W::ReservedNativeAssetCode => ApiError::BadRequest(
                "native asset codes cannot be used as credit asset codes".into(),
            ),
            W::StaleSequence => ApiError::StaleSequence(
                "Stale sequence number — refresh signing info and rebuild the transaction.".into(),
            ),
            W::KeyDerivation | W::Signing | W::SeedDecryption => ApiError::Internal,
        }
    }
}

/// Log an internal failure (type/message only) and map it to the opaque [`ApiError::Internal`].
///
/// Use this instead of `map_err(|_| ApiError::Internal)` so a 500 leaves a trace in the logs.
/// Never pass request bodies, tokens or addresses here — only the underlying error.
pub fn internal(e: impl std::fmt::Debug) -> ApiError {
    tracing::error!(error = ?e, "internal error");
    ApiError::Internal
}

/// Wrap any serializable value in the standard success envelope with a status code.
#[derive(Serialize)]
pub struct Envelope<T: Serialize> {
    #[serde(rename = "statusCode")]
    pub status_code: u16,
    pub message: String,
    pub data: T,
}

impl<T: Serialize> Envelope<T> {
    pub fn ok(data: T) -> Json<Envelope<T>> {
        Json(Envelope {
            status_code: 200,
            message: "OK".into(),
            data,
        })
    }

    pub fn created(data: T) -> (StatusCode, Json<Envelope<T>>) {
        (
            StatusCode::CREATED,
            Json(Envelope {
                status_code: 201,
                message: "Created".into(),
                data,
            }),
        )
    }
}

impl Envelope<Option<()>> {
    /// Build an error envelope (with the status-derived `code`) for failures raised in
    /// middleware, so they match every other error response.
    pub fn error(status: StatusCode, message: String) -> Response {
        error_response(status, code_for_status(status), message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_maps_to_opaque_500() {
        let err = internal("db exploded");
        assert!(matches!(err, ApiError::Internal));
        let (status, message) = err.parts();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(message, "internal server error");
    }

    #[test]
    fn too_many_requests_sets_retry_after_header() {
        let err = ApiError::TooManyRequests {
            message: "slow down".into(),
            retry_after_secs: 0,
        };
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        // Clamped to at least 1 second.
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("1")
        );
    }

    #[test]
    fn non_429_errors_have_no_retry_after_header() {
        let response = ApiError::NotFound.into_response();
        assert!(response
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .is_none());
    }
}
