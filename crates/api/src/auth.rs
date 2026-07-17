//! Dashboard authentication: signup, login, and a JWT-based `CurrentUser` extractor.
//!
//! Security:
//! - Passwords are hashed with **argon2id** (PHC string, random salt); plaintext is never stored
//!   or logged.
//! - Login returns the **same** error for "no such user" and "wrong password" so the endpoint
//!   doesn't reveal which emails are registered.
//! - The session token is a JWT (HS256) signed with the server's `JWT_SECRET`.

use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

/// Token lifetime: 7 days.
const TOKEN_TTL_SECS: i64 = 7 * 24 * 60 * 60;

#[derive(Debug, Deserialize, Default)]
pub struct Credentials {
    pub email: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserView,
}

#[derive(Debug, Serialize)]
pub struct UserView {
    pub id: Uuid,
    pub email: String,
}

/// JWT claims.
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    /// Subject: the user id.
    sub: String,
    /// Expiry (unix seconds).
    exp: i64,
}

/// `POST /v1/auth/signup`
pub async fn signup(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<AuthResponse>>)> {
    let creds: Credentials = parse_optional(&body)?;
    let (email, password) = validate(creds)?;

    let hash = hash_password(&password)?;
    let user = state
        .store()
        .create_user(&email, &hash)
        .await
        .map_err(|e| match e {
            octo_store::StoreError::Conflict => {
                ApiError::BadRequest("email already registered".into())
            }
            _ => ApiError::Internal,
        })?;

    crate::audit::record(
        &state,
        user.id,
        "created an account",
        crate::audit::category::AUTH,
        None,
        &headers,
    )
    .await;

    let token = issue_token(state.jwt_secret(), user.id)?;
    let (code, json) = Envelope::created(AuthResponse {
        token,
        user: UserView {
            id: user.id,
            email: user.email,
        },
    });
    Ok((code, json))
}

/// `POST /v1/auth/login`
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<AuthResponse>>> {
    let creds: Credentials = parse_optional(&body)?;
    let (email, password) = validate(creds)?;

    // Same error for "not found" and "bad password" → no account enumeration.
    let user = state
        .store()
        .find_user_by_email(&email)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or_else(|| ApiError::BadRequest("invalid email or password".into()))?;

    verify_password(&password, &user.password_hash)
        .map_err(|_| ApiError::BadRequest("invalid email or password".into()))?;

    crate::audit::record(
        &state,
        user.id,
        "signed in",
        crate::audit::category::AUTH,
        None,
        &headers,
    )
    .await;

    let token = issue_token(state.jwt_secret(), user.id)?;
    Ok(Envelope::ok(AuthResponse {
        token,
        user: UserView {
            id: user.id,
            email: user.email,
        },
    }))
}

/// `POST /v1/auth/refresh` — exchange a valid, unexpired token for a freshly-signed one.
///
/// The caller presents their current JWT via `Authorization: Bearer`; the response carries a new
/// token for the same user with a full [`TOKEN_TTL_SECS`] window starting now.
///
/// **This is not a security control.** Refreshing does **not** invalidate the previous token:
/// both the old and the new token remain valid until their natural expiry. That is an intentional
/// scope limit — real revocation (server-side session state / a token denylist) is a separate,
/// larger piece of work.
pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<AuthResponse>>> {
    let user_id = authenticate(&headers, &state)?;
    let user = state
        .store()
        .get_user(user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    crate::audit::record(
        &state,
        user.id,
        "refreshed session token",
        crate::audit::category::AUTH,
        None,
        &headers,
    )
    .await;

    let token = issue_token(state.jwt_secret(), user.id)?;
    Ok(Envelope::ok(AuthResponse {
        token,
        user: UserView {
            id: user.id,
            email: user.email,
        },
    }))
}

/// `GET /v1/auth/me` — returns the authenticated user (token required).
pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<UserView>>> {
    let user_id = authenticate(&headers, &state)?;
    let user = state
        .store()
        .get_user(user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;
    Ok(Envelope::ok(UserView {
        id: user.id,
        email: user.email,
    }))
}

// --- helpers ---------------------------------------------------------------

fn validate(creds: Credentials) -> Result<(String, String), ApiError> {
    let email = creds
        .email
        .map(|e| e.trim().to_lowercase())
        .filter(|e| e.contains('@') && e.len() >= 3)
        .ok_or_else(|| ApiError::BadRequest("a valid email is required".into()))?;
    let password = creds
        .password
        .filter(|p| p.len() >= 8)
        .ok_or_else(|| ApiError::BadRequest("password must be at least 8 characters".into()))?;
    Ok((email, password))
}

fn hash_password(password: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| ApiError::Internal)
}

fn verify_password(password: &str, phc: &str) -> Result<(), ()> {
    let parsed = PasswordHash::new(phc).map_err(|_| ())?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| ())
}

type HmacSha256 = Hmac<Sha256>;

/// Standard JWT header for HS256.
const JWT_HEADER_B64: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"; // {"alg":"HS256","typ":"JWT"}

fn b64(input: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}

fn b64_decode(input: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .ok()
}

/// Mint an HS256 JWT for `user_id`.
fn issue_token(secret: &[u8], user_id: Uuid) -> Result<String, ApiError> {
    let claims = Claims {
        sub: user_id.to_string(),
        exp: now_secs() + TOKEN_TTL_SECS,
    };
    let payload = serde_json::to_vec(&claims).map_err(|_| ApiError::Internal)?;
    let signing_input = format!("{JWT_HEADER_B64}.{}", b64(&payload));
    let sig = sign_hs256(secret, signing_input.as_bytes());
    Ok(format!("{signing_input}.{sig}"))
}

/// Verify an HS256 JWT and return its claims if the signature is valid and it has not expired.
fn verify_token(secret: &[u8], token: &str) -> Option<Claims> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;
    if parts.next().is_some() || header != JWT_HEADER_B64 {
        return None;
    }

    let signing_input = format!("{header}.{payload}");
    // Authenticate via constant-time HMAC verify before trusting the payload.
    if !verify_hs256(secret, signing_input.as_bytes(), signature) {
        return None;
    }

    let claims: Claims = serde_json::from_slice(&b64_decode(payload)?).ok()?;
    if claims.exp < now_secs() {
        return None;
    }
    Some(claims)
}

fn sign_hs256(secret: &[u8], input: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(input);
    b64(&mac.finalize().into_bytes())
}

fn verify_hs256(secret: &[u8], input: &[u8], signature_b64: &str) -> bool {
    let Some(sig) = b64_decode(signature_b64) else {
        return false;
    };
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(input);
    mac.verify_slice(&sig).is_ok()
}

fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Authenticate a request from its headers via the `Authorization: Bearer <jwt>` header.
/// Returns the authenticated user's id, or [`ApiError::Unauthorized`].
///
/// Used directly by protected handlers (rather than a `FromRequestParts` extractor, which trips an
/// async-trait lifetime bug on this toolchain — see notes in the repo).
pub fn authenticate(headers: &axum::http::HeaderMap, state: &AppState) -> Result<Uuid, ApiError> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;
    let claims = verify_token(state.jwt_secret(), token).ok_or(ApiError::Unauthorized)?;
    claims
        .sub
        .parse::<Uuid>()
        .map_err(|_| ApiError::Unauthorized)
}

/// Prefix that marks an octo API key (vs a dashboard login JWT).
const API_KEY_PREFIX: &str = "octo_sk_";

/// Extract the raw bearer token (`octo_sk_…` or a JWT), if present.
fn bearer(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
}

/// SHA-256 hex of an API key (matches how keys are stored in `api_keys`).
fn hash_api_key(key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    hex::encode(h.finalize())
}

/// Authorize a request to operate on `wallet_id`, accepting **either**:
/// - a dashboard login JWT whose user **owns** the wallet, or
/// - an `octo_sk_…` API key whose wallet **is** `wallet_id` (the key implies its wallet).
///
/// Returns `Ok(())` when authorized, `Unauthorized` if no/invalid credential, `NotFound` if the
/// credential is valid but not for this wallet (so we don't reveal other users' wallets).
pub async fn authorize_wallet(
    headers: &axum::http::HeaderMap,
    state: &AppState,
    wallet_id: Uuid,
) -> Result<(), ApiError> {
    let token = bearer(headers).ok_or(ApiError::Unauthorized)?;

    if let Some(_key) = token.strip_prefix(API_KEY_PREFIX) {
        // API-key path: the key maps to exactly one wallet.
        let key_wallet = state
            .store()
            .wallet_id_for_key_hash(&hash_api_key(token))
            .await
            .map_err(|_| ApiError::Internal)?
            .ok_or(ApiError::Unauthorized)?;
        if key_wallet != wallet_id {
            return Err(ApiError::NotFound);
        }
        return Ok(());
    }

    // Login-JWT path: the user must own the wallet.
    let user_id = authenticate(headers, state)?;
    let wallet = state.store().get_wallet(wallet_id).await?;
    if wallet.user_id != Some(user_id) {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

/// Require a **dashboard login** (reject API keys). Returns the authenticated user id.
/// Used for sensitive operations (e.g. withdrawals) that must not be driven by an API key.
pub fn require_login(headers: &axum::http::HeaderMap, state: &AppState) -> Result<Uuid, ApiError> {
    if let Some(tok) = bearer(headers) {
        if tok.starts_with(API_KEY_PREFIX) {
            // An API key was presented where a login is required.
            return Err(ApiError::Unauthorized);
        }
    }
    authenticate(headers, state)
}
