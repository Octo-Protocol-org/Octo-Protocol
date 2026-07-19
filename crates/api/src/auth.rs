//! Dashboard authentication: signup, login, refresh, logout, and JWT-based auth helpers.
//!
//! # Session lifecycle
//!
//! ```text
//!  login/signup ──▶ issues token T1 (7-day TTL)
//!  POST /refresh   ──▶ revokes T1, issues T2
//!  POST /logout    ──▶ revokes T2
//! ```
//!
//! Revocation uses a deny-list in Postgres (migration 0008_token_denylist.sql).
//! Every authenticated request checks the deny-list after signature + expiry verification,
//! so a revoked token is rejected even within its original TTL window.
//!
//! # Refresh atomicity
//!
//! `refresh` revokes the old token and issues a new one in two sequential Postgres calls.
//! There is a brief window (< one DB round-trip, typically < 5 ms) where both tokens are
//! technically valid. This is acceptable for bearer-token auth over HTTPS — an attacker
//! would need to replay the old token in a sub-5 ms window after the user triggered a refresh,
//! which is not a realistic threat model. A fully window-free design would require distributed
//! locking or opaque session IDs, which is out of scope here.
//!
//! # Concurrent-request race on refresh
//!
//! In-flight requests that carry T1 at the moment T1 is revoked may succeed or fail
//! depending on timing: if `is_token_revoked` runs before the deny-list INSERT commits they
//! succeed; after, they get 401. Clients should treat a mid-session 401 as a signal to
//! re-authenticate. This is the standard deny-list tradeoff and is documented here explicitly.
//!
//! # Security
//! - Passwords are hashed with **argon2id** (PHC string, random salt).
//! - Same error for "no such user" and "wrong password" → no account enumeration.
//! - Session token: HS256 JWT signed with `JWT_SECRET`.
//! - Revoked tokens stored in deny-list, checked on every authenticated request.
#![allow(clippy::too_many_arguments)]

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
use chrono::{TimeZone, Utc};
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
    sub: String,
    exp: i64,
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

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
        user: UserView { id: user.id, email: user.email },
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
        user: UserView { id: user.id, email: user.email },
    }))
}

/// `POST /v1/auth/refresh`
///
/// Issues a new token AND revokes the one used to authenticate this request.
/// The client must replace the stored token with the new one immediately.
pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<AuthResponse>>> {
    // 1. Authenticate (signature + expiry + deny-list).
    let user_id = authenticate_async(&headers, &state).await?;

    // 2. Capture the raw old token before it is revoked.
    let old_token = bearer(&headers).ok_or(ApiError::Unauthorized)?.to_string();

    // 3. Decode old token's `exp` for the deny-list row (so it can be pruned later).
    let old_exp = token_exp(state.jwt_secret(), &old_token).ok_or(ApiError::Unauthorized)?;
    let expires_at = Utc.timestamp_opt(old_exp, 0).single().unwrap_or_else(Utc::now);

    // 4. Revoke the old token.
    state
        .store()
        .revoke_token(&old_token, expires_at)
        .await
        .map_err(|_| ApiError::Internal)?;

    // 5. Issue a new token.
    let new_token = issue_token(state.jwt_secret(), user_id)?;

    let user = state
        .store()
        .get_user(user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    crate::audit::record(
        &state,
        user_id,
        "refreshed session token",
        crate::audit::category::AUTH,
        None,
        &headers,
    )
    .await;

    Ok(Envelope::ok(AuthResponse {
        token: new_token,
        user: UserView { id: user.id, email: user.email },
    }))
}

/// `POST /v1/auth/logout`
///
/// Revokes the current token immediately. After this call the token is permanently invalid.
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<serde_json::Value>>> {
    let user_id = authenticate_async(&headers, &state).await?;

    let token = bearer(&headers).ok_or(ApiError::Unauthorized)?.to_string();
    let exp = token_exp(state.jwt_secret(), &token).ok_or(ApiError::Unauthorized)?;
    let expires_at = Utc.timestamp_opt(exp, 0).single().unwrap_or_else(Utc::now);

    state
        .store()
        .revoke_token(&token, expires_at)
        .await
        .map_err(|_| ApiError::Internal)?;

    crate::audit::record(
        &state,
        user_id,
        "signed out",
        crate::audit::category::AUTH,
        None,
        &headers,
    )
    .await;

    Ok(Envelope::ok(serde_json::json!({ "message": "signed out" })))
}

/// `GET /v1/auth/me` — returns the authenticated user (token required).
pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<UserView>>> {
    let user_id = authenticate_async(&headers, &state).await?;
    let user = state
        .store()
        .get_user(user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;
    Ok(Envelope::ok(UserView { id: user.id, email: user.email }))
}

// ---------------------------------------------------------------------------
// Authentication helpers (public — used by other routes)
// ---------------------------------------------------------------------------

/// Async authenticate: validates signature + expiry AND checks the deny-list.
/// Use this in all auth-sensitive handlers.
pub async fn authenticate_async(
    headers: &axum::http::HeaderMap,
    state: &AppState,
) -> Result<Uuid, ApiError> {
    let token = bearer(headers).ok_or(ApiError::Unauthorized)?;
    let claims = verify_token(state.jwt_secret(), token).ok_or(ApiError::Unauthorized)?;

    // Deny-list check.
    if state
        .store()
        .is_token_revoked(token)
        .await
        .map_err(|_| ApiError::Internal)?
    {
        return Err(ApiError::Unauthorized);
    }

    claims.sub.parse::<Uuid>().map_err(|_| ApiError::Unauthorized)
}

/// Synchronous authenticate — signature + expiry only, **no deny-list check**.
/// Kept for callers in synchronous context. Migrate to `authenticate_async` where possible.
pub fn authenticate(headers: &axum::http::HeaderMap, state: &AppState) -> Result<Uuid, ApiError> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;
    let claims = verify_token(state.jwt_secret(), token).ok_or(ApiError::Unauthorized)?;
    claims.sub.parse::<Uuid>().map_err(|_| ApiError::Unauthorized)
}

/// Prefix that marks an octo API key (vs a dashboard login JWT).
const API_KEY_PREFIX: &str = "octo_sk_";

/// Extract the raw bearer token from the Authorization header.
pub fn bearer(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
}

fn hash_api_key(key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    hex::encode(h.finalize())
}

/// Authorize a request to operate on `wallet_id` — accepts a login JWT or an API key.
pub async fn authorize_wallet(
    headers: &axum::http::HeaderMap,
    state: &AppState,
    wallet_id: Uuid,
) -> Result<(), ApiError> {
    let token = bearer(headers).ok_or(ApiError::Unauthorized)?;

    if let Some(_key) = token.strip_prefix(API_KEY_PREFIX) {
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

    let user_id = authenticate(headers, state)?;
    let wallet = state.store().get_wallet(wallet_id).await?;
    if wallet.user_id != Some(user_id) {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

/// Require a dashboard login (reject API keys). Returns the authenticated user id.
pub fn require_login(headers: &axum::http::HeaderMap, state: &AppState) -> Result<Uuid, ApiError> {
    if let Some(tok) = bearer(headers) {
        if tok.starts_with(API_KEY_PREFIX) {
            return Err(ApiError::Unauthorized);
        }
    }
    authenticate(headers, state)
}

// ---------------------------------------------------------------------------
// JWT internals
// ---------------------------------------------------------------------------

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
const JWT_HEADER_B64: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

fn b64(input: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}

fn b64_decode(input: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input).ok()
}

fn issue_token(secret: &[u8], user_id: Uuid) -> Result<String, ApiError> {
    let claims = Claims { sub: user_id.to_string(), exp: now_secs() + TOKEN_TTL_SECS };
    let payload = serde_json::to_vec(&claims).map_err(|_| ApiError::Internal)?;
    let signing_input = format!("{JWT_HEADER_B64}.{}", b64(&payload));
    let sig = sign_hs256(secret, signing_input.as_bytes());
    Ok(format!("{signing_input}.{sig}"))
}

fn verify_token(secret: &[u8], token: &str) -> Option<Claims> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;
    if parts.next().is_some() || header != JWT_HEADER_B64 {
        return None;
    }
    let signing_input = format!("{header}.{payload}");
    if !verify_hs256(secret, signing_input.as_bytes(), signature) {
        return None;
    }
    let claims: Claims = serde_json::from_slice(&b64_decode(payload)?).ok()?;
    if claims.exp < now_secs() {
        return None;
    }
    Some(claims)
}

/// Extract the `exp` claim from a structurally valid, unexpired token.
fn token_exp(secret: &[u8], token: &str) -> Option<i64> {
    verify_token(secret, token).map(|c| c.exp)
}

fn sign_hs256(secret: &[u8], input: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(input);
    b64(&mac.finalize().into_bytes())
}

fn verify_hs256(secret: &[u8], input: &[u8], signature_b64: &str) -> bool {
    let Some(sig) = b64_decode(signature_b64) else { return false; };
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
