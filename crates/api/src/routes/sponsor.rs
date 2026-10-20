//! Sponsored transaction endpoints: sponsor a fee-bump, and list history.

use crate::auth::authorize_wallet_scope;
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::sponsor_validation::validate_inner_xdr;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use octo_crypto::SealedSeed;
use octo_wallet_core::{
    compute_inner_tx_hash, inner_sequence_number, sign_fee_bump, sign_fee_bump_with_account_id, FeeBumpRequest,
};
use stellar_base::transaction::MIN_BASE_FEE;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Default, Deserialize)]
pub struct SponsorRequest {
    /// Base64 XDR of the user's signed inner transaction.
    pub transaction_xdr: Option<String>,
    /// Max fee (stroops) the master wallet will pay for the fee-bump.
    pub max_base_fee_stroops: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct SponsorResponse {
    pub id: Uuid,
    pub status: String,
    pub inner_tx_hash: String,
    pub fee_bump_tx_hash: Option<String>,
    pub fee_stroops: i64,
}

/// Dry-run verdict for `POST /v1/wallets/:id/sponsor/validate` (#463).
#[derive(Debug, Serialize)]
pub struct SponsorValidateResponse {
    /// "accepted" | "rejected".
    pub verdict: &'static str,
    /// Why the real endpoint would refuse; `None` when accepted.
    pub reason: Option<String>,
    /// HTTP status the real endpoint would answer with; `None` when accepted.
    pub rejection_status: Option<u16>,
    /// Machine-readable error `code` the real endpoint would answer with; `None` when accepted.
    pub rejection_code: Option<&'static str>,
    /// Fee ceiling the real call would reserve against the daily budget.
    pub projected_fee_stroops: Option<i64>,
    /// Dedup key of the inner transaction, once it parses.
    pub inner_tx_hash: Option<String>,
    /// Daily budget left after this sponsorship; `None` when unlimited or rejected.
    pub budget_remaining_stroops: Option<i64>,
}

/// Everything the real and dry-run sponsor paths check before any budget is reserved.
struct Preflight {
    wallet: octo_store::Wallet,
    config: octo_store::GasSponsorshipConfig,
    inner_xdr: String,
    max_fee: i64,
    inner_hash_hex: String,
}

/// The single validation path shared by `sponsor` and `validate_sponsor`. Read-only: it may
/// query the DB and Horizon but never signs, reserves budget or writes a row.
async fn preflight(state: &AppState, wallet_id: Uuid, req: SponsorRequest) -> ApiResult<Preflight> {
    let inner_xdr = req
        .transaction_xdr
        .filter(|x| !x.is_empty())
        .ok_or_else(|| ApiError::BadRequest("transaction_xdr is required".into()))?;
    let max_fee = req
        .max_base_fee_stroops
        .filter(|f| *f > 0)
        .ok_or_else(|| ApiError::BadRequest("max_base_fee_stroops must be > 0".into()))?;
    if max_fee < MIN_BASE_FEE.to_i64() {
        return Err(ApiError::BadRequest(format!(
            "max_base_fee_stroops must be at least {}",
            MIN_BASE_FEE.to_i64()
        )));
    }

    let wallet = state.store().get_wallet(wallet_id).await?;
    if wallet.is_archived() {
        return Err(ApiError::Forbidden("wallet is archived".into()));
    }

    // 1. Sponsorship must be enabled for this wallet.
    let config = state
        .store()
        .get_gas_sponsorship_config(wallet_id)
        .await
        .map_err(|_| ApiError::Internal)?;
    let config = match config {
        Some(c) if c.enabled => c,
        _ => {
            return Err(ApiError::Forbidden(
                "gas sponsorship is not enabled for this wallet".into(),
            ))
        }
    };

    // 2. Enforce the per-transaction fee cap.
    if let Some(cap) = config.per_tx_fee_cap_stroops {
        if max_fee > cap {
            return Err(ApiError::BadRequest(format!(
                "max_base_fee_stroops exceeds the per-transaction cap of {cap}"
            )));
        }
    }

    // 3. Validate the inner XDR (global + per-wallet op allowlist, no self-sponsorship) before signing.
    validate_inner_xdr(
        &inner_xdr,
        &wallet.stellar_account_g,
        config.allowed_operations.as_deref(),
    )?;

    // A client-custody wallet has no server-side key to pay fees from; refuse before reserving.
    if wallet.sealed_ciphertext.is_none()
        || wallet.sealed_nonce.is_none()
        || wallet.sealed_salt.is_none()
    {
        return Err(ApiError::Forbidden(
            "this wallet is client-custody and has no gas-tank account to pay fees from; \
             provision and fund a gas tank to enable sponsorship"
                .into(),
        ));
    }

    // Pre-flight sequence check to save a wasted budget reservation and signature on a doomed submission.
    let live_seq = state
        .horizon()
        .account_sequence(&wallet.stellar_account_g)
        .await
        .map_err(|e| match e {
            ApiError::NotFound => ApiError::BadRequest(
                "This wallet is not funded on-chain yet. Fund it with XLM (testnet friendbot) first."
                    .into(),
            ),
            other => other,
        })?;
    let inner_seq = inner_sequence_number(&inner_xdr)?;
    if inner_seq <= live_seq {
        return Err(ApiError::StaleSequence(
            "Stale sequence number — refresh signing info and rebuild the transaction.".into(),
        ));
    }

    // 4. Compute the inner tx hash (the dedup key).
    let inner_hash = compute_inner_tx_hash(&inner_xdr, state.network())?;
    Ok(Preflight {
        wallet,
        config,
        inner_xdr,
        max_fee,
        inner_hash_hex: hex::encode(inner_hash),
    })
}

/// `POST /v1/wallets/:id/sponsor/validate` — dry-run of [`sponsor`] (#463).
///
/// Runs [`preflight`] plus a read-only projection of the dedup and daily-budget checks, then
/// reports the verdict. Never signs, reserves budget, submits, audits or fires a webhook. A
/// rejection the real call would return is a `200` with `verdict: "rejected"`; auth failures and
/// upstream/internal errors still answer as errors, since no verdict can be given.
pub async fn validate_sponsor(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<SponsorValidateResponse>>> {
    authorize_wallet_scope(&headers, &state, wallet_id, "sponsor").await?;
    let req: SponsorRequest = parse_optional(&body)?;
    let requested_fee = req.max_base_fee_stroops.filter(|f| *f > 0);

    let resp = match dry_run(&state, wallet_id, req).await {
        Ok((p, budget_remaining_stroops)) => SponsorValidateResponse {
            verdict: "accepted",
            reason: None,
            rejection_status: None,
            rejection_code: None,
            projected_fee_stroops: Some(p.max_fee),
            inner_tx_hash: Some(p.inner_hash_hex),
            budget_remaining_stroops,
        },
        Err(e) => {
            let (status, message) = e.parts();
            if !is_verdict(status) {
                return Err(e);
            }
            SponsorValidateResponse {
                verdict: "rejected",
                reason: Some(message),
                rejection_status: Some(status.as_u16()),
                rejection_code: Some(e.code()),
                projected_fee_stroops: requested_fee,
                inner_tx_hash: None,
                budget_remaining_stroops: None,
            }
        }
    };
    Ok(Envelope::ok(resp))
}

/// [`preflight`] plus the dedup and budget guards evaluated without reserving.
async fn dry_run(
    state: &AppState,
    wallet_id: Uuid,
    req: SponsorRequest,
) -> ApiResult<(Preflight, Option<i64>)> {
    let p = preflight(state, wallet_id, req).await?;
    let (spent_today, already_sponsored) = state
        .store()
        .sponsorship_projection(wallet_id, &p.inner_hash_hex)
        .await?;
    // Same mapping the real reservation's store errors get: duplicate → 409, over budget → 429.
    if already_sponsored {
        return Err(octo_store::StoreError::Conflict.into());
    }
    let remaining = match p.config.daily_budget_stroops {
        Some(budget) => {
            let left = budget - spent_today - p.max_fee;
            if left < 0 {
                return Err(octo_store::StoreError::BudgetExceeded.into());
            }
            Some(left)
        }
        None => None,
    };
    Ok((p, remaining))
}

/// Client-caused refusals become a verdict; auth, upstream and internal failures stay errors.
fn is_verdict(status: StatusCode) -> bool {
    status.is_client_error() && status != StatusCode::UNAUTHORIZED
}

/// `POST /v1/wallets/:id/sponsor` — fee-bump a user's transaction from the master wallet.
pub async fn sponsor(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<SponsorResponse>>)> {
    // Login JWT or API key, scoped to this wallet.
    authorize_wallet_scope(&headers, &state, wallet_id, "sponsor").await?;
    // Serialize fee-bump submissions for this wallet so two callers cannot pass the same
    // sequence preflight concurrently. The guard is held through Horizon submission.
    let _sequence_guard = state.sequence_lock(wallet_id.to_string()).await;

    let req: SponsorRequest = parse_optional(&body)?;
    let Preflight {
        wallet,
        config,
        inner_xdr,
        max_fee,
        inner_hash_hex,
    } = preflight(&state, wallet_id, req).await?;

    // Reserve budget atomically (BudgetExceeded -> 429, Conflict -> 409).
    let reserved = state
        .store()
        .try_reserve_sponsored_transaction(
            wallet_id,
            &inner_hash_hex,
            max_fee,
            config.daily_budget_stroops,
        )
        .await?;

    // 5. Sign the fee-bump (decrypt -> derive -> sign -> zeroize, inside wallet-core).
    // Only server-custody rows (legacy wallets / gas-tank fee accounts) carry a sealed seed;
    // preflight already refused wallets without one.
    let (Some(ciphertext), Some(nonce), Some(salt)) = (
        wallet.sealed_ciphertext.as_ref(),
        wallet.sealed_nonce.as_ref(),
        wallet.sealed_salt.as_ref(),
    ) else {
        let _ = state
            .store()
            .finalize_sponsored_transaction(reserved.id, "failed", None, Some("no gas tank"))
            .await;
        return Err(ApiError::Internal);
    };
    // Rows written before the scheme tag existed fall back to V1.
    let scheme = wallet
        .sealed_scheme
        .unwrap_or(octo_crypto::SCHEME_V1 as i16);
    let scheme_byte = u8::try_from(scheme).map_err(|_| ApiError::Internal)?;
    let sealed = SealedSeed::from_parts_with_scheme(ciphertext.clone(), nonce, salt, scheme_byte)
        .map_err(|_| ApiError::Internal)?;
    let fb = FeeBumpRequest {
        inner_xdr: &inner_xdr,
        max_base_fee_stroops: max_fee,
    };
    // During a rotation the row may be sealed under either key; AES-GCM tells us which.
    let signed = match state
        .opening_keys()
        .find_map(|key| sign_fee_bump(key, &sealed, state.network(), 0, &fb).ok())
    {
        Some(s) => s,
        None => {
            let _ = state
                .store()
                .finalize_sponsored_transaction(reserved.id, "failed", None, Some("signing failed"))
                .await;
            return Err(ApiError::Internal);
        }
    };

    // 6. Submit to Horizon and finalize the record.
    let submit = state
        .horizon()
        .submit_transaction(&signed.envelope_xdr)
        .await;
    let (status, fee_bump_hash) = match submit {
        Ok(r) if r.successful => ("confirmed", Some(r.hash)),
        Ok(r) => ("failed", Some(r.hash)),
        Err(_) => ("failed", None),
    };
    let _ = state
        .store()
        .finalize_sponsored_transaction(reserved.id, status, fee_bump_hash.as_deref(), None)
        .await;

    // 7. Audit log (best-effort) — only when driven by a dashboard login (API keys have no user).
    if let Ok(user_id) = crate::auth::require_login(&headers, &state).await {
        if wallet.user_id == Some(user_id) {
            crate::audit::record(
                &state,
                user_id,
                &format!("sponsored a transaction ({status})"),
                crate::audit::category::SPONSORSHIP,
                Some(&inner_hash_hex),
                &headers,
            )
            .await;
        }
    }

    // 8. Fire a transaction.sponsored webhook (best-effort).
    state
        .webhooks()
        .dispatch(
            wallet_id,
            &octo_webhooks::Event {
                event_type: "transaction.sponsored".to_string(),
                data: serde_json::json!({
                    "id": reserved.id,
                    "wallet_id": wallet_id,
                    "inner_tx_hash": inner_hash_hex,
                    "fee_bump_tx_hash": fee_bump_hash,
                    "fee_stroops": max_fee,
                    "status": status,
                }),
            },
        )
        .await;

    let resp = SponsorResponse {
        id: reserved.id,
        status: status.to_string(),
        inner_tx_hash: inner_hash_hex,
        fee_bump_tx_hash: fee_bump_hash,
        fee_stroops: max_fee,
    };
    let (code, json) = Envelope::created(resp);
    Ok((code, json))
}

#[derive(Debug, Deserialize)]
pub struct SponsoredTxnQuery {
    /// Maximum rows to return (default 50, max 200).
    pub limit: Option<i64>,
    /// Filter by status: pending | confirmed | failed.
    pub status: Option<String>,
    /// Cursor: return rows created before this id.
    pub before: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct SponsoredTxnListResponse {
    pub data: Vec<octo_store::SponsoredTransaction>,
    /// UUID of the last row in this page, or null if there are no more rows.
    pub next_cursor: Option<Uuid>,
}

/// `GET /v1/wallets/:id/sponsored-transactions`
pub async fn list_sponsored_transactions(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    Query(q): Query<SponsoredTxnQuery>,
) -> ApiResult<Json<Envelope<SponsoredTxnListResponse>>> {
    // JWT login session required (no API keys).
    let user_id = crate::auth::require_login(&headers, &state).await?;
    let wallet = state.store().get_wallet(wallet_id).await?;
    if wallet.user_id != Some(user_id) {
        return Err(ApiError::NotFound);
    }

    let limit = q.limit.unwrap_or(50);
    if limit > 200 {
        return Err(ApiError::BadRequest("limit must not exceed 200".into()));
    }
    if limit < 1 {
        return Err(ApiError::BadRequest("limit must be at least 1".into()));
    }

    let status = q.status.filter(|s| !s.is_empty());
    if let Some(ref s) = status {
        if !matches!(s.as_str(), "pending" | "confirmed" | "failed") {
            return Err(ApiError::BadRequest(
                "status must be one of: pending, confirmed, failed".into(),
            ));
        }
    }

    // Fetch limit+1 to detect if there are more rows.
    let rows = state
        .store()
        .list_sponsored_transactions(wallet_id, limit + 1, status.as_deref(), q.before)
        .await?;

    let has_more = rows.len() > limit as usize;
    let mut data = rows;
    if has_more {
        // Drop the sentinel extra row; we only fetched it to detect `has_more`.
        data.truncate(limit as usize);
    }
    // The cursor is the LAST row actually returned, so the next page starts strictly after it.
    let next_cursor = if has_more {
        data.last().map(|r| r.id)
    } else {
        None
    };

    Ok(Envelope::ok(SponsoredTxnListResponse { data, next_cursor }))
}
