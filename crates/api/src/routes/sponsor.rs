//! Sponsored transaction endpoints: sponsor a fee-bump, and list history.

use crate::auth::authorize_wallet;
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::sponsor_validation::validate_inner_xdr;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use octo_crypto::SealedSeed;
use octo_wallet_core::{compute_inner_tx_hash, sign_fee_bump, FeeBumpRequest};
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

/// `POST /v1/wallets/:id/sponsor` — fee-bump a user's transaction from the master wallet.
pub async fn sponsor(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<SponsorResponse>>)> {
    // Login JWT or API key, scoped to this wallet.
    authorize_wallet(&headers, &state, wallet_id).await?;

    let req: SponsorRequest = parse_optional(&body)?;
    let inner_xdr = req
        .transaction_xdr
        .filter(|x| !x.is_empty())
        .ok_or_else(|| ApiError::BadRequest("transaction_xdr is required".into()))?;
    let max_fee = req
        .max_base_fee_stroops
        .filter(|f| *f > 0)
        .ok_or_else(|| ApiError::BadRequest("max_base_fee_stroops must be > 0".into()))?;

    let wallet = state.store().get_wallet(wallet_id).await?;

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

    // 3. Validate the inner XDR (op allowlist + no self-sponsorship). Pure, no I/O.
    validate_inner_xdr(&inner_xdr, &wallet.stellar_account_g)?;

    // 4. Compute the inner tx hash (dedup key) and reserve budget atomically.
    let inner_hash = compute_inner_tx_hash(&inner_xdr, state.network())?;
    let inner_hash_hex = hex::encode(inner_hash);
    let reserved = state
        .store()
        .try_reserve_sponsored_transaction(
            wallet_id,
            &inner_hash_hex,
            max_fee,
            config.daily_budget_stroops,
        )
        .await?; // BudgetExceeded -> 429, Conflict -> 409

    // 5. Sign the fee-bump (decrypt -> derive -> sign -> zeroize, inside wallet-core).
    // Only server-custody rows (legacy wallets / gas-tank fee accounts) carry a sealed seed.
    // A client-custody wallet has no server-side key: sponsorship for those requires a funded
    // gas tank, which is provisioned separately.
    let (Some(ciphertext), Some(nonce), Some(salt)) = (
        wallet.sealed_ciphertext.as_ref(),
        wallet.sealed_nonce.as_ref(),
        wallet.sealed_salt.as_ref(),
    ) else {
        let _ = state
            .store()
            .finalize_sponsored_transaction(reserved.id, "failed", None, Some("no gas tank"))
            .await;
        return Err(ApiError::Forbidden(
            "this wallet is client-custody and has no gas-tank account to pay fees from; \
             provision and fund a gas tank to enable sponsorship"
                .into(),
        ));
    };
    // Keep the versioned-scheme path (PR #158) so master-key rotation keeps working. Rows
    // written before the scheme tag existed fall back to V1.
    let scheme = wallet.sealed_scheme.unwrap_or(octo_crypto::SCHEME_V1 as i16);
    let sealed = SealedSeed::from_parts_with_scheme(ciphertext.clone(), nonce, salt, scheme as u8)
        .map_err(|_| ApiError::Internal)?;
    let fb = FeeBumpRequest {
        inner_xdr: &inner_xdr,
        max_base_fee_stroops: max_fee,
    };
    let signed = match sign_fee_bump(
        state.master_key_for_scheme(scheme),
        &sealed,
        state.network(),
        0,
        &fb,
    ) {
        Ok(s) => s,
        Err(_) => {
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
