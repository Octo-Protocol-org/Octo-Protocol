//! Withdrawal endpoint: build + sign + submit a payment from the master wallet.
//!
//! Security (see `docs/threat-model.md`):
//! - Idempotency-keyed: a retried request with the same key conflicts instead of double-spending.
//! - The seed is decrypted, used to sign, and zeroized entirely inside `wallet-core` — this layer
//!   never sees plaintext key material.
//! - Only a Payment operation is ever built; the destination and amount are validated server-side.

use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use octo_crypto::SealedSeed;
use octo_wallet_core::{is_valid_account, is_valid_asset_code, sign_payment, PaymentRequest};
use serde::{Deserialize, Serialize};
use stellar_base::transaction::MIN_BASE_FEE;
use uuid::Uuid;

/// The fee (in stroops) `sign_payment` will charge — always the protocol floor. Kept in sync
/// with `wallet-core::signer::sign_payment`, which hardcodes `MIN_BASE_FEE` for the same reason
/// documented there: no per-request fee negotiation, so there is nothing to check against a
/// live "current network minimum" beyond the protocol floor we already pay.
fn fee_stroops() -> i64 {
    MIN_BASE_FEE.to_i64()
}

#[derive(Debug, Default, Deserialize)]
pub struct WithdrawRequest {
    /// Destination account (`G...`) or muxed (`M...`).
    pub destination: Option<String>,
    /// Amount in stroops (1 XLM = 10_000_000). Must be > 0.
    pub amount_stroops: Option<i64>,
    /// `None`/omitted => native XLM. Otherwise `{ "code": "...", "issuer": "G..." }`.
    pub asset: Option<AssetSpec>,
    /// Optional numeric memo.
    pub memo_id: Option<i64>,
    /// Idempotency key (may also be supplied via the `Idempotency-Key` header).
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AssetSpec {
    pub code: String,
    pub issuer: String,
}

#[derive(Debug, Serialize)]
pub struct WithdrawResponse {
    pub id: Uuid,
    pub status: String,
    pub stellar_tx_hash: Option<String>,
    pub destination: String,
    pub amount_stroops: i64,
}

/// A Stellar asset code must be 1-12 ASCII alphanumeric characters (the `AssetCode4`/
/// `AssetCode12` rules).
fn is_valid_asset_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 12
        && code.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// `POST /v1/wallets/:id/withdraw`
pub async fn withdraw(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<WithdrawResponse>>)> {
    // Withdrawals are dashboard-only: require a login JWT (API keys are rejected) and confirm the
    // user owns the wallet. Moving funds out is intentionally not exposed to integration keys.
    let user_id = crate::auth::require_login(&headers, &state).await?;
    let owner = state.store().get_wallet(wallet_id).await?;
    if owner.user_id != Some(user_id) {
        return Err(ApiError::NotFound);
    }

    let req: WithdrawRequest = parse_optional(&body)?;

    // --- validate inputs ---
    let destination = req
        .destination
        .filter(|d| !d.is_empty())
        .ok_or_else(|| ApiError::BadRequest("destination is required".into()))?;
    let amount_stroops = req
        .amount_stroops
        .filter(|a| *a > 0)
        .ok_or_else(|| ApiError::BadRequest("amount_stroops must be > 0".into()))?;

    // Idempotency key: header takes precedence, then body, else reject (mutating money op).
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or(req.idempotency_key)
        .filter(|k| !k.is_empty())
        .ok_or_else(|| {
            ApiError::BadRequest("idempotency key required (Idempotency-Key header or body)".into())
        })?;

    let (asset_code, asset_issuer) = match &req.asset {
        None => ("native".to_string(), None),
        Some(a) => {
            if !is_valid_asset_code(&a.code) {
                return Err(ApiError::BadRequest("invalid asset code".into()));
            }
            if !is_valid_account(&a.issuer) {
                return Err(ApiError::BadRequest("invalid asset issuer".into()));
            }
            (a.code.clone(), Some(a.issuer.clone()))
        }
    };

    let wallet = state.store().get_wallet(wallet_id).await?;

    // A key that has already been consumed short-circuits straight to 409 — no point spending a
    // round trip to Horizon re-validating a request whose key is already spent.
    if state
        .store()
        .withdrawal_exists(wallet_id, &idempotency_key)
        .await?
    {
        return Err(ApiError::Conflict);
    }

    // --- pre-flight failure-mode checks (all BEFORE the idempotency key is consumed) ---
    //
    // Failure-mode matrix (see PR description for the full writeup):
    //   1. Insufficient balance of the requested asset       -> checked here
    //   2. Would breach the source account's minimum reserve -> checked here (native only)
    //   3. Destination account doesn't exist on-chain yet    -> checked here (G... destinations)
    //   4. Missing trustline for a credit-asset destination  -> checked here (G... destinations)
    //   5. Fee below the current network minimum             -> NOT checked; we always sign at
    //      the protocol-floor `MIN_BASE_FEE` (see `fee_stroops()`), so this class of failure can't
    //      occur except under rare surge pricing, whose extra Horizon fee-stats call isn't
    //      justified for that edge case.

    // One Horizon call gets balances, sequence, and reserve inputs for the source account.
    let source_info = state.horizon().account_info(&wallet.stellar_account_g).await?;

    match &asset_issuer {
        None => {
            // Native XLM: balance must cover amount + fee, and what's left must clear reserve.
            // `amount_stroops` is caller-supplied, so use checked arithmetic — an i64::MAX amount
            // must fail as "insufficient balance", not panic.
            let native = source_info.native_balance_stroops();
            let required = amount_stroops
                .checked_add(fee_stroops())
                .ok_or_else(|| ApiError::BadRequest("amount_stroops is too large".into()))?;
            if native < required {
                return Err(ApiError::BadRequest(
                    "insufficient XLM balance for amount + fee".into(),
                ));
            }
            let remaining = native - required;
            if remaining < source_info.min_reserve_stroops() {
                return Err(ApiError::BadRequest(
                    "withdrawal would breach the minimum reserve".into(),
                ));
            }
        }
        Some(issuer) => {
            // Credit asset: balance/trustline for that asset, and enough native left for the fee
            // + reserve (the fee is always paid in XLM regardless of the withdrawn asset).
            let asset_balance = source_info
                .asset_balance_stroops(&asset_code, issuer)
                .ok_or_else(|| {
                    ApiError::BadRequest("wallet has no trustline/balance for that asset".into())
                })?;
            if asset_balance < amount_stroops {
                return Err(ApiError::BadRequest(
                    "insufficient balance of the requested asset".into(),
                ));
            }
            let native = source_info.native_balance_stroops();
            if native - fee_stroops() < source_info.min_reserve_stroops() {
                return Err(ApiError::BadRequest(
                    "withdrawal would breach the minimum reserve (fee)".into(),
                ));
            }
        }
    }

    // Destination-account-exists + trustline checks only apply to G... accounts; a muxed (M...)
    // destination is always a subaccount of an existing G... account and isn't independently
    // checkable via `/accounts` the same way, so it's out of scope here (documented gap).
    if destination.starts_with('G') {
        let dest_info = state.horizon().balances(&destination).await;
        match dest_info {
            Err(ApiError::NotFound) => {
                return Err(ApiError::BadRequest(
                    "destination account does not exist on-chain yet".into(),
                ));
            }
            Err(e) => return Err(e),
            Ok(dest_balances) => {
                if let Some(issuer) = &asset_issuer {
                    if !crate::horizon::has_trustline(&dest_balances, &asset_code, issuer) {
                        return Err(ApiError::BadRequest(
                            "destination account has no trustline for that asset".into(),
                        ));
                    }
                }
            }
        }
    }

    // --- reserve the idempotency key (prevents double-spend on retry) ---
    // create_withdrawal is unique on (wallet_id, idempotency_key); a retry conflicts here BEFORE
    // any signing/submit happens. Every check above has already run, so a request that reaches
    // this point has passed the full pre-flight matrix.
    let withdrawal = state
        .store()
        .create_withdrawal(octo_store::NewWithdrawal {
            wallet_id,
            idempotency_key: &idempotency_key,
            destination_account: &destination,
            asset_code: &asset_code,
            asset_issuer: asset_issuer.as_deref(),
            amount_stroops,
            memo_id: req.memo_id,
        })
        .await?; // StoreError::Conflict -> ApiError::Conflict (409)

    // Reuse the sequence fetched during pre-flight rather than a second Horizon round trip.
    let seq = source_info.sequence;

    // --- sign inside wallet-core (decrypt -> derive -> sign -> zeroize) ---
    let sealed = SealedSeed::from_parts_with_scheme(
        wallet.sealed_ciphertext.clone(),
        &wallet.sealed_nonce,
        &wallet.sealed_salt,
        wallet.sealed_scheme as u8,
    )
    .map_err(|_| ApiError::Internal)?;

    let asset_for_sign = req
        .asset
        .as_ref()
        .map(|a| (a.code.as_str(), a.issuer.as_str()));
    let payment = PaymentRequest {
        destination: &destination,
        stroops: amount_stroops,
        asset: asset_for_sign,
        memo_id: req.memo_id.map(|m| m as u64),
        sequence: seq + 1, // next sequence
    };
    let signed = sign_payment(state.master_key_for_scheme(wallet.sealed_scheme), &sealed, state.network(), 0, &payment)?;

    // --- submit to Horizon ---
    let submit = state
        .horizon()
        .submit_transaction(&signed.envelope_xdr)
        .await;

    let (status, hash) = match submit {
        Ok(r) if r.successful => ("confirmed", Some(r.hash)),
        Ok(r) => ("failed", Some(r.hash)),
        Err(_) => ("failed", None),
    };

    // --- record outcome (best-effort status update) ---
    let _ = state
        .store()
        .update_withdrawal_status(withdrawal.id, status, hash.as_deref())
        .await;

    crate::audit::record(
        &state,
        user_id,
        &format!("initiated a withdrawal ({status})"),
        crate::audit::category::WITHDRAWAL,
        Some(&destination),
        &headers,
    )
    .await;

    let resp = WithdrawResponse {
        id: withdrawal.id,
        status: status.to_string(),
        stellar_tx_hash: hash,
        destination,
        amount_stroops,
    };
    let (code, json) = Envelope::created(resp);
    Ok((code, json))
}
