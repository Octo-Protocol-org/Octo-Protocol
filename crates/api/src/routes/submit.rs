//! Non-custodial submit endpoint: relay a client-signed transaction to Horizon.
//!
//! The private key never touches the server — the client builds and signs locally (dashboard or
//! SDK) and Octo validates, submits, and records history. Authorization to *move funds* is the
//! user's own ed25519 signature (checked by the network); the API credential only authorizes use
//! of Octo's relay + bookkeeping.

use crate::auth::authorize_wallet;
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use crate::submit_validation::validate_signed_xdr;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use octo_wallet_core::compute_inner_tx_hash;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Default, Deserialize)]
pub struct SubmitSignedRequest {
    /// Base64 XDR of the client-signed v1 `TransactionEnvelope`.
    pub transaction_xdr: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SubmitSignedResponse {
    pub status: String,
    pub stellar_tx_hash: Option<String>,
    /// Human-readable reason when `status == "failed"` (from Horizon result codes).
    pub detail: Option<String>,
}

/// Map common Stellar result codes to human-readable explanations.
fn explain_code(code: &str) -> String {
    match code {
        "op_underfunded" => "Insufficient balance to cover this amount.".into(),
        "op_low_reserve" => {
            "Not enough XLM to satisfy the base reserve (each trustline/subentry reserves 0.5 XLM)."
                .into()
        }
        "op_no_destination" => "The destination account does not exist on this network.".into(),
        "op_no_trust" => {
            "The destination has no trustline for this asset — they must add one first.".into()
        }
        "op_no_issuer" => "The asset issuer does not exist on this network.".into(),
        "op_invalid_limit" => "The trust limit is invalid.".into(),
        "op_line_full" => "The destination's trustline limit would be exceeded.".into(),
        "tx_bad_seq" => {
            "Stale sequence number — refresh signing info and rebuild the transaction.".into()
        }
        "tx_bad_auth" => {
            "Signature verification failed — the transaction was not signed by this wallet's key."
                .into()
        }
        "tx_insufficient_fee" => "The network fee was too low; rebuild with a higher fee.".into(),
        other => format!("Transaction failed ({other})."),
    }
}

/// `POST /v1/wallets/:id/submit-signed`
pub async fn submit_signed(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<SubmitSignedResponse>>)> {
    authorize_wallet(&headers, &state, wallet_id).await?;
    // For the audit log only: present when the caller used a login JWT (None for API keys).
    let audit_user = crate::auth::authenticate(&headers, &state).await.ok();
    let wallet = state.store().get_wallet(wallet_id).await?;

    let req: SubmitSignedRequest = parse_optional(&body)?;
    let signed_xdr = req
        .transaction_xdr
        .filter(|x| !x.is_empty())
        .ok_or_else(|| ApiError::BadRequest("transaction_xdr is required".into()))?;

    // Pure validation: v1 envelope, ≥1 signature, source == this wallet, op allowlist.
    let payment = validate_signed_xdr(&signed_xdr, &wallet.stellar_account_g)?;

    // Compute the canonical tx hash up-front so the response/record always reference it, even
    // when Horizon submission errors out at the transport layer.
    let precomputed_hash = hex::encode(
        compute_inner_tx_hash(&signed_xdr, state.network())
            .map_err(|_| ApiError::BadRequest("transaction_xdr could not be hashed".into()))?,
    );

    let submit = state.horizon().submit_transaction(&signed_xdr).await;

    let (status, hash, detail) = match submit {
        Ok(r) if r.successful => ("confirmed", Some(r.hash), None),
        Ok(r) => {
            let reason = r
                .operation_codes
                .iter()
                .find(|c| c.as_str() != "op_success")
                .map(|c| explain_code(c))
                .or_else(|| r.transaction_code.as_deref().map(explain_code));
            ("failed", Some(r.hash), reason)
        }
        Err(ApiError::BadRequest(msg)) => ("failed", Some(precomputed_hash), Some(msg)),
        Err(_) => (
            "failed",
            Some(precomputed_hash),
            Some("Could not reach the Stellar network — try again.".into()),
        ),
    };

    // Record outbound payments in the history the dashboard lists (best-effort).
    if let Some(p) = &payment {
        let _ = state
            .store()
            .record_withdrawal_transaction(
                wallet_id,
                &p.asset_code,
                p.asset_issuer.as_deref(),
                p.amount_stroops,
                &wallet.stellar_account_g,
                &p.destination,
                hash.as_deref(),
                status,
            )
            .await;
    }

    if let Some(user_id) = audit_user {
        crate::audit::record(
            &state,
            user_id,
            &format!("submitted a signed transaction ({status})"),
            crate::audit::category::WALLET,
            payment.as_ref().map(|p| p.destination.as_str()),
            &headers,
        )
        .await;
    }

    let resp = SubmitSignedResponse {
        status: status.to_string(),
        stellar_tx_hash: hash,
        detail,
    };
    let (code, json) = Envelope::created(resp);
    Ok((code, json))
}

/// `GET /v1/wallets/:id/signing-info` — what a client needs to build a transaction locally:
/// the account's current sequence number plus network parameters. No Horizon access required
/// client-side.
pub async fn signing_info(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<SigningInfo>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;
    let wallet = state.store().get_wallet(wallet_id).await?;

    let sequence = state
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

    Ok(Envelope::ok(SigningInfo {
        account: wallet.stellar_account_g,
        sequence,
        network_passphrase: state.network().passphrase().to_string(),
        base_fee_stroops: 100,
    }))
}

#[derive(Debug, Serialize)]
pub struct SigningInfo {
    pub account: String,
    /// The account's current sequence number, as a **string**.
    ///
    /// This is not stylistic. Stellar sequence numbers are `(ledger << 32)`-based and are already
    /// ~1.6e16 on testnet, which is past JavaScript's `Number.MAX_SAFE_INTEGER` (9.007e15). Sent
    /// as a JSON number, `JSON.parse` silently rounds it — e.g. ...466433 becomes ...466432, one
    /// too low — so the client signs with a stale sequence and Horizon rejects the transaction
    /// with `tx_bad_seq`. The first withdrawal after funding happens to land on an even value and
    /// succeeds, which makes this look like an intermittent bug rather than a rounding one.
    ///
    /// Horizon itself returns `sequence` as a string for exactly this reason; we match it.
    #[serde(with = "crate::json::i64_as_string")]
    pub sequence: i64,
    pub network_passphrase: String,
    pub base_fee_stroops: i64,
}
