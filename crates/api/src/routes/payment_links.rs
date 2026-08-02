//! Payment links: shareable public URLs that accept a USDC deposit.

use crate::auth::authorize_wallet;
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use octo_wallet_core::encode_muxed;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const USDC_ASSET_CODE: &str = "USDC";
/// The widely-used testnet USDC issuer (same one the dashboard's trustline flow uses) — v1
/// payment links are USDC-only, so a submitted payment must actually be this asset, not just
/// any asset landing at the right address.
const USDC_TESTNET_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

#[derive(Debug, Serialize)]
pub struct PaymentLinkView {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub image_url: Option<String>,
    pub amount_usdc_stroops: Option<i64>,
    pub active: bool,
    pub collected_usdc_stroops: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CreatePaymentLinkRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub image_url: Option<String>,
    pub amount_usdc_stroops: Option<i64>,
}

/// `POST /v1/wallets/:id/payment-links`
pub async fn create_payment_link(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<PaymentLinkView>>)> {
    authorize_wallet(&headers, &state, wallet_id).await?;
    let req: CreatePaymentLinkRequest = parse_optional(&body)?;
    let name = req
        .name
        .filter(|n| !n.is_empty())
        .ok_or_else(|| ApiError::BadRequest("name is required".into()))?;

    let wallet = state.store().get_wallet(wallet_id).await?;
    let base = wallet.stellar_account_g.clone();
    let address = state
        .store()
        .allocate_address(
            wallet_id,
            |id| {
                let id_u64 = u64::try_from(id).map_err(|_| ())?;
                encode_muxed(&base, id_u64).map_err(|_| ())
            },
            None,
            serde_json::json!({}),
        )
        .await?;

    let slug = Uuid::new_v4().simple().to_string()[..10].to_string();
    let link = state
        .store()
        .create_payment_link(octo_store::NewPaymentLink {
            wallet_id,
            address_id: address.id,
            slug: &slug,
            name: &name,
            description: req.description.as_deref(),
            image_url: req.image_url.as_deref(),
            amount_usdc_stroops: req.amount_usdc_stroops,
        })
        .await?;

    let (code, json) = Envelope::created(PaymentLinkView {
        id: link.id,
        slug: link.slug,
        name: link.name,
        description: link.description,
        image_url: link.image_url,
        amount_usdc_stroops: link.amount_usdc_stroops,
        active: link.active,
        collected_usdc_stroops: 0,
        created_at: link.created_at,
    });
    Ok((code, json))
}

/// `GET /v1/wallets/:id/payment-links`
pub async fn list_payment_links(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<crate::routes::wallets::ListParams>,
) -> ApiResult<Json<Envelope<PaymentLinkListResponse>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;
    let limit = crate::routes::wallets::validated_limit(q.limit)?;

    let rows = state
        .store()
        .list_payment_links(wallet_id, limit + 1, q.before)
        .await?;
    let has_more = rows.len() > limit as usize;
    let mut items = rows;
    if has_more {
        items.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        items.last().map(|l| l.id)
    } else {
        None
    };

    let ids: Vec<Uuid> = items.iter().map(|l| l.id).collect();
    let totals: std::collections::HashMap<Uuid, i64> = state
        .store()
        .sum_payment_link_collected_batch(&ids)
        .await?
        .into_iter()
        .collect();

    let views = items
        .into_iter()
        .map(|l| PaymentLinkView {
            id: l.id,
            slug: l.slug,
            name: l.name,
            description: l.description,
            image_url: l.image_url,
            amount_usdc_stroops: l.amount_usdc_stroops,
            active: l.active,
            collected_usdc_stroops: totals.get(&l.id).copied().unwrap_or(0),
            created_at: l.created_at,
        })
        .collect();

    Ok(Envelope::ok(PaymentLinkListResponse {
        data: views,
        next_cursor,
    }))
}

#[derive(Debug, Serialize)]
pub struct PaymentLinkListResponse {
    pub data: Vec<PaymentLinkView>,
    pub next_cursor: Option<Uuid>,
}

/// `GET /v1/wallets/:id/payment-links/:link_id`
pub async fn get_payment_link(
    State(state): State<AppState>,
    Path((wallet_id, link_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> ApiResult<Json<Envelope<PaymentLinkView>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;
    let link = state.store().get_payment_link(wallet_id, link_id).await?;
    let collected = state.store().sum_payment_link_collected(link.id).await?;
    Ok(Envelope::ok(PaymentLinkView {
        id: link.id,
        slug: link.slug,
        name: link.name,
        description: link.description,
        image_url: link.image_url,
        amount_usdc_stroops: link.amount_usdc_stroops,
        active: link.active,
        collected_usdc_stroops: collected,
        created_at: link.created_at,
    }))
}

#[derive(Debug, Default, Deserialize)]
pub struct SetPaymentLinkActiveRequest {
    pub active: Option<bool>,
}

/// `PUT /v1/wallets/:id/payment-links/:link_id`
pub async fn set_payment_link_active(
    State(state): State<AppState>,
    Path((wallet_id, link_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Envelope<PaymentLinkView>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;
    let req: SetPaymentLinkActiveRequest = parse_optional(&body)?;
    let active = req
        .active
        .ok_or_else(|| ApiError::BadRequest("active is required".into()))?;
    let link = state
        .store()
        .set_payment_link_active(wallet_id, link_id, active)
        .await?;
    let collected = state.store().sum_payment_link_collected(link.id).await?;
    Ok(Envelope::ok(PaymentLinkView {
        id: link.id,
        slug: link.slug,
        name: link.name,
        description: link.description,
        image_url: link.image_url,
        amount_usdc_stroops: link.amount_usdc_stroops,
        active: link.active,
        collected_usdc_stroops: collected,
        created_at: link.created_at,
    }))
}

#[derive(Debug, Serialize)]
pub struct PublicPaymentLinkView {
    pub name: String,
    pub description: Option<String>,
    pub image_url: Option<String>,
    pub amount_usdc_stroops: Option<i64>,
    pub deposit_address: String,
    pub asset_code: String,
}

/// `GET /v1/pay/:slug` — public, no auth.
pub async fn get_public_payment_link(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> ApiResult<Json<Envelope<PublicPaymentLinkView>>> {
    let link = state.store().get_payment_link_by_slug(&slug).await?;
    if !link.active {
        return Err(ApiError::NotFound);
    }
    let address = state
        .store()
        .get_address(link.address_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Envelope::ok(PublicPaymentLinkView {
        name: link.name,
        description: link.description,
        image_url: link.image_url,
        amount_usdc_stroops: link.amount_usdc_stroops,
        deposit_address: address.muxed_address,
        asset_code: USDC_ASSET_CODE.into(),
    }))
}

#[derive(Debug, Default, Deserialize)]
pub struct CreatePaymentIntentRequest {
    pub payer_name: Option<String>,
    pub payer_email: Option<String>,
    pub amount_usdc_stroops: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct PaymentIntentView {
    pub payment_id: Uuid,
    pub deposit_address: String,
    pub amount_usdc_stroops: i64,
}

/// `POST /v1/pay/:slug/intent` — public, no auth.
pub async fn create_payment_intent(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<PaymentIntentView>>)> {
    let link = state.store().get_payment_link_by_slug(&slug).await?;
    if !link.active {
        return Err(ApiError::NotFound);
    }
    let req: CreatePaymentIntentRequest = parse_optional(&body)?;

    // A fixed-amount link ignores whatever the payer sends; a flexible one requires a positive amount.
    let amount = match link.amount_usdc_stroops {
        Some(fixed) => fixed,
        None => req
            .amount_usdc_stroops
            .filter(|a| *a > 0)
            .ok_or_else(|| ApiError::BadRequest("amount_usdc_stroops is required".into()))?,
    };

    let payment = state
        .store()
        .record_payment_link_intent(
            link.id,
            req.payer_name.as_deref(),
            req.payer_email.as_deref(),
            amount,
        )
        .await?;
    let address = state
        .store()
        .get_address(link.address_id)
        .await?
        .ok_or(ApiError::NotFound)?;

    let (code, json) = Envelope::created(PaymentIntentView {
        payment_id: payment.id,
        deposit_address: address.muxed_address,
        amount_usdc_stroops: amount,
    });
    Ok((code, json))
}

#[derive(Debug, Serialize)]
pub struct PaymentStatusView {
    pub status: String,
    pub transaction_id: Option<Uuid>,
}

/// `GET /v1/pay/:slug/payments/:payment_id` — public, no auth.
pub async fn get_payment_status(
    State(state): State<AppState>,
    Path((slug, payment_id)): Path<(String, Uuid)>,
) -> ApiResult<Json<Envelope<PaymentStatusView>>> {
    let link = state.store().get_payment_link_by_slug(&slug).await?;
    let payment = state
        .store()
        .get_payment_link_payment(link.id, payment_id)
        .await?;
    Ok(Envelope::ok(PaymentStatusView {
        status: payment.status,
        transaction_id: payment.transaction_id,
    }))
}

/// `GET /v1/pay/:slug/signing-info` — public, no auth. Lets a Freighter payer build a
/// transaction locally without needing direct Horizon access.
#[derive(Debug, Default, Deserialize)]
pub struct PublicSigningInfoParams {
    /// The PAYER's own account (e.g. from Freighter) — this is the transaction's source, so its
    /// sequence number is what the built transaction must use, not the merchant's.
    pub account: Option<String>,
}

pub async fn public_signing_info(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(params): Query<PublicSigningInfoParams>,
) -> ApiResult<Json<Envelope<crate::routes::submit::SigningInfo>>> {
    // Confirms the link exists/is active before doing any Horizon work on the caller's behalf.
    let link = state.store().get_payment_link_by_slug(&slug).await?;
    if !link.active {
        return Err(ApiError::NotFound);
    }

    let account = match params.account {
        Some(a) => a,
        None => {
            state
                .store()
                .get_wallet(link.wallet_id)
                .await?
                .stellar_account_g
        }
    };
    let sequence = state.horizon().account_sequence(&account).await?;
    Ok(Envelope::ok(crate::routes::submit::SigningInfo {
        account,
        sequence,
        network_passphrase: state.network().passphrase().to_string(),
        base_fee_stroops: 100,
    }))
}

#[derive(Debug, Default, Deserialize)]
pub struct SubmitPaymentRequest {
    pub transaction_xdr: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SubmitPaymentResponse {
    pub status: String,
    pub stellar_tx_hash: Option<String>,
    pub detail: Option<String>,
}

/// `POST /v1/pay/:slug/submit-signed` — public, no auth. A payer relays a transaction they signed
/// themselves (e.g. via Freighter). Only a Payment to this link's own deposit address is allowed
/// — nothing else the payer's wallet might otherwise be able to spend.
pub async fn submit_payment(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<SubmitPaymentResponse>>)> {
    let link = state.store().get_payment_link_by_slug(&slug).await?;
    if !link.active {
        return Err(ApiError::NotFound);
    }
    let address = state
        .store()
        .get_address(link.address_id)
        .await?
        .ok_or(ApiError::NotFound)?;

    let req: SubmitPaymentRequest = parse_optional(&body)?;
    let signed_xdr = req
        .transaction_xdr
        .filter(|x| !x.is_empty())
        .ok_or_else(|| ApiError::BadRequest("transaction_xdr is required".into()))?;

    use stellar_base::xdr::{OperationBody, TransactionEnvelope, XDRDeserialize};
    let env = TransactionEnvelope::from_xdr_base64(&signed_xdr)
        .map_err(|_| ApiError::BadRequest("transaction_xdr is not valid base64 XDR".into()))?;
    let v1 = match env {
        TransactionEnvelope::Tx(v1) => v1,
        _ => {
            return Err(ApiError::BadRequest(
                "transaction_xdr must be a v1 TransactionEnvelope".into(),
            ))
        }
    };
    if v1.signatures.is_empty() {
        return Err(ApiError::BadRequest(
            "transaction_xdr carries no signatures; sign it client-side first".into(),
        ));
    }
    // Exactly one Payment operation, to this link's own deposit address, in USDC — a payer's
    // signed transaction must not be able to do anything else through this relay, and must
    // actually be the asset this link advertises (not e.g. native XLM landing at the right
    // address, which would silently misreport the merchant's real received amount).
    let has_matching_payment = v1.tx.operations.iter().any(|op| {
        let OperationBody::Payment(p) = &op.body else {
            return false;
        };
        if crate::submit_validation::muxed_to_string(&p.destination) != address.muxed_address {
            return false;
        }
        let (asset_code, asset_issuer) = crate::submit_validation::asset_parts(&p.asset);
        asset_code == USDC_ASSET_CODE && asset_issuer.as_deref() == Some(USDC_TESTNET_ISSUER)
    });
    if !has_matching_payment || v1.tx.operations.len() != 1 {
        return Err(ApiError::BadRequest(
            "transaction_xdr must contain exactly one USDC Payment to this link's deposit address"
                .into(),
        ));
    }

    let submit = state.horizon().submit_transaction(&signed_xdr).await;
    let (status, hash, detail) = match submit {
        Ok(r) if r.successful => ("confirmed", Some(r.hash), None),
        Ok(r) => {
            let reason = r
                .operation_codes
                .iter()
                .find(|c| c.as_str() != "op_success")
                .cloned()
                .or(r.transaction_code.clone());
            ("failed", Some(r.hash), reason)
        }
        Err(ApiError::BadRequest(msg)) => ("failed", None, Some(msg)),
        Err(_) => (
            "failed",
            None,
            Some("Could not reach the Stellar network — try again.".into()),
        ),
    };

    let (code, json) = Envelope::created(SubmitPaymentResponse {
        status: status.to_string(),
        stellar_tx_hash: hash,
        detail,
    });
    Ok((code, json))
}
