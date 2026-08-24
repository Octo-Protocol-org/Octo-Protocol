//! Address endpoints: generate a customer deposit address, list them with pagination.
//!
//! Response shape depends on the wallet's chain (see `docs/deposit-model.md`):
//! - **Stellar**: both forms — the muxed `M...` (default) and the `G...` + numeric `memo_id`
//!   fallback for senders that don't support muxed.
//! - **EVM**: a single real HD-derived EOA (`address`). There is no memo fallback — EVM has
//!   nowhere for a memo to go — so `memo_id`/`muxed_address`/`base_address` are omitted entirely
//!   from EVM responses (not merely `null`), so clients aren't encouraged to send a memo that
//!   would be silently dropped.

use crate::auth::authorize_wallet;
use crate::error::{ApiError, ApiResult, Envelope};
use crate::json::parse_optional;
use crate::routes::wallets::ListParams;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use octo_chain::{ChainAdapter, DepositAddress as ChainDepositAddress, DeriveInput, EvmAdapter};
use octo_crypto::SealedSeed;
use octo_store::{Address, Wallet};
use octo_wallet_core::encode_muxed;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request body for creating an address.
#[derive(Debug, Default, Deserialize)]
pub struct CreateAddressRequest {
    /// Opaque caller reference for their own user.
    #[serde(default)]
    pub customer_ref: Option<String>,
    /// Arbitrary metadata echoed back in webhooks.
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// An address, in whichever shape its chain produces — see the module doc.
#[derive(Debug, Serialize)]
pub struct AddressView {
    pub id: Uuid,
    pub customer_ref: Option<String>,
    /// `"stellar"` or `"evm"`, so a client can branch without inspecting which optional fields
    /// happen to be present.
    pub chain_kind: String,

    /// Stellar only: the muxed `M...` address (default form).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub muxed_address: Option<String>,
    /// Stellar only: the `G...` fallback base account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_address: Option<String>,
    /// Stellar only. **Never present on an EVM response** — EVM has no memo field, so advertising
    /// one would invite a client to send a memo that lands nowhere and is silently dropped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo_id: Option<i64>,

    /// EVM only: the EIP-55 checksummed deposit address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,

    pub metadata: serde_json::Value,
    /// Lifetime total (stroops) of confirmed deposits credited to this address. Always `0` for an
    /// EVM address today — EVM deposit crediting is a separate, not-yet-built ingest worker — but
    /// plumbed through rather than hardcoded so this doesn't need a signature change once it
    /// lands.
    pub received_stroops: i64,
}

impl AddressView {
    fn stellar(address: Address, base_address: String, received_stroops: i64) -> AddressView {
        AddressView {
            id: address.id,
            customer_ref: address.customer_ref,
            chain_kind: "stellar".into(),
            muxed_address: address.muxed_address,
            base_address: Some(base_address),
            memo_id: address.muxed_id,
            address: None,
            metadata: address.metadata,
            received_stroops,
        }
    }

    fn evm(address: Address, received_stroops: i64) -> AddressView {
        AddressView {
            id: address.id,
            customer_ref: address.customer_ref,
            chain_kind: "evm".into(),
            muxed_address: None,
            base_address: None,
            memo_id: None,
            address: address.evm_address,
            metadata: address.metadata,
            received_stroops,
        }
    }
}

/// Paginated list response for addresses.
#[derive(Debug, Serialize)]
pub struct AddressListResponse {
    pub data: Vec<AddressView>,
    /// UUID of the last row in this page, or null if there are no more rows.
    pub next_cursor: Option<Uuid>,
}

/// `POST /v1/wallets/{id}/addresses`
pub async fn create_address(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Envelope<AddressView>>)> {
    // Authorize via login JWT (wallet owner) or API key (key's wallet).
    authorize_wallet(&headers, &state, wallet_id).await?;
    let req: CreateAddressRequest = parse_optional(&body)?;
    let wallet = state.store().get_wallet(wallet_id).await?;
    let metadata = req.metadata.unwrap_or_else(|| serde_json::json!({}));

    let view = if wallet.is_evm() {
        let address =
            allocate_evm_address(&state, &wallet, req.customer_ref.as_deref(), metadata).await?;
        AddressView::evm(address, 0)
    } else {
        // allocate_address bumps the muxed-id counter atomically and derives the M... via this
        // closure. Unchanged from before EVM support existed.
        let base = wallet.stellar_account_g.clone();
        let address = state
            .store()
            .allocate_address(
                wallet_id,
                |id| {
                    // muxed_id is a positive i64 from the counter; encode needs u64.
                    let id_u64 = u64::try_from(id).map_err(|_| ())?;
                    encode_muxed(&base, id_u64).map_err(|_| ())
                },
                req.customer_ref.as_deref(),
                metadata,
            )
            .await?;
        // A brand-new address has no deposits yet, so this is always 0 — no query needed.
        AddressView::stellar(address, wallet.stellar_account_g.clone(), 0)
    };

    if let Some(uid) = wallet.user_id {
        crate::audit::record(
            &state,
            uid,
            "generated a deposit address",
            crate::audit::category::ADDRESS,
            wallet.label.as_deref(),
            &headers,
        )
        .await;
    }

    let (status, json) = Envelope::created(view);
    Ok((status, json))
}

/// Open the wallet's sealed HD seed and allocate the next EVM deposit address under it, via
/// [`octo_chain::EvmAdapter`]. Mirrors the decrypt pattern in `routes/sponsor.rs`: the seed is
/// opened only for the duration of the derive call and never persisted in plaintext.
async fn allocate_evm_address(
    state: &AppState,
    wallet: &Wallet,
    customer_ref: Option<&str>,
    metadata: serde_json::Value,
) -> ApiResult<Address> {
    let (Some(ciphertext), Some(nonce), Some(salt), Some(scheme), Some(chain_id)) = (
        wallet.sealed_ciphertext.as_ref(),
        wallet.sealed_nonce.as_ref(),
        wallet.sealed_salt.as_ref(),
        wallet.sealed_scheme,
        wallet.chain_id.as_deref(),
    ) else {
        // wallets_evm_has_chain_id / wallets_evm_is_server_custody / wallets_server_custody_has_seed
        // together guarantee an EVM wallet always has all five — reaching here means the schema
        // invariant was violated some other way.
        return Err(ApiError::Internal);
    };
    let sealed = SealedSeed::from_parts_with_scheme(ciphertext.clone(), nonce, salt, scheme as u8)
        .map_err(|_| ApiError::Internal)?;
    let master_key = *state.master_key_for_scheme(scheme);
    let context = evm_crypto_context(chain_id);

    let address = state
        .store()
        .allocate_evm_address(
            wallet.id,
            |index| {
                EvmAdapter
                    .derive_deposit_address(
                        DeriveInput::Evm {
                            master_key: &master_key,
                            sealed: &sealed,
                            context: context.as_bytes(),
                        },
                        u64::from(index),
                    )
                    .map(|d| match d {
                        ChainDepositAddress::Evm(e) => e.address,
                        ChainDepositAddress::Stellar(_) => {
                            unreachable!("EvmAdapter always returns DepositAddress::Evm")
                        }
                    })
                    .map_err(|_| ())
            },
            customer_ref,
            metadata,
        )
        .await?;
    Ok(address)
}

/// The AAD context a wallet's sealed seed is bound under. Must match exactly what provisioning
/// used, or `octo_crypto::open` rejects it — see `docs/threat-model.md` on context binding, and
/// `octo_evm_core::provision_evm_wallet`'s doc comment on why this must be chain-scoped (a seed
/// sealed for one EVM chain must not open under another).
fn evm_crypto_context(chain_id: &str) -> String {
    format!("octo:{chain_id}")
}

/// `GET /v1/wallets/{id}/addresses` — list deposit addresses for a wallet, with optional
/// `?limit=` and `?before=` cursor pagination.
pub async fn list_addresses(
    State(state): State<AppState>,
    Path(wallet_id): Path<Uuid>,
    headers: HeaderMap,
    Query(q): Query<ListParams>,
) -> ApiResult<Json<Envelope<AddressListResponse>>> {
    authorize_wallet(&headers, &state, wallet_id).await?;
    let wallet = state.store().get_wallet(wallet_id).await?;

    let limit = crate::routes::wallets::validated_limit(q.limit)?;

    // Fetch limit+1 to detect whether a next page exists.
    let rows = state
        .store()
        .list_addresses(wallet_id, limit + 1, q.before)
        .await?;

    let has_more = rows.len() > limit as usize;
    let mut items = rows;
    if has_more {
        items.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        items.last().map(|a| a.id)
    } else {
        None
    };

    // One batched query for all rows on this page instead of N — see
    // Store::sum_deposits_for_addresses. Chain-agnostic (keyed by address_id), so it's safe to
    // call for an EVM page too; it will simply find no transactions until the EVM ingest worker
    // exists.
    let ids: Vec<Uuid> = items.iter().map(|a| a.id).collect();
    let totals = state
        .store()
        .sum_deposits_for_addresses(&ids)
        .await
        .map_err(|_| crate::error::ApiError::Internal)?;
    let totals: std::collections::HashMap<Uuid, i64> = totals.into_iter().collect();

    let is_evm = wallet.is_evm();
    let base = wallet.stellar_account_g.clone();
    let views = items
        .into_iter()
        .map(|a| {
            let received = totals.get(&a.id).copied().unwrap_or(0);
            if is_evm {
                AddressView::evm(a, received)
            } else {
                AddressView::stellar(a, base.clone(), received)
            }
        })
        .collect();

    Ok(Envelope::ok(AddressListResponse {
        data: views,
        next_cursor,
    }))
}
