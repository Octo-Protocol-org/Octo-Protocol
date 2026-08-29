//! The [`ChainAdapter`] trait: the boundary between Octo's business logic and any one chain.
//!
//! What belongs in an adapter vs. in business logic (see also `docs/architecture.md`):
//! - **Adapter**: chain identity, address grammar (validate/normalize), how a customer deposit
//!   address is shaped for this chain, and how to turn a chain-native failure code into a
//!   sentence a merchant can read. An adapter holds no business state — it is stateless per call
//!   (any config it needs, e.g. which network, is fixed at construction).
//! - **Business logic** (`octo-api`, `octo-ingest`): what to *do* with a validated address or a
//!   deposit — allocate a customer id, persist a row, fire a webhook, decide whether to credit a
//!   deposit yet. None of that is chain-specific, so none of it belongs behind this trait.
//! - **Never in an adapter**: raw key material. Adapters call out to a chain's own signing crate
//!   (e.g. `octo-wallet-core` for Stellar) exactly like business logic would — `octo-chain` itself
//!   never depends on `octo-crypto` and never sees a seed or private key.

use crate::capabilities::ChainCapabilities;
use crate::error::ChainError;
use crate::id::ChainId;
use async_trait::async_trait;

/// Both forms of a customer deposit address for one chain adapter.
///
/// This generalises Stellar's muxed (`M...`) + `G...`-plus-memo pair
/// ([`octo_wallet_core::DepositAddress`]) to any chain. A chain without
/// [`ChainCapabilities::supports_muxed_addresses`] has no `fallback` — see that field's docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositAddress {
    /// The address to hand to the customer by default.
    pub primary: String,
    /// A fallback destination + memo for senders that can't address `primary` directly (e.g. an
    /// exchange that can't send to a Stellar muxed address). `None` on chains with no such
    /// fallback — those chains must derive a distinct address per customer instead.
    pub fallback: Option<DepositFallback>,
}

/// The base-address-plus-memo fallback half of a [`DepositAddress`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositFallback {
    /// The chain's plain (non-muxed) base address.
    pub address: String,
    /// The numeric memo/tag that attributes a payment to `address` back to the same customer id
    /// as `DepositAddress::primary`.
    pub memo: String,
}

/// The trait boundary between Octo's business logic and one specific chain.
///
/// Object-safe by construction (`async_trait`, no generic methods) so it can be stored as
/// `Arc<dyn ChainAdapter>` — required because `AppState` is cloned across every Axum handler and
/// `octo-ingest`'s supervisor spawns one task per wallet, both of which need `Send + Sync +
/// 'static` shared ownership.
///
/// Implementations must be pure with respect to business state: an adapter call may talk to its
/// own chain (or, for Stellar today, simply forward to `octo-wallet-core`), but must never read
/// or write Octo's store directly.
#[async_trait]
pub trait ChainAdapter: Send + Sync + 'static {
    /// This adapter's CAIP-2 chain identity (AD-1). Fixed at construction — never varies per call.
    fn chain_id(&self) -> &ChainId;

    /// What this adapter's chain can and cannot do. Fixed at construction.
    fn capabilities(&self) -> ChainCapabilities;

    /// Check that `address` is a well-formed address on this chain, in any form the chain
    /// accepts (e.g. for Stellar, both plain `G...` and muxed `M...`). Must return quickly and
    /// without I/O — this checks grammar, not on-chain existence.
    async fn validate_address(&self, address: &str) -> Result<(), ChainError>;

    /// Reduce `address` to its canonical base form, whether given in any address form the chain
    /// accepts. Two addresses that name the same underlying account/key must normalize to the
    /// same string — callers that compare destinations (e.g. a withdrawal allowlist) rely on
    /// this. Generalises [`octo_wallet_core::to_base_account`].
    async fn normalize_address(&self, address: &str) -> Result<String, ChainError>;

    /// Build a customer deposit address from this wallet's chain-specific base identity (for
    /// Stellar, the master account's `G...` address) and a per-customer `id`. Deterministic: the
    /// same `(base_identity, id)` pair must always produce the same [`DepositAddress`].
    /// Generalises [`octo_wallet_core::deposit_address`].
    async fn derive_deposit_address(
        &self,
        base_identity: &str,
        customer_id: u64,
    ) -> Result<DepositAddress, ChainError>;

    /// Map a chain-specific result/error code into a sentence a merchant dashboard can show
    /// verbatim. Must never fail or panic — an unrecognised code still gets a generic-but-honest
    /// explanation. Generalises `explain_code` (`crates/api/src/routes/submit.rs`).
    async fn explain_failure(&self, code: &str) -> String;
}
