//! What kind of chain an adapter speaks for, and what it can and cannot do.
//!
//! [`ChainAdapter`](crate::ChainAdapter) is deliberately a small required core plus a
//! capability description — not the union of every field Stellar and EVM chains need. Callers
//! branch on `capabilities()`, not on `kind()`, wherever the behaviour difference is about a
//! capability (e.g. "does this chain have memos") rather than the chain family itself.

/// Which chain family an adapter implements.
///
/// Business logic should prefer branching on [`ChainCapabilities`] over this enum — `kind()`
/// exists for diagnostics, metrics, and the rare case where behaviour genuinely depends on the
/// chain family rather than a specific capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChainKind {
    /// Stellar and Stellar-compatible networks (pubnet, testnet, standalone).
    Stellar,
    /// EVM-compatible chains (Ethereum L1 and its L2s), identified via CAIP-2 `eip155:*`.
    Evm,
}

/// What an adapter's chain can and cannot do.
///
/// Fields describe capabilities, not chain identity — a new field should only be added when a
/// behaviour genuinely varies per-chain and callers need to branch on it. Do not add fields that
/// are always true for one `ChainKind` and always false for another; that's what `kind()` is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainCapabilities {
    /// The chain family this capability set describes.
    pub kind: ChainKind,
    /// Whether the chain supports an out-of-band numeric memo alongside a plain address as a
    /// deposit-attribution fallback (Stellar: yes, via `MEMO_ID`; EVM: no equivalent).
    pub supports_memo: bool,
    /// Whether the chain has an address format that embeds a sub-account id in a single account
    /// (Stellar: muxed `M...` addresses). When `false`,
    /// [`ChainAdapter::derive_deposit_address`](crate::ChainAdapter::derive_deposit_address)
    /// must derive a distinct on-chain address per customer instead of a shared base + id.
    pub supports_muxed_addresses: bool,
    /// Whether a transaction the chain reports as final can later be reversed by a reorg.
    /// Stellar: `false` (instant finality). EVM: `true` — ingest must gate crediting on
    /// confirmation depth.
    pub has_reorgs: bool,
    /// Decimal places of the chain's native asset (Stellar stroops: 7; ETH wei: 18).
    pub native_decimals: u8,
}
