//! Error type shared by [`crate::ChainId`] parsing and every [`crate::ChainAdapter`] method.

use thiserror::Error;

/// Errors returned by `octo-chain` types and adapters.
///
/// Like [`octo_wallet_core::WalletError`], variants describe the *kind* of failure without
/// carrying secret material — this crate never sees any.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// A [`crate::ChainId`] string did not conform to the CAIP-2 grammar
    /// (`namespace:reference`, `namespace` = `[-a-z0-9]{3,8}`, `reference` = `[-_a-zA-Z0-9]{1,32}`).
    #[error("invalid CAIP-2 chain id: {0:?}")]
    InvalidChainId(String),

    /// [`crate::ChainRegistry::get`] was asked for a chain id no adapter is registered for.
    #[error("unsupported chain: {0}")]
    UnsupportedChain(String),

    /// An address string was not valid for the adapter's chain.
    #[error("invalid address")]
    InvalidAddress,

    /// A signature failed to parse or did not verify.
    #[error("invalid signature")]
    InvalidSignature,

    /// The adapter could not complete the request for a reason specific to its chain (e.g. a
    /// malformed RPC response). Carries a short, non-secret description.
    #[error("chain adapter error: {0}")]
    Adapter(String),
}
