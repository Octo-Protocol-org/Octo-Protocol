use thiserror::Error;

/// Errors produced by the `evm-core` crate.
///
/// Variants never carry or format secret material (private keys, raw key
/// bytes); only public, non-sensitive context is included in messages.
#[derive(Debug, Error)]
pub enum EvmCoreError {
    /// The signature recovery id was not 0 or 1.
    #[error("invalid recovery id: expected 0 or 1, got {0}")]
    InvalidRecoveryId(u8),

    /// Derivation of a key or address failed.
    #[error("derivation error: {0}")]
    Derivation(String),

    /// An address was malformed or could not be parsed.
    #[error("invalid address: {0}")]
    Address(String),

    /// Signing failed.
    #[error("signing error: {0}")]
    Signing(String),
}
