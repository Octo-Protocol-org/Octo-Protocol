//! Error type for evm-core.
//!
//! Like [`octo_wallet_core`](https://docs.rs/octo-wallet-core)'s `WalletError`, variants describe
//! the *kind* of failure without echoing key material.

use thiserror::Error;

/// Errors returned by evm-core operations.
#[derive(Debug, Error)]
pub enum EvmError {
    /// The supplied BIP39 mnemonic phrase was invalid.
    #[error("invalid mnemonic phrase")]
    InvalidMnemonic,

    /// A non-hardened BIP-44 index was outside `0..=2^31-1`.
    #[error("derivation index out of range")]
    InvalidDerivationIndex,

    /// The vanishingly rare BIP-32 case where a derived child key is invalid (the arithmetic
    /// produced zero, or a value outside the curve order). Per spec, the caller should treat this
    /// index as unusable; we do not silently substitute a different index because that would
    /// break the "stored index reproduces this address" recovery guarantee.
    #[error("child key derivation produced an invalid key")]
    InvalidChildKey,

    /// An address string was not a well-formed `0x`-prefixed 20-byte hex address, or a
    /// mixed-case address failed its EIP-55 checksum (a likely typo).
    #[error("invalid EVM address")]
    InvalidAddress,

    /// Decrypting the sealed seed failed (wrong key/context or tampered record).
    #[error("seed decryption failed")]
    SeedDecryption,
}

impl From<octo_crypto::CryptoError> for EvmError {
    fn from(_: octo_crypto::CryptoError) -> Self {
        // Collapse all crypto failures to a single coarse variant — do not leak which.
        EvmError::SeedDecryption
    }
}
