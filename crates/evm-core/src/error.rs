//! Error type for octo-evm-core.
//!
//! Like [`octo_crypto::CryptoError`] and `octo_wallet_core::WalletError`, variants describe the
//! *kind* of failure without echoing key material, seeds, or signatures.

use thiserror::Error;

/// Errors returned by octo-evm-core operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EvmCoreError {
    /// The supplied BIP39 mnemonic phrase was invalid.
    #[error("invalid mnemonic phrase")]
    InvalidMnemonic,

    /// A BIP-32 child-key derivation step produced an invalid scalar (IL >= curve order, or the
    /// resulting child key is zero). Per BIP-32 this means "skip to the next index" — for our
    /// fixed derivation path this indicates a corrupt seed rather than a normal condition, since
    /// the probability of hitting it by chance is ~1 in 2^127.
    #[error("invalid derivation path")]
    InvalidDerivationPath,

    /// Failed to construct a secp256k1 key from derived bytes (not a valid scalar in [1, n-1]).
    #[error("key derivation failed")]
    KeyDerivation,

    /// An address string was not a well-formed `0x`-prefixed 20-byte hex address.
    #[error("invalid EVM address")]
    InvalidAddress,

    /// An address string was well-formed but its mixed-case EIP-55 checksum did not match — this
    /// is the typo-detection property EIP-55 exists for, and it must be rejected, not silently
    /// accepted by lowercasing before comparison.
    #[error("invalid EIP-55 checksum")]
    InvalidChecksum,

    /// The digest supplied for signing was not exactly 32 bytes.
    #[error("invalid digest length: expected 32 bytes")]
    InvalidDigestLength,

    /// Signing or recovery failed.
    #[error("signing failed")]
    Signing,

    /// Decrypting the sealed seed failed (wrong key/context or tampered record).
    #[error("seed decryption failed")]
    SeedDecryption,
}

impl From<octo_crypto::CryptoError> for EvmCoreError {
    fn from(_: octo_crypto::CryptoError) -> Self {
        // Collapse all crypto failures to a single coarse variant — do not leak which, mirroring
        // octo_wallet_core::WalletError's handling of the same crate.
        EvmCoreError::SeedDecryption
    }
}
