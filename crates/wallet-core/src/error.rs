//! Error type for wallet-core.
//!
//! Like [`octo_crypto::CryptoError`], variants avoid carrying secret material. They describe the
//! *kind* of failure (bad input, derivation, signing) without echoing keys, seeds, or amounts.

use thiserror::Error;

/// Wallet errors never contain secret material or unredacted transaction data that could leak through logs.
#[derive(Debug, Error)]
pub enum WalletError {
    /// The supplied BIP39 mnemonic phrase was invalid.
    #[error("invalid mnemonic phrase")]
    InvalidMnemonic,

    /// The mnemonic phrase failed the BIP-39 checksum verification.
    #[error("invalid mnemonic checksum")]
    InvalidChecksum,

    /// A derivation path component or index was invalid.
    #[error("invalid derivation path")]
    InvalidDerivationPath,

    /// Failed to construct a Stellar keypair from the derived seed bytes.
    #[error("key derivation failed")]
    KeyDerivation,

    /// The mnemonic-derived account did not match the account claimed by the caller.
    #[error("mnemonic does not derive the expected account")]
    MnemonicAccountMismatch,

    /// An address string (G... or M...) could not be parsed.
    #[error("invalid Stellar address")]
    InvalidAddress,

    /// A credit-asset code was not 1 to 12 bytes, so it can never match a real Stellar asset
    /// (see [`crate::asset::is_valid_asset_code`]).
    #[error("invalid asset code")]
    InvalidAssetCode,

    /// A requested amount was out of range (must be a positive number of stroops).
    #[error("invalid amount")]
    InvalidAmount,

    /// Building or signing the transaction failed.
    #[error("transaction signing failed")]
    Signing,

    /// Decrypting the sealed seed failed (wrong key/context or tampered record).
    #[error("seed decryption failed")]
    SeedDecryption,

    /// A supplied XDR string could not be parsed as a valid `TransactionEnvelope`, or was a
    /// variant this crate does not accept here (e.g. a fee-bump used as an inner transaction).
    #[error("invalid transaction XDR")]
    InvalidXdr,

    /// An ed25519 signature failed to parse or did not verify against the claimed account.
    #[error("invalid signature")]
    InvalidSignature,

    /// The transaction sequence number does not match the account's current chain sequence.
    #[error("stale transaction sequence number")]
    StaleSequence,
}

impl From<octo_crypto::CryptoError> for WalletError {
    fn from(_: octo_crypto::CryptoError) -> Self {
        // Collapse all crypto failures to a single coarse variant — do not leak which.
        WalletError::SeedDecryption
    }
}

#[cfg(test)]
mod tests {
    use super::WalletError;

    #[test]
    fn wallet_error_output_never_contains_secret_material() {
        let secret = "illness spike retreat truth genius clock brain pass fit cave bargain toe";
        let errors = [
            WalletError::InvalidMnemonic,
            WalletError::InvalidDerivationPath,
            WalletError::KeyDerivation,
            WalletError::MnemonicAccountMismatch,
            WalletError::InvalidAddress,
            WalletError::InvalidAssetCode,
            WalletError::InvalidAmount,
            WalletError::Signing,
            WalletError::SeedDecryption,
            WalletError::InvalidXdr,
            WalletError::InvalidSignature,
        ];

        for error in errors {
            assert!(!error.to_string().contains(secret));
            assert!(!format!("{error:?}").contains(secret));
        }
    }
}
