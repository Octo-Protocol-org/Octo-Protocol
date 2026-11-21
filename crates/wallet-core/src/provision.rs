//! Non-custodial wallet provisioning.
//!
//! `wallet-core` is the only crate that ever holds key material. Provisioning therefore
//! happens entirely client-side: the caller supplies a mnemonic (or entropy) and receives a
//! [`ProvisionedWallet`] holding the derived public account plus the in-memory seed. Nothing
//! here persists, transmits, or logs secret material — see `docs/non-custodial-flow.md`.

use crate::derive::{WalletSeed, SEP0005_DEFAULT_ACCOUNT};
use crate::error::WalletError;

/// Result of provisioning a wallet locally.
///
/// The `seed` is kept in memory only so the caller can sign locally; it is never serialized
/// (no `Serialize` impl) and is zeroized on drop by [`WalletSeed`].
#[derive(Debug)]
pub struct ProvisionedWallet {
    /// Stellar account (`G...`) derived via SEP-0005 for the default account index.
    pub public_key: String,
    /// In-memory seed material. Never persist or transmit this value.
    pub seed: WalletSeed,
}

impl ProvisionedWallet {
    /// Returns the public key without exposing the seed.
    pub fn public_key(&self) -> &str {
        &self.public_key
    }
}

/// Provisions a wallet from an existing BIP-39 mnemonic phrase.
///
/// The phrase is validated and used to derive the SEP-0005 account locally. No network or
/// server-side seed handling is involved.
pub fn provision_wallet(mnemonic: &str) -> Result<ProvisionedWallet, WalletError> {
    let seed = WalletSeed::from_mnemonic(mnemonic)?;
    let public_key = seed.derive_account(SEP0005_DEFAULT_ACCOUNT)?;
    Ok(ProvisionedWallet { public_key, seed })
}

/// Imports a wallet from a BIP-39 mnemonic phrase.
///
/// Alias of [`provision_wallet`] kept for callers that frame the operation as an import.
pub fn import_wallet(mnemonic: &str) -> Result<ProvisionedWallet, WalletError> {
    provision_wallet(mnemonic)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Public BIP-39 test vector (all-zero entropy); never a real key.
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn provision_and_import_agree() {
        let provisioned = provision_wallet(TEST_MNEMONIC).expect("provision");
        let imported = import_wallet(TEST_MNEMONIC).expect("import");
        assert_eq!(provisioned.public_key(), imported.public_key());
        assert!(provisioned.public_key().starts_with('G'));
    }

    #[test]
    fn rejects_invalid_mnemonic() {
        assert!(provision_wallet("not a valid mnemonic").is_err());
    }
}
