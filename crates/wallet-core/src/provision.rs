//! High-level master-wallet provisioning: generate a seed, derive the master account, and seal
//! the seed for storage — all in one place so the API never touches raw secret material.

use crate::derive::WalletSeed;
use crate::error::WalletError;
use crate::signer::StellarNetwork;
use octo_crypto::{seal, SealedSeed, MASTER_KEY_LEN};
use stellar_base::crypto::DalekKeyPair;
use zeroize::Zeroizing;

/// The result of provisioning a master wallet: the public account, the sealed seed to persist,
/// and the one-time recovery mnemonic to hand to the operator (out-of-band).
pub struct ProvisionedWallet {
    /// The master account's `G...` address (account index 0).
    pub account_g: String,
    /// The AES-256-GCM-sealed seed to store at rest.
    pub sealed: SealedSeed,
    /// The BIP39 mnemonic — the backup secret. Show once, never persist in plaintext.
    pub mnemonic: Zeroizing<String>,
}

/// Generate a brand-new master wallet for `network`.
///
/// Flow: fresh BIP39 mnemonic → SEP-0005 derive account 0 → `G...`; seal the raw seed under the
/// network-bound crypto context. The decrypted seed never leaves this function except sealed.
pub fn provision_wallet(
    master_key: &[u8; MASTER_KEY_LEN],
    network: StellarNetwork,
) -> Result<ProvisionedWallet, WalletError> {
    let (mnemonic, seed) = WalletSeed::generate();
    let account_g = master_account_id(&seed)?;
    let sealed = seal(master_key, seed.as_bytes(), network.crypto_context())?;
    Ok(ProvisionedWallet {
        account_g,
        sealed,
        mnemonic,
    })
}

/// Re-provision from an existing mnemonic and verify its derived account before sealing the seed.
pub fn import_wallet(
    master_key: &[u8; MASTER_KEY_LEN],
    network: StellarNetwork,
    mnemonic: &str,
    expected_account_g: &str,
) -> Result<ProvisionedWallet, WalletError> {
    let seed = WalletSeed::from_phrase(mnemonic)?;
    let account_g = master_account_id(&seed)?;
    if account_g != expected_account_g {
        return Err(WalletError::MnemonicAccountMismatch);
    }
    let sealed = seal(master_key, seed.as_bytes(), network.crypto_context())?;
    Ok(ProvisionedWallet {
        account_g,
        sealed,
        mnemonic: Zeroizing::new(mnemonic.to_string()),
    })
}

/// Derive the `G...` account id for master account 0 from a seed.
fn master_account_id(seed: &WalletSeed) -> Result<String, WalletError> {
    let secret = seed.derive_ed25519_secret(0)?;
    let kp =
        DalekKeyPair::from_seed_bytes(secret.as_ref()).map_err(|_| WalletError::KeyDerivation)?;
    Ok(kp.public_key().account_id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use octo_crypto::open;

    #[test]
    fn provision_then_reopen_seed_yields_same_account() {
        let mk = [3u8; 32];
        let p = provision_wallet(&mk, StellarNetwork::Testnet).unwrap();
        assert!(p.account_g.starts_with('G'));

        // The sealed seed must open under the same network context and re-derive the same account.
        let seed_bytes = open(&mk, &p.sealed, StellarNetwork::Testnet.crypto_context()).unwrap();
        let seed = WalletSeed::from_bytes(seed_bytes.to_vec());
        assert_eq!(master_account_id(&seed).unwrap(), p.account_g);
    }

    #[test]
    fn import_reproduces_account_from_mnemonic() {
        let mk = [9u8; 32];
        let vector = "illness spike retreat truth genius clock brain pass fit cave bargain toe";
        let p = import_wallet(
            &mk,
            StellarNetwork::Testnet,
            vector,
            "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6",
        )
        .unwrap();
        assert_eq!(
            p.account_g,
            "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6"
        );
    }

    #[test]
    fn import_rejects_a_mnemonic_that_does_not_derive_the_expected_account() {
        let mk = [9u8; 32];
        let vector = "illness spike retreat truth genius clock brain pass fit cave bargain toe";
        let result = import_wallet(
            &mk,
            StellarNetwork::Testnet,
            vector,
            "GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX",
        );

        assert!(matches!(result, Err(WalletError::MnemonicAccountMismatch)));
    }

    #[test]
    fn provisioned_wallets_are_unique() {
        let mk = [1u8; 32];
        let a = provision_wallet(&mk, StellarNetwork::Testnet).unwrap();
        let b = provision_wallet(&mk, StellarNetwork::Testnet).unwrap();
        assert_ne!(a.account_g, b.account_g);
    }
}
