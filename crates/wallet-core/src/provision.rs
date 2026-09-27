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

/// Re-provision from an existing mnemonic (recovery / import).
pub fn import_wallet(
    master_key: &[u8; MASTER_KEY_LEN],
    network: StellarNetwork,
    mnemonic: &str,
) -> Result<ProvisionedWallet, WalletError> {
    let seed = WalletSeed::from_phrase(mnemonic)?;
    let account_g = master_account_id(&seed)?;
    let sealed = seal(master_key, seed.as_bytes(), network.crypto_context())?;
    Ok(ProvisionedWallet {
        account_g,
        sealed,
        mnemonic: Zeroizing::new(mnemonic.to_string()),
    })
}

/// Derive the `G...` account id for master account 0 from a seed.
fn master_account_id(seed: &WalletSeed) -> Result<String, WalletError> {
    let secret = seed.derive_ed25519_secret(0);
    let kp =
        DalekKeyPair::from_seed_bytes(secret.as_ref()).map_err(|_| WalletError::KeyDerivation)?;
    Ok(kp.public_key().account_id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use octo_crypto::open;

    // -----------------------------------------------------------------------
    // SEP-0005 Test 1 known-answer vector.
    //
    // Source: https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md
    //         § "Test Cases" — "Test 1" (no passphrase, 12-word mnemonic).
    //
    // This same vector is used by the reference Stellar SDK test suites (e.g. js-stellar-base
    // `test/unit/keypair_test.js`, go/txnbuild, and the Python `stellar-sdk`) and by
    // derive.rs's own `sep0005_account_0_matches_official_vector` test, giving independent,
    // cross-language confirmation of the expected output.
    // -----------------------------------------------------------------------
    const SEP0005_TEST1_MNEMONIC: &str =
        "illness spike retreat truth genius clock brain pass fit cave bargain toe";
    /// m/44'/148'/0' as published in SEP-0005 Test 1.
    const SEP0005_TEST1_ACCOUNT_0: &str =
        "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";

    /// `import_wallet` given a published SEP-0005 test mnemonic must derive the
    /// independently-verified account address for index 0 — proving the full
    /// provision/import stack agrees with the canonical Stellar key-derivation spec.
    #[test]
    fn import_wallet_derives_the_expected_account_for_a_known_sep0005_test_vector() {
        let mk = [9u8; 32];
        let p = import_wallet(&mk, StellarNetwork::Testnet, SEP0005_TEST1_MNEMONIC).unwrap();
        assert_eq!(p.account_g, SEP0005_TEST1_ACCOUNT_0);
        // The returned mnemonic echoes back exactly what was supplied.
        assert_eq!(p.mnemonic.as_str(), SEP0005_TEST1_MNEMONIC);
    }

    /// `provision_wallet` generates a fresh mnemonic each call; `import_wallet` applied to
    /// that mnemonic must reproduce the exact same `G...` account — proving the two functions
    /// are mutual inverses and that no account-id is ever silently lost across the seal/unseal
    /// boundary.
    #[test]
    fn provision_wallet_returns_a_mnemonic_and_account_that_are_mutually_consistent_via_import_wallet(
    ) {
        let mk = [3u8; 32];
        let provisioned = provision_wallet(&mk, StellarNetwork::Testnet).unwrap();
        assert!(provisioned.account_g.starts_with('G'), "master account must be a G... strkey");

        // Re-import using the mnemonic provision_wallet returned and confirm the account matches.
        let reimported =
            import_wallet(&mk, StellarNetwork::Testnet, &provisioned.mnemonic).unwrap();
        assert_eq!(
            reimported.account_g,
            provisioned.account_g,
            "import_wallet must derive the same account as provision_wallet for the same mnemonic"
        );
    }

    // -----------------------------------------------------------------------
    // Supporting tests (seal/unseal integrity, uniqueness)
    // -----------------------------------------------------------------------

    #[test]
    fn sealed_seed_opens_and_re_derives_same_account() {
        let mk = [3u8; 32];
        let p = provision_wallet(&mk, StellarNetwork::Testnet).unwrap();

        // The sealed seed must open under the same network context and re-derive the same account.
        let seed_bytes = open(&mk, &p.sealed, StellarNetwork::Testnet.crypto_context()).unwrap();
        let seed = WalletSeed::from_bytes(seed_bytes.to_vec());
        assert_eq!(master_account_id(&seed).unwrap(), p.account_g);
    }

    #[test]
    fn provisioned_wallets_are_unique() {
        let mk = [1u8; 32];
        let a = provision_wallet(&mk, StellarNetwork::Testnet).unwrap();
        let b = provision_wallet(&mk, StellarNetwork::Testnet).unwrap();
        assert_ne!(a.account_g, b.account_g);
    }
}
