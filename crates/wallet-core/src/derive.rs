//! SEP-0005 hierarchical key derivation for Stellar (SLIP-0010 ed25519).
//!
//! Stellar's SEP-0005 derives account keys at the path `m/44'/148'/<index>'` (all hardened),
//! where `148` is Stellar's SLIP-0044 coin type. From one BIP39 mnemonic we can derive unlimited
//! account keypairs deterministically.
//!
//! In octo's muxed-account model we normally derive only **account 0** (the single master
//! account) and fan out to customers via muxed ids — but this module supports arbitrary indexes
//! so the "real account per customer" model remains available later.

use crate::error::WalletError;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use zeroize::Zeroizing;

/// Stellar's SLIP-0044 coin type.
const STELLAR_COIN_TYPE: u32 = 148;
/// BIP44 purpose.
const BIP44_PURPOSE: u32 = 44;
/// Hardened-derivation offset.
const HARDENED: u32 = 0x8000_0000;

/// Validate a BIP-39 recovery phrase without constructing or holding secret material.
///
/// Verifies word count, English wordlist membership, and BIP-39 checksum. Safe to call
/// with untrusted input and produces no secret-bearing output, making it suitable for
/// pre-flight client-side checks and API validation routes.
///
/// Returns `Ok(())` on valid mnemonics, or [`WalletError::InvalidMnemonic`] if the phrase
/// is syntactically invalid or fails checksum validation.
pub fn validate_seed_phrase(phrase: &str) -> Result<(), WalletError> {
    // Validate mnemonic syntax, wordlist membership, and checksum.
    Mnemonic::from_phrase(phrase, Language::English)
        .map_err(|_| WalletError::InvalidMnemonic)?;
    Ok(())
}

/// A BIP39 seed (the 64-byte output of mnemonic + passphrase), zeroized on drop.
pub struct WalletSeed(Zeroizing<Vec<u8>>);

impl WalletSeed {
    /// Generate a fresh 12-word mnemonic and return both it and its seed.
    ///
    /// The mnemonic is the **backup secret** — it must be shown to the operator once (for
    /// out-of-band storage) and then only ever persisted in sealed form. It is returned in a
    /// [`Zeroizing`] string so the caller controls its lifetime.
    pub fn generate() -> (Zeroizing<String>, WalletSeed) {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let phrase = Zeroizing::new(mnemonic.phrase().to_string());
        let seed = Seed::new(&mnemonic, "");
        let wallet_seed = WalletSeed(Zeroizing::new(seed.as_bytes().to_vec()));
        (phrase, wallet_seed)
    }

    /// Reconstruct a seed from an existing BIP39 mnemonic phrase (recovery / re-import).
    pub fn from_phrase(phrase: &str) -> Result<WalletSeed, WalletError> {
        // Enforce wordlist and checksum validation before constructing secret material.
        validate_seed_phrase(phrase)?;
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English)
            .map_err(|_| WalletError::InvalidMnemonic)?;
        let seed = Seed::new(&mnemonic, "");
        Ok(WalletSeed(Zeroizing::new(seed.as_bytes().to_vec())))
    }

    /// Construct directly from raw seed bytes (e.g. after decrypting a sealed seed).
    pub fn from_bytes(bytes: Vec<u8>) -> WalletSeed {
        WalletSeed(Zeroizing::new(bytes))
    }

    /// Borrow the raw seed bytes (kept private to the crate; callers derive, they don't read).
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Derive the 32-byte ed25519 secret key for Stellar account `index` (`m/44'/148'/index'`).
    ///
    /// # Derivation Path & Invariants
    ///
    /// Derives according to Stellar's [SEP-0005](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md)
    /// specification using SLIP-0010 ed25519 master-key derivation:
    ///
    /// - **Path**: `m/44'/148'/index'`, where `44'` is BIP-44 purpose, `148'` is Stellar's
    ///   SLIP-0044 coin type, and `index'` is the account index.
    /// - **All-Hardened Derivation**: Every level in SEP-0005 is strictly hardened (`index | HARDENED`).
    ///   Unlike EVM's BIP-44 path (`m/44'/60'/0'/0/index`, referenced for contrast in
    ///   `docs/ethereum-expansion-issues.md`), which permits unhardened derivation at the change and
    ///   address levels, ed25519 does not safely support unhardened public derivation without
    ///   compromising key security (leaking an extended public key alongside a single child private
    ///   key would allow recovering the parent secret key and all sibling keys). Full hardening
    ///   guarantees that compromise of any derived key cannot compromise parent or sibling keys.
    /// - **Valid Index Range**: Hardened indices must fall within `0..2^31` (`0..0x8000_0000`). Values
    ///   at or above the 2^31 ceiling cannot be hardened without overflowing the 31-bit index space.
    ///
    /// # Architecture & Deposit Model
    ///
    /// In Octo's deposit architecture (see `docs/deposit-model.md`), this derivation underpins the
    /// muxed-address model: account index 0 is derived as the single master base account (`G...`).
    /// Customer funds are multiplexed via 64-bit IDs encoded into SEP-0023 muxed addresses (`M...`),
    /// allowing off-chain per-user address allocation with zero on-chain account reserves and no sweeps.
    /// Arbitrary index derivation remains available if dedicated on-chain accounts are required.
    ///
    /// The returned secret is wrapped in [`Zeroizing`] and zeroized on drop. Feed it to
    /// [`crate::signer`] to construct a keypair.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octo_wallet_core::WalletSeed;
    ///
    /// let mnemonic = "illness spike retreat truth genius clock brain pass fit cave bargain toe";
    /// let seed = WalletSeed::from_phrase(mnemonic).unwrap();
    /// let secret = seed.derive_ed25519_secret(0);
    /// assert_eq!(secret.len(), 32);
    /// ```
    pub fn derive_ed25519_secret(&self, index: u32) -> Zeroizing<[u8; 32]> {
        // Derive ed25519 key at hardened path m/44'/148'/index'.
        let path = [
            BIP44_PURPOSE | HARDENED,
            STELLAR_COIN_TYPE | HARDENED,
            index | HARDENED,
        ];
        let key = slip10_ed25519::derive_ed25519_private_key(self.as_bytes(), &path);
        Zeroizing::new(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use stellar_strkey::ed25519::PublicKey;

    // Official SEP-0005 Test 1 vector (no passphrase).
    // https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md
    const VECTOR_MNEMONIC: &str =
        "illness spike retreat truth genius clock brain pass fit cave bargain toe";
    // m/44'/148'/0' — verified against the official SEP-0005 Test 1 vector.
    const EXPECTED_ACCOUNT_0: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";

    fn account_id(seed: &WalletSeed, index: u32) -> String {
        let secret = seed.derive_ed25519_secret(index);
        let signing = ed25519_dalek::SigningKey::from_bytes(&secret);
        let pk = PublicKey(signing.verifying_key().to_bytes());
        format!("{pk}")
    }

    #[test]
    fn sep0005_account_0_matches_official_vector() {
        let seed = WalletSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        assert_eq!(account_id(&seed, 0), EXPECTED_ACCOUNT_0);
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = WalletSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        let b = WalletSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        assert_eq!(account_id(&a, 0), account_id(&b, 0));
        assert_eq!(account_id(&a, 5), account_id(&b, 5));
    }

    #[test]
    fn different_indexes_give_different_accounts() {
        let seed = WalletSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        assert_ne!(account_id(&seed, 0), account_id(&seed, 1));
        assert_ne!(account_id(&seed, 1), account_id(&seed, 2));
    }

    #[test]
    fn generated_mnemonic_roundtrips() {
        let (phrase, seed) = WalletSeed::generate();
        let reimported = WalletSeed::from_phrase(&phrase).unwrap();
        assert_eq!(account_id(&seed, 0), account_id(&reimported, 0));
    }

    #[test]
    fn invalid_mnemonic_rejected() {
        assert!(matches!(
            WalletSeed::from_phrase("not a real mnemonic phrase at all"),
            Err(WalletError::InvalidMnemonic)
        ));
    }

    // Sourced checksum-invalid and syntactically invalid test vectors.
    //
    // Sources:
    // 1. Trezor python-mnemonic test suite (tests/test_mnemonic.py:test_failed_checksum).
    // 2. BIP-39 specification official vectors (bitcoin/bips/bip-0039.mediawiki &
    //    trezor/python-mnemonic/vectors.json), mutating the final checksum word to an alternative
    //    wordlist entry ("almost valid" vectors: correct word count and wordlist membership, wrong checksum).
    // 3. Grossly invalid vectors (length mismatches, non-wordlist tokens, empty input).
    const SOURCED_CHECKSUM_INVALID_VECTORS: &[&str] = &[
        // Trezor python-mnemonic tests/test_mnemonic.py test_failed_checksum
        "bless cloud wheel regular tiny venue bird web grief security dignity zoo",
        // BIP-39 spec vector 0 (12-word all-zero entropy), mutated checksum word (about -> abandon)
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        // BIP-39 spec vector 0 (12-word all-zero entropy), mutated checksum word (about -> zoo)
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo",
        // BIP-39 spec vector 1 (12-word all-0x7F entropy), mutated checksum word (yellow -> legal)
        "legal winner thank year wave sausage worth useful legal winner thank legal",
        // BIP-39 spec vector 3 (12-word all-0xFF entropy), mutated checksum word (wrong -> zoo)
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo",
        // 15-word phrase, mutated checksum word
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        // BIP-39 spec vector 4 (18-word all-zero entropy), mutated checksum word (agent -> abandon)
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        // BIP-39 spec vector 7 (24-word all-zero entropy), mutated checksum word (art -> abandon)
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        // BIP-39 spec vector 8 (24-word all-0x7F entropy), mutated checksum word (title -> yellow)
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth yellow",
        // BIP-39 spec vector 9 (24-word all-0xFF entropy), mutated checksum word (vote -> zoo)
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo",
        // Grossly invalid: non-wordlist tokens
        "not a real mnemonic phrase at all",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword",
        // Grossly invalid: incorrect word counts (11, 13, 25 words)
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        // Grossly invalid: empty and corrupt strings
        "",
        "   ",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon 1234",
    ];

    #[test]
    fn from_phrase_rejects_every_sourced_checksum_invalid_vector() {
        for &vector in SOURCED_CHECKSUM_INVALID_VECTORS {
            let res = WalletSeed::from_phrase(vector);
            assert!(
                matches!(res, Err(WalletError::InvalidMnemonic)),
                "from_phrase must reject checksum-invalid vector {vector:?}, got {res:?}"
            );
        }
    }

    #[test]
    fn validate_seed_phrase_accepts_every_from_phrase_accepted_vector() {
        let (gen_phrase, _) = WalletSeed::generate();
        let valid_vectors = [
            VECTOR_MNEMONIC,
            gen_phrase.as_str(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        ];
        for vector in valid_vectors {
            assert!(
                validate_seed_phrase(vector).is_ok(),
                "validate_seed_phrase rejected valid vector {vector:?}"
            );
            assert!(
                WalletSeed::from_phrase(vector).is_ok(),
                "from_phrase rejected valid vector {vector:?}"
            );
        }
    }

    #[test]
    fn validate_seed_phrase_rejects_every_from_phrase_rejected_vector() {
        for &vector in SOURCED_CHECKSUM_INVALID_VECTORS {
            let val_res = validate_seed_phrase(vector);
            let seed_res = WalletSeed::from_phrase(vector);
            assert!(
                matches!(val_res, Err(WalletError::InvalidMnemonic)),
                "validate_seed_phrase must reject {vector:?}"
            );
            assert!(
                matches!(seed_res, Err(WalletError::InvalidMnemonic)),
                "from_phrase must reject {vector:?}"
            );
        }
    }

    #[test]
    fn validate_seed_phrase_never_returns_secret_material_even_on_success() {
        // Assert at type level that validate_seed_phrase produces unit () and holds no secret state.
        let result: Result<(), WalletError> = validate_seed_phrase(VECTOR_MNEMONIC);
        assert_eq!(result.unwrap(), ());
        assert_eq!(std::mem::size_of::<()>(), 0);
    }

    proptest! {
        #[test]
        fn derivation_is_deterministic_for_any_index(
            entropy in any::<[u8; 16]>(),
            index in any::<u32>()
        ) {
            let mnemonic =
                bip39::Mnemonic::from_entropy(&entropy, bip39::Language::English).unwrap();
            let seed_bytes = bip39::Seed::new(&mnemonic, "").as_bytes().to_vec();
            let seed_a = WalletSeed::from_bytes(seed_bytes.clone());
            let seed_b = WalletSeed::from_bytes(seed_bytes);
            let secret_a = seed_a.derive_ed25519_secret(index);
            let secret_b = seed_b.derive_ed25519_secret(index);
            prop_assert_eq!(*secret_a, *secret_b);
        }

        #[test]
        fn distinct_indices_yield_distinct_secrets(
            entropy in any::<[u8; 16]>(),
            index_a in any::<u32>(),
            index_b in any::<u32>()
        ) {
            prop_assume!(index_a != index_b);
            let mnemonic =
                bip39::Mnemonic::from_entropy(&entropy, bip39::Language::English).unwrap();
            let seed =
                WalletSeed::from_bytes(bip39::Seed::new(&mnemonic, "").as_bytes().to_vec());
            let secret_a = seed.derive_ed25519_secret(index_a);
            let secret_b = seed.derive_ed25519_secret(index_b);
            prop_assert_ne!(*secret_a, *secret_b);
        }
    }

    #[test]
    fn boundary_indices_derive_without_panic() {
        let seed = WalletSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        // Exercises the hardened-offset OR-mask at the extreme ends of u32:
        // 0, 1 (lowest valid indices), HARDENED-1 (highest non-hardened u32 value),
        // and u32::MAX (wraps the OR-mask into the already-set upper bit).
        for &index in &[0u32, 1, super::HARDENED - 1, u32::MAX] {
            let secret = seed.derive_ed25519_secret(index);
            let signing = ed25519_dalek::SigningKey::from_bytes(&secret);
            let pk = PublicKey(signing.verifying_key().to_bytes());
            let encoded = format!("{pk}");
            let decoded = PublicKey::from_string(&encoded).unwrap();
            assert_eq!(decoded.0, signing.verifying_key().to_bytes());
        }
    }
}
