//! BIP-32 secp256k1 key derivation, restricted to the path shape octo needs:
//! `m / 44' / 60' / 0' / {branch} / {index}`.
//!
//! Levels 0-2 (`44'`, `60'`, `0'`) are **hardened**; levels 3-4 (`branch`, `index`) are
//! **non-hardened**. That is standard BIP-44, and it is also the source of the single most
//! important security fact in this crate:
//!
//! > **With non-hardened derivation, the extended *public* key (xpub) at a given depth plus any
//! > one child *private* key is enough to recover every sibling private key at that depth.** The
//! > child private key `k_i = IL + k_par (mod n)` is a simple modular addition, and
//! > `IL = HMAC-SHA512(c_par, serP(K_par) || i)` is computable from public data alone (the parent
//! > **public** key `K_par` and chain code `c_par`). So an attacker who has the xpub for
//! > `m/44'/60'/0'/0` and recovers *one* leaked deposit-address private key can invert the
//! > addition to get `k_par`, and from there derive every other customer's deposit key on that
//! > wallet.
//!
//! Consequence: **the xpub for this branch must be treated as secret**, on par with a private
//! key, even though BIP-32 nominally calls it "public". octo never constructs or exposes an xpub
//! at all — every derivation here re-walks the path from the sealed seed — but any future code
//! that adds xpub-based (watch-only) derivation must carry this warning forward. See
//! `docs/threat-model.md`.
//!
//! We derive hardened, not from an xpub, so this crate only ever needs private-parent-key CKD
//! (BIP-32 "CKDpriv"); public-parent CKD ("CKDpub") is deliberately not implemented.

use crate::error::EvmError;
use hmac::{Hmac, Mac};
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{FieldBytes, Scalar, SecretKey};
use sha2::Sha512;
use zeroize::Zeroizing;

type HmacSha512 = Hmac<Sha512>;

/// BIP-44 purpose.
const PURPOSE: u32 = 44;
/// Ethereum's SLIP-44 coin type.
const EVM_COIN_TYPE: u32 = 60;
/// Hardened-derivation offset (bit 31 set).
const HARDENED: u32 = 0x8000_0000;
/// Upper bound (inclusive) of the non-hardened index space: `2^31 - 1`.
pub const MAX_NON_HARDENED_INDEX: u32 = HARDENED - 1;

/// The BIP-44 "external" (deposit-facing) branch: `m/44'/60'/0'/0/i`. This is the only branch
/// customer deposit addresses are ever allocated from.
pub const DEPOSIT_BRANCH: u32 = 0;
/// The BIP-44 "internal" (change) branch: `m/44'/60'/0'/1/i`. Never handed out as a customer
/// deposit address; used only for the wallet's own identity address (index 0).
pub const IDENTITY_BRANCH: u32 = 1;

/// A raw BIP-32 extended private key: a 32-byte secret scalar plus its 32-byte chain code.
/// Zeroized on drop.
struct ExtendedKey {
    secret: Zeroizing<[u8; 32]>,
    chain_code: Zeroizing<[u8; 32]>,
}

/// A BIP39 seed, held only long enough to derive from and then dropped/zeroized.
pub struct EvmSeed(Zeroizing<Vec<u8>>);

impl EvmSeed {
    /// Wrap raw BIP39 seed bytes (e.g. decrypted from a [`octo_crypto::SealedSeed`]).
    ///
    /// The same 64-byte seed that produces a wallet's Stellar SEP-0005 keys can be reused here:
    /// the coin-type level of the path (`60'` vs `148'`) keeps the two derivation trees disjoint.
    pub fn from_bytes(bytes: Vec<u8>) -> EvmSeed {
        EvmSeed(Zeroizing::new(bytes))
    }

    /// Reconstruct from an existing BIP39 mnemonic phrase (recovery / re-import).
    pub fn from_phrase(phrase: &str) -> Result<EvmSeed, EvmError> {
        let mnemonic = bip39::Mnemonic::from_phrase(phrase, bip39::Language::English)
            .map_err(|_| EvmError::InvalidMnemonic)?;
        let seed = bip39::Seed::new(&mnemonic, "");
        Ok(EvmSeed(Zeroizing::new(seed.as_bytes().to_vec())))
    }

    /// Generate a fresh 12-word mnemonic and its seed.
    pub fn generate() -> (Zeroizing<String>, EvmSeed) {
        let mnemonic = bip39::Mnemonic::new(bip39::MnemonicType::Words12, bip39::Language::English);
        let phrase = Zeroizing::new(mnemonic.phrase().to_string());
        let seed = bip39::Seed::new(&mnemonic, "");
        (phrase, EvmSeed(Zeroizing::new(seed.as_bytes().to_vec())))
    }

    /// Borrow the raw seed bytes (crate-private: callers derive, they don't read).
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// BIP-32 master key: `HMAC-SHA512(key = "Bitcoin seed", data = seed)`. The key name is a
    /// BIP-32 convention shared by every coin derived under it, not a Bitcoin-specific value.
    fn master_key(&self) -> Result<ExtendedKey, EvmError> {
        let mut mac =
            HmacSha512::new_from_slice(b"Bitcoin seed").map_err(|_| EvmError::InvalidChildKey)?;
        mac.update(&self.0);
        split_i(&mac.finalize().into_bytes())
    }

    /// Derive the secret key at `m/44'/60'/0'/{branch}/{index}`.
    ///
    /// `branch` and `index` are non-hardened (`DEPOSIT_BRANCH`/`IDENTITY_BRANCH` select `branch`);
    /// `44'`, `60'`, `0'` above them are hardened. See this module's doc comment for why that
    /// split matters.
    pub(crate) fn derive_secret(
        &self,
        branch: u32,
        index: u32,
    ) -> Result<Zeroizing<[u8; 32]>, EvmError> {
        if index > MAX_NON_HARDENED_INDEX {
            return Err(EvmError::InvalidDerivationIndex);
        }
        let m = self.master_key()?;
        let purpose = ckd_priv_hardened(&m, PURPOSE)?;
        let coin_type = ckd_priv_hardened(&purpose, EVM_COIN_TYPE)?;
        let account = ckd_priv_hardened(&coin_type, 0)?;
        let chain = ckd_priv_normal(&account, branch)?;
        let leaf = ckd_priv_normal(&chain, index)?;
        Ok(leaf.secret)
    }
}

/// Split a 64-byte HMAC-SHA512 output `I` into `(IL, IR)` = (secret, chain code).
fn split_i(i: &[u8]) -> Result<ExtendedKey, EvmError> {
    if i.len() != 64 {
        return Err(EvmError::InvalidChildKey);
    }
    let mut secret = [0u8; 32];
    let mut chain_code = [0u8; 32];
    secret.copy_from_slice(&i[..32]);
    chain_code.copy_from_slice(&i[32..]);
    // IL must be a valid, nonzero scalar below the curve order — SecretKey::from_slice enforces
    // that; reject rather than silently reduce, per BIP-32 §"Private parent key -> private child key".
    SecretKey::from_slice(&secret).map_err(|_| EvmError::InvalidChildKey)?;
    Ok(ExtendedKey {
        secret: Zeroizing::new(secret),
        chain_code: Zeroizing::new(chain_code),
    })
}

/// CKDpriv, hardened case: `i' = i + 2^31`. `data = 0x00 || ser256(k_par) || ser32(i')`.
fn ckd_priv_hardened(parent: &ExtendedKey, index: u32) -> Result<ExtendedKey, EvmError> {
    ckd_priv(parent, index | HARDENED, true)
}

/// CKDpriv, non-hardened case: `data = serP(point(k_par)) || ser32(i)`.
fn ckd_priv_normal(parent: &ExtendedKey, index: u32) -> Result<ExtendedKey, EvmError> {
    if index > MAX_NON_HARDENED_INDEX {
        return Err(EvmError::InvalidDerivationIndex);
    }
    ckd_priv(parent, index, false)
}

fn ckd_priv(parent: &ExtendedKey, index: u32, hardened: bool) -> Result<ExtendedKey, EvmError> {
    let parent_secret =
        SecretKey::from_slice(parent.secret.as_ref()).map_err(|_| EvmError::InvalidChildKey)?;

    let mut data = Vec::with_capacity(37);
    if hardened {
        data.push(0x00);
        data.extend_from_slice(parent.secret.as_ref());
    } else {
        let point = parent_secret.public_key().to_encoded_point(true);
        data.extend_from_slice(point.as_bytes());
    }
    data.extend_from_slice(&index.to_be_bytes());

    let mut mac = HmacSha512::new_from_slice(parent.chain_code.as_ref())
        .map_err(|_| EvmError::InvalidChildKey)?;
    mac.update(&data);
    let i = mac.finalize().into_bytes();

    let il = &i[..32];
    let ir = &i[32..];

    let il_scalar: Scalar = Option::from(Scalar::from_repr(*FieldBytes::from_slice(il)))
        .ok_or(EvmError::InvalidChildKey)?;
    let parent_scalar = parent_secret.to_nonzero_scalar();
    let child_scalar = il_scalar + parent_scalar.as_ref();

    let child_bytes: FieldBytes = child_scalar.into();
    // A zero sum (or, equivalently, a scalar SecretKey::from_slice rejects) is the "invalid key"
    // case BIP-32 calls out as vanishingly rare (~2^-127). We surface it rather than silently
    // deriving a different index — see EvmError::InvalidChildKey's doc comment.
    SecretKey::from_slice(child_bytes.as_slice()).map_err(|_| EvmError::InvalidChildKey)?;

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&child_bytes);
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(ir);

    Ok(ExtendedKey {
        secret: Zeroizing::new(secret),
        chain_code: Zeroizing::new(chain_code),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-32 Test Vector 1, seed = 000102030405060708090a0b0c0d0e0f.
    // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
    //
    // The BIP only publishes base58check-encoded xprv/xpub strings; the raw hex below is that
    // xprv's 32-byte key field (bytes 46..78 of the base58check payload, after the version/
    // depth/fingerprint/child-number/chaincode header and the leading 0x00 key-type byte),
    // decoded locally and cross-checked against the seed's well-known public xprv/xpub strings
    // for "Chain m" and "Chain m/0H".
    #[test]
    fn bip32_vector1_master_and_hardened_child() {
        let seed_bytes = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let seed = EvmSeed::from_bytes(seed_bytes);
        let m = seed.master_key().unwrap();
        // xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi
        assert_eq!(
            hex::encode(m.secret.as_ref()),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
        assert_eq!(
            hex::encode(m.chain_code.as_ref()),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
        );
        let child = ckd_priv_hardened(&m, 0).unwrap();
        // xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7
        assert_eq!(
            hex::encode(child.secret.as_ref()),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );
        assert_eq!(
            hex::encode(child.chain_code.as_ref()),
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
        );
    }

    // Known mnemonic -> m/44'/60'/0'/0/0 address, cross-checked against an independent
    // implementation (ethers.js `HDNodeWallet.fromPhrase`).
    const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";
    // ethers.js / hardhat's well-known "test test ... junk" mnemonic; account 0 is the
    // widely-published 0xf39F... address used by Hardhat's default test network.
    const EXPECTED_ADDR_0: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    #[test]
    fn known_mnemonic_derives_expected_address() {
        let seed = EvmSeed::from_phrase(TEST_MNEMONIC).unwrap();
        let secret = seed.derive_secret(DEPOSIT_BRANCH, 0).unwrap();
        let addr = crate::address::address_from_secret(&secret).unwrap();
        assert_eq!(addr, EXPECTED_ADDR_0[..42]);
    }

    // More indices from the same mnemonic, cross-checked against eth-account
    // (`Account.from_mnemonic(mnemonic, account_path=f"m/44'/60'/0'/0/{i}")`) — these are also
    // Hardhat's well-published default accounts #1, #2 and #9.
    #[test]
    fn known_mnemonic_derives_expected_addresses_at_other_indices() {
        let seed = EvmSeed::from_phrase(TEST_MNEMONIC).unwrap();
        let cases = [
            (1u32, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
            (2, "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
            (9, "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720"),
        ];
        for (index, expected) in cases {
            let secret = seed.derive_secret(DEPOSIT_BRANCH, index).unwrap();
            let addr = crate::address::address_from_secret(&secret).unwrap();
            assert_eq!(addr, expected, "mismatch at index {index}");
        }
    }

    // Identity branch (m/44'/60'/0'/1/0), same cross-check method.
    #[test]
    fn identity_branch_matches_independent_implementation() {
        let seed = EvmSeed::from_phrase(TEST_MNEMONIC).unwrap();
        let secret = seed.derive_secret(IDENTITY_BRANCH, 0).unwrap();
        let addr = crate::address::address_from_secret(&secret).unwrap();
        assert_eq!(addr, "0x4b39F7b0624b9dB86AD293686bc38B903142dbBc");
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = EvmSeed::from_phrase(TEST_MNEMONIC).unwrap();
        let b = EvmSeed::from_phrase(TEST_MNEMONIC).unwrap();
        let sa = a.derive_secret(DEPOSIT_BRANCH, 5).unwrap();
        let sb = b.derive_secret(DEPOSIT_BRANCH, 5).unwrap();
        assert_eq!(*sa, *sb);
    }

    #[test]
    fn distinct_indices_yield_distinct_keys() {
        let seed = EvmSeed::from_phrase(TEST_MNEMONIC).unwrap();
        let a = seed.derive_secret(DEPOSIT_BRANCH, 0).unwrap();
        let b = seed.derive_secret(DEPOSIT_BRANCH, 1).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn deposit_and_identity_branches_diverge() {
        let seed = EvmSeed::from_phrase(TEST_MNEMONIC).unwrap();
        let a = seed.derive_secret(DEPOSIT_BRANCH, 0).unwrap();
        let b = seed.derive_secret(IDENTITY_BRANCH, 0).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn index_above_max_non_hardened_is_rejected() {
        let seed = EvmSeed::from_phrase(TEST_MNEMONIC).unwrap();
        assert!(matches!(
            seed.derive_secret(DEPOSIT_BRANCH, MAX_NON_HARDENED_INDEX + 1),
            Err(EvmError::InvalidDerivationIndex)
        ));
        assert!(seed
            .derive_secret(DEPOSIT_BRANCH, MAX_NON_HARDENED_INDEX)
            .is_ok());
    }

    proptest::proptest! {
        #[test]
        fn derivation_is_deterministic_for_any_index(
            entropy in proptest::prelude::any::<[u8; 16]>(),
            index in 0u32..=MAX_NON_HARDENED_INDEX
        ) {
            let mnemonic = bip39::Mnemonic::from_entropy(&entropy, bip39::Language::English).unwrap();
            let seed_bytes = bip39::Seed::new(&mnemonic, "").as_bytes().to_vec();
            let a = EvmSeed::from_bytes(seed_bytes.clone());
            let b = EvmSeed::from_bytes(seed_bytes);
            let sa = a.derive_secret(DEPOSIT_BRANCH, index).unwrap();
            let sb = b.derive_secret(DEPOSIT_BRANCH, index).unwrap();
            proptest::prop_assert_eq!(*sa, *sb);
        }

        #[test]
        fn distinct_indices_never_collide(
            entropy in proptest::prelude::any::<[u8; 16]>(),
            index_a in 0u32..=MAX_NON_HARDENED_INDEX,
            index_b in 0u32..=MAX_NON_HARDENED_INDEX,
        ) {
            proptest::prop_assume!(index_a != index_b);
            let mnemonic = bip39::Mnemonic::from_entropy(&entropy, bip39::Language::English).unwrap();
            let seed = EvmSeed::from_bytes(bip39::Seed::new(&mnemonic, "").as_bytes().to_vec());
            let sa = seed.derive_secret(DEPOSIT_BRANCH, index_a).unwrap();
            let sb = seed.derive_secret(DEPOSIT_BRANCH, index_b).unwrap();
            proptest::prop_assert_ne!(*sa, *sb);
        }
    }
}
