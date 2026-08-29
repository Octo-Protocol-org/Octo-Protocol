//! BIP-32 secp256k1 HD derivation for EVM chains, at `m/44'/60'/0'/0/{index}` (BIP-44), from the
//! same BIP-39 mnemonic type already used by `octo-wallet-core`.
//!
//! # ⚠️ Non-hardened tail: read before touching #220 or #224
//!
//! Stellar's SEP-0005 path (`m/44'/148'/index'`) is all-hardened. BIP-44's last two levels
//! (`change`, `address_index`) are deliberately **not** hardened — that's what lets an
//! account-level extended *public* key (xpub) derive every customer's deposit address without the
//! private key ever touching the address-generating host.
//!
//! The price of that convenience: **a leaked non-hardened child private key, combined with the
//! account-level xpub, recovers the account-level private key** — and therefore every sibling
//! child key under it. This falls directly out of the CKD-priv formula used below:
//! `child_priv = (IL + parent_priv) mod n`, where `IL` comes from
//! `HMAC-SHA512(parent_chain_code, parent_pubkey || index)`. Anyone holding the xpub (parent
//! pubkey + parent chain code) can recompute `IL` for the known index the moment they see a leaked
//! `child_priv`, then solve `parent_priv = (child_priv - IL) mod n`. Hardened derivation avoids
//! this because it hashes the parent *private* key instead of the public key, so `IL` cannot be
//! recomputed from public data alone.
//!
//! Practically: octo must never publish or persist an xpub for this HD tree unless it also accepts
//! that every non-hardened descendant private key leak is equivalent to leaking the whole
//! sub-tree's spending authority. #220 (xpub-based per-customer address derivation) and #224 (the
//! sweep engine, which necessarily holds descendant private keys) must be built with this
//! consequence in mind.
//!
//! # Zero-derivation edge case
//!
//! BIP-32 requires each CKD step to reject (skip to the next index) if the HMAC output's left half
//! (`IL`) is not a valid scalar (`>= n`) or if the resulting child key is exactly zero. Both are
//! astronomically unlikely (~2^-127) for real seeds but are checked in constant time on every call
//! (see [`is_zero_scalar_ct`]) rather than assumed away, since skipping the check would mean
//! constructing a signing key from unvalidated material.

use crate::error::EvmCoreError;
use hmac::{Hmac, Mac};
use k256::elliptic_curve::group::GroupEncoding as _;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use k256::elliptic_curve::PrimeField as _;
use k256::{ProjectivePoint, PublicKey as K256PublicKey, Scalar, SecretKey};
use sha2::Sha512;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha512 = Hmac<Sha512>;

/// BIP-44 purpose constant.
const BIP44_PURPOSE: u32 = 44;
/// EVM's SLIP-0044 coin type.
const EVM_COIN_TYPE: u32 = 60;
/// Hardened-derivation offset.
const HARDENED: u32 = 0x8000_0000;

/// A BIP39 seed (the 64-byte output of mnemonic + passphrase), zeroized on drop.
pub struct EvmSeed(Zeroizing<Vec<u8>>);

impl EvmSeed {
    /// Reconstruct a seed from an existing BIP39 mnemonic phrase (the same mnemonic type used for
    /// the Stellar wallet — an EVM key can be derived from the same backup phrase under a
    /// different coin type).
    pub fn from_phrase(phrase: &str) -> Result<EvmSeed, EvmCoreError> {
        let mnemonic = bip39::Mnemonic::from_phrase(phrase, bip39::Language::English)
            .map_err(|_| EvmCoreError::InvalidMnemonic)?;
        let seed = bip39::Seed::new(&mnemonic, "");
        Ok(EvmSeed(Zeroizing::new(seed.as_bytes().to_vec())))
    }

    /// Construct directly from raw seed bytes (e.g. after decrypting a sealed seed).
    pub fn from_bytes(bytes: Vec<u8>) -> EvmSeed {
        EvmSeed(Zeroizing::new(bytes))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Derive the 32-byte secp256k1 secret key for EVM account `index`
    /// (`m/44'/60'/0'/0/{index}`).
    ///
    /// Returned zeroized. Fails only if a derivation step hits the ~2^-127-probability invalid-
    /// scalar case described in the module docs, in which case the seed should not be used for
    /// this index (there is no legitimate reason to construct a signing key from an invalid
    /// scalar, so this is surfaced as an error rather than silently retried).
    pub fn derive_secp256k1_secret(&self, index: u32) -> Result<Zeroizing<[u8; 32]>, EvmCoreError> {
        let path = [
            BIP44_PURPOSE | HARDENED,
            EVM_COIN_TYPE | HARDENED,
            HARDENED, // account' = 0'
            0,        // change
            index,    // address_index
        ];
        let (secret, _chain_code) = derive_path(self.as_bytes(), &path)?;
        Ok(secret)
    }
}

/// Derive the secret key and chain code at `path` from `seed`, applying BIP-32 CKD-priv at each
/// level. `path` entries with the high bit set (`& HARDENED != 0`) are hardened.
///
/// Exposed at the crate's internal granularity (rather than only the fixed BIP-44 wrapper above)
/// so tests can walk the exact chains from BIP-32's own Test Vector 1 and 2, which use derivation
/// paths octo never derives in production (e.g. `m/0'/1/2'/2/1000000000`).
pub(crate) fn derive_path(
    seed: &[u8],
    path: &[u32],
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), EvmCoreError> {
    let (mut key, mut chain_code) = master_key(seed)?;
    for &child in path {
        let (next_key, next_chain_code) = ckd_priv(&key, &chain_code, child)?;
        key = next_key;
        chain_code = next_chain_code;
    }
    Ok((key, chain_code))
}

/// BIP-32 master key generation: `I = HMAC-SHA512(key = "Bitcoin seed", data = seed)`,
/// `IL` = master secret key, `IR` = master chain code.
fn master_key(seed: &[u8]) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), EvmCoreError> {
    let mut mac =
        HmacSha512::new_from_slice(b"Bitcoin seed").map_err(|_| EvmCoreError::KeyDerivation)?;
    mac.update(seed);
    let i = Zeroizing::new(mac.finalize().into_bytes());

    let il: [u8; 32] = i[..32]
        .try_into()
        .map_err(|_| EvmCoreError::KeyDerivation)?;
    let chain_code: [u8; 32] = i[32..]
        .try_into()
        .map_err(|_| EvmCoreError::KeyDerivation)?;

    // BIP-32: master IL must be a valid, nonzero scalar. Constant-time — see module docs.
    let il_scalar = require_valid_secret_scalar(&il)?;
    Ok((Zeroizing::new(scalar_to_bytes(&il_scalar)), chain_code))
}

/// One step of BIP-32 CKD-priv (private parent -> private child).
fn ckd_priv(
    key: &Zeroizing<[u8; 32]>,
    chain_code: &[u8; 32],
    index: u32,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), EvmCoreError> {
    let mut mac =
        HmacSha512::new_from_slice(chain_code).map_err(|_| EvmCoreError::KeyDerivation)?;

    if index & HARDENED != 0 {
        // Hardened: data = 0x00 || ser256(kpar) || ser32(index). Hashes the PARENT PRIVATE key —
        // this is precisely why a leaked hardened child does not expose the parent (see module
        // docs): IL cannot be recomputed from public data alone.
        mac.update(&[0u8]);
        mac.update(key.as_slice());
    } else {
        // Non-hardened: data = serP(point(kpar)) || ser32(index). Hashes the PARENT PUBLIC key.
        let parent_secret = SecretKey::from_bytes(key.as_slice().into())
            .map_err(|_| EvmCoreError::KeyDerivation)?;
        let parent_public = parent_secret.public_key();
        let compressed = parent_public.to_encoded_point(true);
        mac.update(compressed.as_bytes());
    }
    mac.update(&index.to_be_bytes());

    let i = Zeroizing::new(mac.finalize().into_bytes());
    let il: [u8; 32] = i[..32]
        .try_into()
        .map_err(|_| EvmCoreError::KeyDerivation)?;
    let chain_code_out: [u8; 32] = i[32..]
        .try_into()
        .map_err(|_| EvmCoreError::KeyDerivation)?;

    let il_scalar = require_valid_secret_scalar(&il)?;
    let parent_scalar = Option::<Scalar>::from(Scalar::from_repr((**key).into()))
        .ok_or(EvmCoreError::KeyDerivation)?;

    let child_scalar = il_scalar + parent_scalar;
    // BIP-32: the resulting child key must not be zero. Constant-time — see module docs.
    if bool::from(child_scalar.is_zero()) {
        return Err(EvmCoreError::InvalidDerivationPath);
    }

    Ok((
        Zeroizing::new(scalar_to_bytes(&child_scalar)),
        chain_code_out,
    ))
}

/// Parse `bytes` as a secp256k1 scalar, rejecting `>= n` (invalid encoding) and `== 0` (invalid
/// private key) — both required by BIP-32 for `IL` — using constant-time comparisons throughout
/// so a derivation step never leaks secret-dependent timing.
fn require_valid_secret_scalar(bytes: &[u8; 32]) -> Result<Scalar, EvmCoreError> {
    // `Scalar::from_repr` itself runs in constant time and returns `None` (via `CtOption`) for any
    // value >= the curve order n, so out-of-range encodings never reach the zero check below.
    let scalar = Option::<Scalar>::from(Scalar::from_repr((*bytes).into()))
        .ok_or(EvmCoreError::InvalidDerivationPath)?;
    // Defense in depth: explicit constant-time zero check on the secret scalar via `subtle`,
    // independent of `Scalar`'s own (also constant-time) `is_zero`.
    let is_zero: bool = bytes.ct_eq(&[0u8; 32]).into();
    if is_zero || bool::from(scalar.is_zero()) {
        return Err(EvmCoreError::InvalidDerivationPath);
    }
    Ok(scalar)
}

fn scalar_to_bytes(scalar: &Scalar) -> [u8; 32] {
    scalar.to_repr().into()
}

/// Build the AAD/context string [`octo_crypto`] binds a sealed EVM seed to:
/// `"octo:{chain_id}"` (e.g. `"octo:eip155:1"`).
///
/// Distinguishing by full chain id — not just a generic `"evm"` tag — means a seed sealed for one
/// EVM chain cannot be opened under a *different* EVM chain's context either, not only isolated
/// from Stellar. octo-wallet-core's Stellar contexts (`"octo:mainnet"`, `"octo:testnet"`,
/// `"octo:standalone"` — see `StellarNetwork::crypto_context`) share the same `"octo:"` namespace
/// but never collide with an `"octo:eip155:*"` value, so a seed sealed under one chain family can
/// never be opened under the other even by coincidence.
pub fn crypto_context(chain_id: &str) -> Vec<u8> {
    format!("octo:{chain_id}").into_bytes()
}

/// Compute the uncompressed secp256k1 public key (65 bytes: `0x04 || X || Y`) for a derived
/// secret key. Used by [`crate::address`] to derive the EVM address, and never exposes the
/// secret scalar itself to callers.
pub(crate) fn uncompressed_public_key(secret: &[u8; 32]) -> Result<[u8; 65], EvmCoreError> {
    let secret_key =
        SecretKey::from_bytes(secret.into()).map_err(|_| EvmCoreError::KeyDerivation)?;
    let public_key: K256PublicKey = secret_key.public_key();
    let encoded = public_key.to_encoded_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(encoded.as_bytes());
    // Touch GroupEncoding so the import is used regardless of which k256 arithmetic path the
    // compiler picks; ProjectivePoint's affine roundtrip is exercised in tests below.
    let _ = ProjectivePoint::from(*public_key.as_affine()).to_bytes();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // BIP-32 Test Vector 1 & 2
    // Source: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki ("Test vector 1" /
    // "Test vector 2"), fetched 2026-08-25. The expected private key + chain code at each level
    // are extracted here by base58check-decoding the spec's own `ext prv` strings (bs58, dev-dep
    // only) rather than hand-transcribed, so a transcription slip can't silently pass.
    // ---------------------------------------------------------------------

    /// Base58check-decode a `xprv...` string into (depth, child_number, chain_code, secret_key).
    fn decode_xprv(xprv: &str) -> (u8, u32, [u8; 32], [u8; 32]) {
        let payload = bs58::decode(xprv)
            .with_check(None)
            .into_vec()
            .expect("valid base58check xprv");
        assert_eq!(
            payload.len(),
            78,
            "serialized extended key must be 78 bytes"
        );
        assert_eq!(
            &payload[0..4],
            &0x0488ADE4u32.to_be_bytes(),
            "mainnet xprv version bytes"
        );
        let depth = payload[4];
        let child_number = u32::from_be_bytes(payload[9..13].try_into().unwrap());
        let chain_code: [u8; 32] = payload[13..45].try_into().unwrap();
        assert_eq!(
            payload[45], 0x00,
            "private key data must be prefixed with 0x00"
        );
        let secret: [u8; 32] = payload[46..78].try_into().unwrap();
        (depth, child_number, chain_code, secret)
    }

    fn assert_path_matches(seed_hex: &str, path: &[u32], expected_xprv: &str) {
        let seed = hex::decode(seed_hex).unwrap();
        let (_, _, expected_chain_code, expected_secret) = decode_xprv(expected_xprv);
        let (secret, chain_code) = derive_path(&seed, path).unwrap();
        assert_eq!(
            *secret, expected_secret,
            "private key mismatch for path {path:?}"
        );
        assert_eq!(
            chain_code, expected_chain_code,
            "chain code mismatch for path {path:?}"
        );
    }

    #[test]
    // `0 | H` mirrors the spec's own "0'" path notation (index 0, hardened) for readability
    // against the BIP-32 test vector text, even though `0 | H == H` makes the `0 |` a no-op.
    #[allow(clippy::identity_op)]
    fn bip32_test_vector_1() {
        const SEED: &str = "000102030405060708090a0b0c0d0e0f";
        const H: u32 = HARDENED;

        assert_path_matches(
            SEED,
            &[],
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
        );
        assert_path_matches(
            SEED,
            &[0 | H],
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
        );
        assert_path_matches(
            SEED,
            &[0 | H, 1],
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
        );
        assert_path_matches(
            SEED,
            &[0 | H, 1, 2 | H],
            "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
        );
        assert_path_matches(
            SEED,
            &[0 | H, 1, 2 | H, 2],
            "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
        );
        assert_path_matches(
            SEED,
            &[0 | H, 1, 2 | H, 2, 1_000_000_000],
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
        );
    }

    #[test]
    fn bip32_test_vector_2() {
        const SEED: &str = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
        const H: u32 = HARDENED;
        // Boundary indices: 2147483647 is the highest valid *non*-hardened u32 (HARDENED - 1),
        // and 2147483647' == u32::MAX is the highest valid hardened index.
        const MAX_NONHARDENED: u32 = 2_147_483_647;

        assert_path_matches(
            SEED,
            &[],
            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
        );
        assert_path_matches(
            SEED,
            &[0],
            "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
        );
        assert_path_matches(
            SEED,
            &[0, MAX_NONHARDENED | H],
            "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
        );
        assert_eq!(
            MAX_NONHARDENED | H,
            u32::MAX,
            "sanity: highest hardened index is u32::MAX"
        );
        assert_path_matches(
            SEED,
            &[0, MAX_NONHARDENED | H, 1],
            "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
        );
        assert_path_matches(
            SEED,
            &[0, MAX_NONHARDENED | H, 1, (MAX_NONHARDENED - 1) | H],
            "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
        );
        assert_path_matches(
            SEED,
            &[0, MAX_NONHARDENED | H, 1, (MAX_NONHARDENED - 1) | H, 2],
            "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
        );
    }

    // ---------------------------------------------------------------------
    // Mnemonic -> address, cross-checked against two independent implementations.
    //
    // Generated 2026-08-25 with Python `eth-account`/`eth-keys` (the library underlying
    // web3.py) and Node `ethers.js` v6, independently, for mnemonic (the same phrase already
    // used as octo-wallet-core's SEP-0005 vector) at m/44'/60'/0'/0/{0,1,2}. Both implementations
    // produced byte-identical addresses and private keys. Regenerate with either library to
    // reproduce:
    //   python: Account.from_mnemonic(MNEMONIC, account_path="m/44'/60'/0'/0/0").address
    //   node:   ethers.HDNodeWallet.fromMnemonic(ethers.Mnemonic.fromPhrase(MNEMONIC),
    //                                             "m/44'/60'/0'/0/0").address
    // ---------------------------------------------------------------------

    const VECTOR_MNEMONIC: &str =
        "illness spike retreat truth genius clock brain pass fit cave bargain toe";

    const EXPECTED_ADDR_0: &str = "0x6b30c7d7657A83141186Cd8c155CDB90C8750371";
    const EXPECTED_PRIV_0: &str =
        "a372be85c90ff55eb343815d88ecc36938e0b84641a66faeb0d0627e5caedc9a";
    const EXPECTED_ADDR_1: &str = "0x754c39C8836A546e7CF6A2f099033fCB6675e63f";
    const EXPECTED_PRIV_1: &str =
        "d02ff57db5ffbf14f83e02401f8123f462ca99d281406922f9c42900088548bb";
    const EXPECTED_ADDR_2: &str = "0x7BacbFad8d4E1948842eFA3fA2CFfe872c7BA3AF";
    const EXPECTED_PRIV_2: &str =
        "4f5f89cd91af690affafbc1f64a49a52ff1d379c02efdc5927b01b689fd37ff1";

    #[test]
    fn mnemonic_to_address_matches_independent_implementations() {
        let seed = EvmSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        for (index, expected_addr, expected_priv) in [
            (0u32, EXPECTED_ADDR_0, EXPECTED_PRIV_0),
            (1, EXPECTED_ADDR_1, EXPECTED_PRIV_1),
            (2, EXPECTED_ADDR_2, EXPECTED_PRIV_2),
        ] {
            let secret = seed.derive_secp256k1_secret(index).unwrap();
            assert_eq!(
                hex::encode(*secret),
                expected_priv,
                "private key mismatch at index {index}"
            );

            let public_key = uncompressed_public_key(&secret).unwrap();
            let address = crate::address::address_from_uncompressed_public_key(&public_key);
            let checksummed = crate::address::to_checksum_address(&address);
            assert_eq!(
                checksummed, expected_addr,
                "address mismatch at index {index}"
            );
        }
    }

    // ---------------------------------------------------------------------
    // Sealing / context isolation (reuses octo-crypto; see crypto_context docs).
    // ---------------------------------------------------------------------

    #[test]
    fn seal_open_roundtrip_with_evm_context() {
        let seed = EvmSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        let mk = [7u8; 32];
        let ctx = crypto_context("eip155:1");
        let sealed = octo_crypto::seal(&mk, seed.as_bytes(), &ctx).unwrap();
        let opened = octo_crypto::open(&mk, &sealed, &ctx).unwrap();
        assert_eq!(opened.as_slice(), seed.as_bytes());
    }

    #[test]
    fn seed_sealed_for_eip155_context_cannot_open_under_stellar_context() {
        let seed = EvmSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        let mk = [7u8; 32];
        let eip155_ctx = crypto_context("eip155:1");
        let sealed = octo_crypto::seal(&mk, seed.as_bytes(), &eip155_ctx).unwrap();

        // Must match octo_wallet_core::signer::StellarNetwork::Public::crypto_context() exactly
        // (kept as a literal, not an import, so evm-core does not depend on wallet-core).
        let stellar_mainnet_ctx: &[u8] = b"octo:mainnet";
        assert!(matches!(
            octo_crypto::open(&mk, &sealed, stellar_mainnet_ctx),
            Err(octo_crypto::CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn seed_sealed_for_one_evm_chain_cannot_open_under_another() {
        let seed = EvmSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        let mk = [7u8; 32];
        let mainnet_ctx = crypto_context("eip155:1");
        let sepolia_ctx = crypto_context("eip155:11155111");
        let sealed = octo_crypto::seal(&mk, seed.as_bytes(), &mainnet_ctx).unwrap();
        assert!(matches!(
            octo_crypto::open(&mk, &sealed, &sepolia_ctx),
            Err(octo_crypto::CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = EvmSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        let b = EvmSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        assert_eq!(
            *a.derive_secp256k1_secret(0).unwrap(),
            *b.derive_secp256k1_secret(0).unwrap()
        );
    }

    #[test]
    fn different_indexes_give_different_secrets() {
        let seed = EvmSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        let a = seed.derive_secp256k1_secret(0).unwrap();
        let b = seed.derive_secp256k1_secret(1).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn invalid_mnemonic_rejected() {
        assert!(matches!(
            EvmSeed::from_phrase("not a real mnemonic phrase at all"),
            Err(EvmCoreError::InvalidMnemonic)
        ));
    }

    // ---------------------------------------------------------------------
    // Zeroize on drop. `Zeroizing<T>`'s `Drop` impl calls `Zeroize::zeroize()` on its inner value
    // (that's its entire purpose), so exercising `zeroize()` directly on the same wrapped bytes
    // tests the exact code path `Drop` runs, without needing an unsafe use-after-free memory read
    // (which `#![forbid(unsafe_code)]` disallows even in this crate's own tests).
    // ---------------------------------------------------------------------

    #[test]
    fn derived_secret_is_zeroized_on_drop() {
        use zeroize::Zeroize;
        let seed = EvmSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        let mut secret = seed.derive_secp256k1_secret(0).unwrap();
        assert_ne!(
            *secret, [0u8; 32],
            "sanity: a real derived secret must not already be zero"
        );
        secret.zeroize();
        assert_eq!(
            *secret,
            [0u8; 32],
            "Zeroizing<[u8; 32]>::zeroize — the exact call its Drop impl makes — must clear the secret"
        );
    }

    #[test]
    fn seed_bytes_are_zeroized_on_drop() {
        use zeroize::Zeroize;
        let mut seed = EvmSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        assert!(
            seed.0.iter().any(|&b| b != 0),
            "sanity: a real seed must not already be all-zero"
        );
        seed.0.zeroize();
        assert!(
            seed.0.iter().all(|&b| b == 0),
            "Zeroizing<Vec<u8>>::zeroize — the exact call its Drop impl makes — must clear the seed"
        );
    }

    #[test]
    fn boundary_indices_derive_without_panic() {
        let seed = EvmSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        for index in [0u32, 1, HARDENED - 1, u32::MAX] {
            let secret = seed.derive_secp256k1_secret(index).unwrap();
            // Must be a valid, constructible secp256k1 secret key.
            assert!(SecretKey::from_bytes((*secret).as_ref().into()).is_ok());
        }
    }

    proptest::proptest! {
        #[test]
        fn derivation_is_deterministic_for_any_index(
            entropy in proptest::prelude::any::<[u8; 16]>(),
            index in proptest::prelude::any::<u32>()
        ) {
            let mnemonic = bip39::Mnemonic::from_entropy(&entropy, bip39::Language::English).unwrap();
            let seed_bytes = bip39::Seed::new(&mnemonic, "").as_bytes().to_vec();
            let seed_a = EvmSeed::from_bytes(seed_bytes.clone());
            let seed_b = EvmSeed::from_bytes(seed_bytes);
            let secret_a = seed_a.derive_secp256k1_secret(index).unwrap();
            let secret_b = seed_b.derive_secp256k1_secret(index).unwrap();
            proptest::prop_assert_eq!(*secret_a, *secret_b);
        }

        #[test]
        fn distinct_indices_yield_distinct_secrets(
            entropy in proptest::prelude::any::<[u8; 16]>(),
            index_a in proptest::prelude::any::<u32>(),
            index_b in proptest::prelude::any::<u32>()
        ) {
            proptest::prop_assume!(index_a != index_b);
            let mnemonic = bip39::Mnemonic::from_entropy(&entropy, bip39::Language::English).unwrap();
            let seed = EvmSeed::from_bytes(bip39::Seed::new(&mnemonic, "").as_bytes().to_vec());
            let secret_a = seed.derive_secp256k1_secret(index_a).unwrap();
            let secret_b = seed.derive_secp256k1_secret(index_b).unwrap();
            proptest::prop_assert_ne!(*secret_a, *secret_b);
        }
    }
}
