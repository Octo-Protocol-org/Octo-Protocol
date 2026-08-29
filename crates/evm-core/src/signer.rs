//! secp256k1 ECDSA signing over pre-hashed 32-byte digests, with EIP-2 low-s normalisation, and
//! signer-address recovery.
//!
//! Mirrors `octo_wallet_core::signer`'s "no raw-XDR oracle" posture (see its module docs): this
//! module signs a caller-supplied 32-byte digest and nothing else. It has no notion of a
//! transaction, a chain id, or an EIP-155/EIP-1559 signing scheme — building the correct signing
//! hash for whatever is being signed (a legacy tx, a typed-data hash, ...) is the caller's
//! responsibility. The operation exposed here is fixed and narrow (sign *this* digest) rather than
//! a variable-length "sign these arbitrary bytes" primitive that could be pointed at anything.

use crate::error::EvmCoreError;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint as _;

/// A secp256k1 ECDSA signature over a 32-byte digest, in Ethereum's `(r, s, v)` form.
///
/// `v` is the raw recovery id (`0` or `1`) — **not** yet offset into Ethereum's legacy `27`/`28`
/// or EIP-155 `chain_id * 2 + 35`/`36` encodings. Callers apply whichever offset their signing
/// scheme requires; this type only carries the cryptographic recovery bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvmSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

/// Sign a pre-hashed 32-byte digest with `secret` (a derived secp256k1 secret key), producing a
/// low-s normalised `(r, s, v)` signature.
///
/// # Why low-s (EIP-2)
///
/// An ECDSA signature `(r, s)` and `(r, n - s)` both verify against the same message and key —
/// the curve order `n` gives every signature a second, equally valid form. Without normalising to
/// the lower half `[1, (n-1)/2]`, anything that identifies a transaction by its signature bytes
/// (rather than a proper hash-based txid) can be tricked by a third party who resubmits the
/// flipped-`s` form: same authorization, different signature, same effect — classic signature
/// malleability. Normalising to low-s makes the signature canonical.
///
/// # Validation
///
/// `SigningKey::from_bytes` never constructs a key from unvalidated bytes: it rejects any input
/// that is not a valid nonzero scalar strictly less than the curve order, so a corrupted or
/// attacker-influenced `secret` slice fails closed here rather than producing an unpredictable
/// signature.
pub fn sign_digest(secret: &[u8; 32], digest: &[u8; 32]) -> Result<EvmSignature, EvmCoreError> {
    let signing_key =
        SigningKey::from_bytes(secret.into()).map_err(|_| EvmCoreError::KeyDerivation)?;

    let (signature, recovery_id): (Signature, RecoveryId) = signing_key
        .sign_prehash_recoverable(digest)
        .map_err(|_| EvmCoreError::Signing)?;

    // k256's recoverable signing already returns a low-s normalised signature (with a recovery id
    // that already reflects the normalisation) — assert that invariant explicitly rather than
    // silently trusting an upstream default, since a signature this crate hands out with a high-s
    // value would reintroduce the malleability EIP-2 exists to close.
    debug_assert!(
        signature.normalize_s().is_none(),
        "k256 must already return a low-s normalised signature"
    );

    // The recovery id's bit 1 ("x was reduced mod the field prime") only fires when r's true
    // x-coordinate is >= the curve order — probability ~1 in 2^128. Ethereum's (r,s,v) scheme has
    // no slot for that bit, so rather than silently discard it and hand back a v that would fail
    // to recover, treat it as a (vanishingly unlikely) hard signing failure.
    let v = recovery_id.to_byte();
    if v > 1 {
        return Err(EvmCoreError::Signing);
    }

    Ok(EvmSignature {
        r: signature.r().to_bytes().into(),
        s: signature.s().to_bytes().into(),
        v,
    })
}

/// Recover the 20-byte EVM address that produced `signature` over `digest`.
pub fn recover_address(
    digest: &[u8; 32],
    signature: &EvmSignature,
) -> Result<[u8; 20], EvmCoreError> {
    let sig =
        Signature::from_scalars(signature.r, signature.s).map_err(|_| EvmCoreError::Signing)?;
    let recovery_id = RecoveryId::from_byte(signature.v).ok_or(EvmCoreError::Signing)?;

    let verifying_key = VerifyingKey::recover_from_prehash(digest, &sig, recovery_id)
        .map_err(|_| EvmCoreError::Signing)?;

    let public_key: k256::PublicKey = verifying_key.into();
    let encoded = public_key.to_encoded_point(false);
    let mut uncompressed = [0u8; 65];
    uncompressed.copy_from_slice(encoded.as_bytes());
    Ok(crate::address::address_from_uncompressed_public_key(
        &uncompressed,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::to_checksum_address;

    // ---------------------------------------------------------------------
    // Fixed (digest, key) -> (r, s, v) vector.
    //
    // Generated with, and cross-checked between, two independent implementations:
    // Python `eth-keys` (the library underlying `eth-account`/web3.py) and Node `ethers.js` v6 —
    // both produced byte-identical r/s/v/address for privkey = 1,
    // digest = keccak256("octo evm-core signer test vector"). Regenerate with either library to
    // reproduce.
    // ---------------------------------------------------------------------

    const SIGN_PRIVKEY: [u8; 32] = {
        let mut k = [0u8; 32];
        k[31] = 1;
        k
    };
    const SIGN_DIGEST_HEX: &str =
        "689ac62ee0407cbe9ce390cb91457b4a0ebf67f92d2f4697fd55ebb53585ba85";
    const EXPECTED_R_HEX: &str = "e067e8c10e7d41e507b23e26ce3ca4f8d8ad44fb501582a21fdaf1fdf6f9d37d";
    const EXPECTED_S_HEX: &str = "7a607c7a6e0713eb990c293c89b9f7c4a4108bf5c53f0331b35dc78f61189088";
    const EXPECTED_V: u8 = 1;
    const EXPECTED_ADDRESS: &str = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";

    fn digest_bytes() -> [u8; 32] {
        let v = hex::decode(SIGN_DIGEST_HEX).unwrap();
        v.try_into().unwrap()
    }

    #[test]
    fn sign_digest_matches_known_vector() {
        let digest = digest_bytes();
        let sig = sign_digest(&SIGN_PRIVKEY, &digest).unwrap();

        assert_eq!(hex::encode(sig.r), EXPECTED_R_HEX);
        assert_eq!(hex::encode(sig.s), EXPECTED_S_HEX);
        assert_eq!(sig.v, EXPECTED_V);
    }

    #[test]
    fn s_is_always_in_lower_half_of_curve_order() {
        // secp256k1 order n.
        const N: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        // A handful of distinct digests over the same key: low-s must hold for every one, not
        // just the fixed vector above (which could coincidentally already be low-s).
        for msg in [
            "octo evm-core signer test vector",
            "a different message entirely",
            "",
            "0123456789",
        ] {
            let digest = k256_keccak(msg.as_bytes());
            let sig = sign_digest(&SIGN_PRIVKEY, &digest).unwrap();
            // s <= (n-1)/2  <=>  2*s <= n-1 <=> 2*s < n (n is odd). Compare as big-endian bigints.
            let mut doubled = [0u8; 33];
            let mut carry = 0u16;
            for i in (0..32).rev() {
                let v = (sig.s[i] as u16) * 2 + carry;
                doubled[i + 1] = (v & 0xff) as u8;
                carry = v >> 8;
            }
            doubled[0] = (carry & 0xff) as u8;
            let n_extended: [u8; 33] = {
                let mut e = [0u8; 33];
                e[1..].copy_from_slice(&N);
                e
            };
            assert!(doubled < n_extended, "s must be <= (n-1)/2, i.e. 2s < n");
        }
    }

    fn k256_keccak(msg: &[u8]) -> [u8; 32] {
        use sha3::{Digest, Keccak256};
        let hash = Keccak256::digest(msg);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        out
    }

    #[test]
    fn recovery_returns_signing_address() {
        let digest = digest_bytes();
        let sig = sign_digest(&SIGN_PRIVKEY, &digest).unwrap();
        let recovered = recover_address(&digest, &sig).unwrap();
        assert_eq!(to_checksum_address(&recovered), EXPECTED_ADDRESS);
    }

    #[test]
    fn round_trip_recovery_for_derived_keys() {
        let seed = crate::derive::EvmSeed::from_phrase(
            "illness spike retreat truth genius clock brain pass fit cave bargain toe",
        )
        .unwrap();
        for index in [0u32, 1, 7] {
            let secret = seed.derive_secp256k1_secret(index).unwrap();
            let digest = k256_keccak(format!("message for index {index}").as_bytes());
            let sig = sign_digest(&secret, &digest).unwrap();
            let recovered = recover_address(&digest, &sig).unwrap();

            let pubkey = crate::derive::uncompressed_public_key(&secret).unwrap();
            let expected = crate::address::address_from_uncompressed_public_key(&pubkey);
            assert_eq!(recovered, expected);
        }
    }

    #[test]
    fn different_digests_yield_different_signatures() {
        let sig_a = sign_digest(&SIGN_PRIVKEY, &digest_bytes()).unwrap();
        let sig_b = sign_digest(&SIGN_PRIVKEY, &k256_keccak(b"a different message")).unwrap();
        assert_ne!(sig_a.r, sig_b.r);
    }

    #[test]
    fn signing_is_deterministic() {
        let digest = digest_bytes();
        let a = sign_digest(&SIGN_PRIVKEY, &digest).unwrap();
        let b = sign_digest(&SIGN_PRIVKEY, &digest).unwrap();
        assert_eq!(
            a, b,
            "RFC6979 deterministic nonce must give identical signatures"
        );
    }

    #[test]
    fn recovery_rejects_wrong_v() {
        let digest = digest_bytes();
        let sig = sign_digest(&SIGN_PRIVKEY, &digest).unwrap();
        let flipped = EvmSignature {
            v: 1 - sig.v,
            ..sig
        };
        // Flipping v either fails to recover a valid point, or recovers the wrong address —
        // either way it must not silently produce the same address as the correct v.
        if let Ok(addr) = recover_address(&digest, &flipped) {
            assert_ne!(to_checksum_address(&addr), EXPECTED_ADDRESS);
        }
    }

    #[test]
    fn recovery_rejects_tampered_signature() {
        let digest = digest_bytes();
        let mut sig = sign_digest(&SIGN_PRIVKEY, &digest).unwrap();
        sig.r[0] ^= 0xff;
        if let Ok(addr) = recover_address(&digest, &sig) {
            assert_ne!(to_checksum_address(&addr), EXPECTED_ADDRESS);
        }
    }
}
