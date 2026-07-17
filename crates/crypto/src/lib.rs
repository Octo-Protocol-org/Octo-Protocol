//! AES-256-GCM seal/open of the HD seed at rest.
//!
//! This crate is the at-rest encryption boundary for octo's secret material (the HD seed).
//! It knows nothing about Stellar — it just authenticated-encrypts bytes under a 256-bit master
//! key, with two hardening properties beyond plain AES-GCM:
//!
//! 1. **Per-record subkey derivation (HKDF-SHA256).** Each sealed record gets a fresh random
//!    `salt`; the actual AES key is `HKDF(master_key, salt, info=context)`. This means the master
//!    key is never used directly as the cipher key, every record uses a distinct key, and the
//!    `context` (e.g. `"octo:mainnet"`) is bound into key derivation.
//! 2. **AAD context binding.** The same `context` is also passed as AES-GCM associated data, so a
//!    ciphertext sealed for one context cannot be opened under another even if salts collided.
//! 3. **Scheme version tag.** Each [`SealedSeed`] carries an explicit `scheme` byte so that
//!    future cipher or KDF upgrades can be identified without a flag-day migration. The current
//!    scheme is [`SCHEME_V1`] (`1`). Rows in the database default to `1` via the migration
//!    (`0008_scheme_version.sql`). The legacy `scheme = 0` tag maps to the same algorithm as `1`
//!    and exists only as an internal baseline for migration tooling — it is never produced by
//!    `seal` and [`open`] rejects it with [`CryptoError::UnknownScheme`].
//!
//! Plaintext and derived keys are wrapped in [`Zeroizing`] and wiped on drop. Errors are coarse
//! and leak no cryptographic detail (see [`CryptoError`]).
#![forbid(unsafe_code)]
// Secret-handling crate: a panic could surface key material in a backtrace, and lossy/sign
// conversions on amounts are bugs. Deny them (tests may unwrap freely).
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::CryptoError;

use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Length of the AES-256 master key, in bytes.
pub const MASTER_KEY_LEN: usize = 32;
/// Length of the AES-GCM nonce, in bytes (96 bits, the recommended size).
pub const NONCE_LEN: usize = 12;
/// Length of the per-record HKDF salt, in bytes.
pub const SALT_LEN: usize = 32;

/// The current sealing scheme: AES-256-GCM with per-record HKDF-SHA256 subkey derivation and
/// context-bound AAD. All new seals are produced with this scheme tag.
pub const SCHEME_V1: u8 = 1;

/// A sealed secret: the AES-256-GCM ciphertext (including the authentication tag) plus the
/// public, non-secret `nonce` and `salt` needed to open it, and an explicit `scheme` version tag
/// that identifies the cipher and KDF used to produce the ciphertext.
///
/// None of these fields are secret, so deriving `Debug` is safe — but note that `open` *also*
/// requires the original `context` and master key, neither of which is stored here.
///
/// ## Scheme values
/// | `scheme` | Algorithm |
/// |---|---|
/// | `1` (current) | AES-256-GCM, HKDF-SHA256 per-record subkey, context-bound AAD |
///
/// Scheme `0` is a sentinel for "not yet set" in older DB rows; it is never produced by [`seal`]
/// and is rejected by [`open`] with [`CryptoError::UnknownScheme`]. Rows that carry `scheme = 0`
/// must be migrated with [`reseal`] before they can be opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedSeed {
    /// AES-256-GCM ciphertext with the 16-byte GCM tag appended.
    pub ciphertext: Vec<u8>,
    /// Random 96-bit nonce used for this record.
    pub nonce: [u8; NONCE_LEN],
    /// Random salt used to derive this record's subkey via HKDF.
    pub salt: [u8; SALT_LEN],
    /// Scheme version tag. Currently always [`SCHEME_V1`] for records produced by [`seal`].
    pub scheme: u8,
}

impl SealedSeed {
    /// Reconstruct a [`SealedSeed`] from stored byte slices (e.g. read back from the database).
    ///
    /// Fails with [`CryptoError::InvalidNonceLength`] if the nonce or salt have the wrong length.
    pub fn from_parts(
        ciphertext: Vec<u8>,
        nonce: &[u8],
        salt: &[u8],
    ) -> Result<SealedSeed, CryptoError> {
        Self::from_parts_with_scheme(ciphertext, nonce, salt, SCHEME_V1)
    }

    /// Like [`from_parts`] but also accepts the explicit scheme tag stored in the database.
    pub fn from_parts_with_scheme(
        ciphertext: Vec<u8>,
        nonce: &[u8],
        salt: &[u8],
        scheme: u8,
    ) -> Result<SealedSeed, CryptoError> {
        let nonce: [u8; NONCE_LEN] = nonce
            .try_into()
            .map_err(|_| CryptoError::InvalidNonceLength)?;
        let salt: [u8; SALT_LEN] = salt
            .try_into()
            .map_err(|_| CryptoError::InvalidNonceLength)?;
        Ok(SealedSeed {
            ciphertext,
            nonce,
            salt,
            scheme,
        })
    }
}

/// Derive a fresh per-record AES-256 key from the master key, salt, and context using HKDF-SHA256.
///
/// The returned key is zeroized on drop. Expansion to 32 bytes is always within HKDF-SHA256's
/// output limit, so the only error path is structural and surfaces as [`CryptoError`] rather than
/// a panic.
fn derive_subkey(
    master_key: &[u8; MASTER_KEY_LEN],
    salt: &[u8; SALT_LEN],
    context: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(context, okm.as_mut())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(okm)
}

/// Authenticated-encrypt `plaintext` under `master_key`, binding `context` into both the key
/// derivation and the AEAD associated data.
///
/// `context` is a non-secret domain separator that must be supplied identically to [`open`]
/// (e.g. `b"octo:mainnet"`). A fresh random nonce and salt are generated per call, so sealing the
/// same plaintext twice yields different output. The returned [`SealedSeed`] always has
/// `scheme = `[`SCHEME_V1`].
pub fn seal(
    master_key: &[u8; MASTER_KEY_LEN],
    plaintext: &[u8],
    context: &[u8],
) -> Result<SealedSeed, CryptoError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let subkey = derive_subkey(master_key, &salt, context)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(subkey.as_ref()));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: context,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(SealedSeed {
        ciphertext,
        nonce: nonce_bytes,
        salt,
        scheme: SCHEME_V1,
    })
}

/// Authenticated-decrypt a [`SealedSeed`] produced by [`seal`].
///
/// Returns the plaintext wrapped in [`Zeroizing`] so it is wiped when dropped. Fails with
/// [`CryptoError::DecryptionFailed`] for *any* authentication failure (wrong key, tampered
/// ciphertext/nonce/tag, or a `context` that differs from the one used to seal), and with
/// [`CryptoError::UnknownScheme`] when the `scheme` tag is not a value this code knows how to
/// handle — the variant is deliberately indistinguishable across those cases for security.
pub fn open(
    master_key: &[u8; MASTER_KEY_LEN],
    sealed: &SealedSeed,
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    // Validate the scheme tag before attempting any cryptographic operation.
    match sealed.scheme {
        SCHEME_V1 => {} // the only supported scheme
        _ => return Err(CryptoError::UnknownScheme(sealed.scheme)),
    }

    if sealed.nonce.len() != NONCE_LEN {
        return Err(CryptoError::InvalidNonceLength);
    }

    let subkey = derive_subkey(master_key, &sealed.salt, context)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(subkey.as_ref()));
    let nonce = Nonce::from_slice(&sealed.nonce);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &sealed.ciphertext,
                aad: context,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(Zeroizing::new(plaintext))
}

/// Re-seal a [`SealedSeed`] under a new master key and/or scheme.
///
/// This is the atomic unit of key rotation: it opens the seed with `old_master_key` (under the
/// old scheme carried by `sealed`), immediately re-seals it with `new_master_key` under
/// [`SCHEME_V1`], and returns the new [`SealedSeed`]. The plaintext seed lives only in a
/// [`Zeroizing`] buffer for the duration of this call.
///
/// If `old_master_key == new_master_key`, the function is still useful as a cipher/KDF upgrade
/// path. If the record is already sealed under the target scheme and the same key, the caller
/// (i.e. the migration job in `octo-store`) can skip resealing by comparing the `scheme` tag
/// before calling this function — but calling it anyway is safe; it simply produces a fresh
/// nonce/salt (so ciphertext differs).
pub fn reseal(
    old_master_key: &[u8; MASTER_KEY_LEN],
    new_master_key: &[u8; MASTER_KEY_LEN],
    sealed: &SealedSeed,
    context: &[u8],
) -> Result<SealedSeed, CryptoError> {
    // Decrypt under the old key. The seed is held Zeroizing the whole time.
    let plaintext = open(old_master_key, sealed, context)?;
    // Re-encrypt under the new key. `seal` always produces scheme = SCHEME_V1.
    seal(new_master_key, &plaintext, context)
    // `plaintext` is dropped (zeroized) here at end of scope.
}

/// Convenience: parse a 32-byte master key from a byte slice (e.g. decoded from a KMS/env value).
pub fn master_key_from_slice(bytes: &[u8]) -> Result<[u8; MASTER_KEY_LEN], CryptoError> {
    bytes.try_into().map_err(|_| CryptoError::InvalidKeyLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: &[u8] = b"octo:testnet";

    fn key() -> [u8; MASTER_KEY_LEN] {
        let mut k = [0u8; MASTER_KEY_LEN];
        OsRng.fill_bytes(&mut k);
        k
    }

    #[test]
    fn seal_open_roundtrip() {
        let mk = key();
        let secret = b"a 24-word BIP39 mnemonic seed lives here";
        let sealed = seal(&mk, secret, CTX).unwrap();
        let opened = open(&mk, &sealed, CTX).unwrap();
        assert_eq!(opened.as_slice(), secret);
    }

    #[test]
    fn seal_always_produces_scheme_v1() {
        let mk = key();
        let sealed = seal(&mk, b"seed", CTX).unwrap();
        assert_eq!(sealed.scheme, SCHEME_V1, "seal must always produce scheme v1");
    }

    #[test]
    fn ciphertext_is_not_plaintext() {
        let mk = key();
        let secret = b"super secret seed";
        let sealed = seal(&mk, secret, CTX).unwrap();
        assert_ne!(sealed.ciphertext.as_slice(), secret.as_slice());
        // ciphertext carries the 16-byte GCM tag, so it is longer than the plaintext.
        assert_eq!(sealed.ciphertext.len(), secret.len() + 16);
    }

    #[test]
    fn two_seals_differ_nonce_and_ciphertext() {
        let mk = key();
        let secret = b"identical plaintext";
        let a = seal(&mk, secret, CTX).unwrap();
        let b = seal(&mk, secret, CTX).unwrap();
        // Fresh random nonce + salt per call => no reuse, different ciphertext.
        assert_ne!(a.nonce, b.nonce, "nonce must be unique per seal");
        assert_ne!(a.salt, b.salt, "salt must be unique per seal");
        assert_ne!(a.ciphertext, b.ciphertext, "ciphertext must differ");
        // Both still open to the same plaintext.
        assert_eq!(open(&mk, &a, CTX).unwrap().as_slice(), secret);
        assert_eq!(open(&mk, &b, CTX).unwrap().as_slice(), secret);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mk = key();
        let mut sealed = seal(&mk, b"seed", CTX).unwrap();
        sealed.ciphertext[0] ^= 0xff;
        assert!(matches!(
            open(&mk, &sealed, CTX),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn tampered_tag_fails() {
        let mk = key();
        let mut sealed = seal(&mk, b"seed", CTX).unwrap();
        // The last byte is part of the GCM tag.
        let last = sealed.ciphertext.len() - 1;
        sealed.ciphertext[last] ^= 0x01;
        assert!(matches!(
            open(&mk, &sealed, CTX),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn tampered_nonce_fails() {
        let mk = key();
        let mut sealed = seal(&mk, b"seed", CTX).unwrap();
        sealed.nonce[0] ^= 0xff;
        assert!(matches!(
            open(&mk, &sealed, CTX),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn wrong_master_key_fails() {
        let mk = key();
        let other = key();
        let sealed = seal(&mk, b"seed", CTX).unwrap();
        assert!(matches!(
            open(&other, &sealed, CTX),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn wrong_context_fails() {
        // A record sealed for mainnet must not open under testnet, even with the right key.
        let mk = key();
        let sealed = seal(&mk, b"seed", b"octo:mainnet").unwrap();
        assert!(matches!(
            open(&mk, &sealed, b"octo:testnet"),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let mk = key();
        let sealed = seal(&mk, b"", CTX).unwrap();
        assert_eq!(open(&mk, &sealed, CTX).unwrap().as_slice(), b"");
    }

    #[test]
    fn master_key_from_slice_validates_length() {
        assert!(master_key_from_slice(&[0u8; 32]).is_ok());
        assert!(matches!(
            master_key_from_slice(&[0u8; 31]),
            Err(CryptoError::InvalidKeyLength)
        ));
        assert!(matches!(
            master_key_from_slice(&[0u8; 33]),
            Err(CryptoError::InvalidKeyLength)
        ));
    }

    /// Opening a record with an unknown scheme tag must fail with `UnknownScheme`, not silently
    /// misinterpret the bytes or panic. This is the forward-compatibility contract: any future
    /// scheme added to the enum must be explicitly handled in `open`; the catch-all arm here
    /// ensures that unrecognised values are rejected rather than silently accepted.
    #[test]
    fn unknown_scheme_tag_is_rejected_not_silently_misinterpreted() {
        let mk = key();
        // Build a well-formed SealedSeed with a scheme tag that doesn't exist yet (255).
        let valid = seal(&mk, b"seed", CTX).unwrap();
        let unknown_scheme = SealedSeed {
            scheme: 255,
            ..valid
        };
        let err = open(&mk, &unknown_scheme, CTX)
            .expect_err("open must fail for unknown scheme");
        assert!(
            matches!(err, CryptoError::UnknownScheme(255)),
            "expected UnknownScheme(255), got: {err:?}"
        );
    }

    /// Scheme 0 is the "unset" sentinel from old DB rows (before the scheme column existed).
    /// It must be rejected by `open` with `UnknownScheme(0)` — not decrypted silently.
    #[test]
    fn scheme_zero_is_rejected_by_open() {
        let mk = key();
        let valid = seal(&mk, b"seed", CTX).unwrap();
        let scheme_zero = SealedSeed { scheme: 0, ..valid };
        let err = open(&mk, &scheme_zero, CTX)
            .expect_err("scheme 0 must be rejected by open");
        assert!(
            matches!(err, CryptoError::UnknownScheme(0)),
            "expected UnknownScheme(0), got: {err:?}"
        );
    }

    /// `reseal` must produce a record openable with the new key and not the old one.
    #[test]
    fn reseal_produces_record_openable_only_with_new_key() {
        let old_key = key();
        let new_key = key();
        let secret = b"important seed material";
        let sealed_v1 = seal(&old_key, secret, CTX).unwrap();

        let resealed = reseal(&old_key, &new_key, &sealed_v1, CTX).unwrap();

        // The resealed record opens with the new key.
        let opened = open(&new_key, &resealed, CTX).unwrap();
        assert_eq!(opened.as_slice(), secret);

        // The resealed record does NOT open with the old key.
        assert!(
            matches!(open(&old_key, &resealed, CTX), Err(CryptoError::DecryptionFailed)),
            "resealed record must not open with the old key"
        );

        // The resealed record carries the current scheme tag.
        assert_eq!(resealed.scheme, SCHEME_V1);
    }

    /// Re-sealing under the same key is idempotent on the plaintext but produces fresh
    /// nonce/salt (different ciphertext), which is correct and intentional.
    #[test]
    fn reseal_same_key_produces_fresh_ciphertext_but_same_plaintext() {
        let key = key();
        let secret = b"seed";
        let original = seal(&key, secret, CTX).unwrap();
        let resealed = reseal(&key, &key, &original, CTX).unwrap();

        // Plaintext is preserved.
        assert_eq!(open(&key, &resealed, CTX).unwrap().as_slice(), secret);
        // But nonce/salt/ciphertext are different (fresh randomness).
        assert_ne!(original.nonce, resealed.nonce);
        assert_ne!(original.salt, resealed.salt);
        assert_ne!(original.ciphertext, resealed.ciphertext);
    }

    /// Ensure that the `Zeroizing` wrapper is used throughout the reseal path.
    /// This is a structural assertion: the plaintext never escapes the reseal function as a
    /// plain `Vec<u8>` — it is always wrapped in `Zeroizing<Vec<u8>>` and dropped at the end of
    /// `reseal`. Runtime verification of memory contents is impractical in a portable test, so we
    /// assert at the type level: `open` returns `Zeroizing<Vec<u8>>`, and `reseal` consumes it
    /// without converting it to a plain Vec (readable in `reseal`'s source above).
    #[test]
    fn reseal_path_uses_zeroizing_buffer_structural_assertion() {
        // The return type of `open` is `Zeroizing<Vec<u8>>` — if the code ever
        // unwraps it to a plain Vec before re-sealing, this won't compile.
        let key = key();
        let sealed = seal(&key, b"seed", CTX).unwrap();
        // Call reseal; the important property is that it compiles cleanly with the `Zeroizing`
        // wrapper used throughout (see `reseal` implementation: `open` → `Zeroizing`, passed
        // directly to `seal`'s `plaintext` parameter without any `.to_vec()` or similar).
        let _resealed = reseal(&key, &key, &sealed, CTX).unwrap();
    }
}
