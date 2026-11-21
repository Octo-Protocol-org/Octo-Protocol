//! EVM signing primitives.
//!
//! This module mirrors the "no raw-XDR oracle" posture of
//! `wallet-core/src/signer.rs`: we expose *typed* operations (sign a
//! transaction hash, sign a personal-message digest, recover an address)
//! rather than a general-purpose "sign these arbitrary bytes" primitive.
//! That keeps the surface small and makes it harder to accidentally build
//! a signing oracle out of this crate.
//!
//! # Security notes
//!
//! * Signatures are produced with **low-`s` normalisation** (EIP-2). Without
//!   this, `(r, s)` and `(r, n - s)` are both valid signatures over the same
//!   digest, which makes signatures malleable and breaks any code that
//!   treats a signature as a unique identifier.
//! * Secret key material is held in [`Zeroizing`] buffers and is wiped on
//!   drop.
//! * Secret comparisons use [`subtle`]'s constant-time equality.
//! * Sealed key material reuses [`octo_crypto`] with a **chain-scoped AAD
//!   context** so that a key sealed for an EVM chain cannot be opened in a
//!   Stellar context (and vice versa).

use k256::ecdsa::{
    RecoveryId, Signature, SigningKey, VerifyingKey,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha3::{Digest, Keccak256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::address::{Address, validate_address};
use crate::error::EvmError;

/// AAD context prefix used when sealing EVM key material.
///
/// The full context is `octo:eip155:<chain_id>`, e.g. `octo:eip155:1` for
/// Ethereum mainnet. This deliberately differs from the Stellar context used
/// by `wallet-core` so that a sealed EVM key cannot be opened in a Stellar
/// context.
pub const EVM_SEAL_CONTEXT_PREFIX: &str = "octo:eip155";

/// Build the chain-scoped AAD context string for a given EIP-155 chain id.
///
/// # Panics
///
/// Never panics; the formatting is infallible.
pub fn seal_context(chain_id: u64) -> String {
    format!("{EVM_SEAL_CONTEXT_PREFIX}:{chain_id}")
}

/// A secp256k1 signing key for EVM chains.
///
/// Wraps a [`SigningKey`] and keeps the raw secret bytes in a
/// [`Zeroizing`] buffer so they are wiped on drop.
pub struct EvmSigner {
    /// The underlying signing key. `k256`'s `SigningKey` already zeroizes
    /// its scalar on drop, but we additionally keep the raw bytes in a
    /// `Zeroizing` buffer for the sealing path.
    key: SigningKey,
    /// Raw 32-byte secret scalar, zeroized on drop.
    secret: Zeroizing<[u8; 32]>,
}

impl EvmSigner {
    /// Construct a signer from a 32-byte secret scalar.
    ///
    /// The bytes are validated to be a non-zero scalar strictly less than
    /// the secp256k1 group order `n`. This is the *only* way to build a
    /// signer from raw bytes, and it rejects out-of-range values rather
    /// than silently reducing them.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, EvmError> {
        // `SigningKey::from_bytes` rejects zero and values >= n.
        let key = SigningKey::from_bytes(bytes.into())
            .map_err(|_| EvmError::InvalidSecretKey)?;
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(bytes);
        Ok(Self { key, secret })
    }

    /// Construct a signer from a [`Zeroizing`] 32-byte secret scalar.
    pub fn from_zeroizing(bytes: &Zeroizing<[u8; 32]>) -> Result<Self, EvmError> {
        Self::from_bytes(bytes)
    }

    /// Return the 20-byte EVM address for this signer.
    pub fn address(&self) -> Address {
        address_from_verifying_key(self.key.verifying_key())
    }

    /// Return the compressed SEC1 public key bytes.
    pub fn public_key_compressed(&self) -> [u8; 33] {
        let point = self.key.verifying_key().to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// Return the uncompressed SEC1 public key bytes (65 bytes, `0x04` prefix).
    pub fn public_key_uncompressed(&self) -> [u8; 65] {
        let point = self.key.verifying_key().to_encoded_point(false);
        let mut out = [0u8; 65];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// Sign a 32-byte digest, returning `(r, s, v)` with low-`s`
    /// normalisation (EIP-2).
    ///
    /// `v` is the EIP-155 recovery id (`0` or `1`). Callers that need the
    /// legacy `27`/`28` offset or the EIP-155 `chain_id * 2 + 35 + recid`
    /// encoding should apply that themselves.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<SignatureParts, EvmError> {
        let (sig, recid) = self
            .key
            .sign_prehash_recoverable(digest)
            .map_err(|_| EvmError::SigningFailed)?;
        Ok(SignatureParts::from_parts(sig, recid))
    }

    /// Sign a 32-byte digest and return the signature as a 65-byte
    /// `r || s || v` buffer, with low-`s` normalisation.
    pub fn sign_digest_bytes(&self, digest: &[u8; 32]) -> Result<[u8; 65], EvmError> {
        let parts = self.sign_digest(digest)?;
        Ok(parts.to_bytes())
    }

    /// Sign an EIP-191 personal message.
    ///
    /// The message is hashed as
    /// `keccak256("\x19Ethereum Signed Message:\n" || len || message)`
    /// before signing. This is a *typed* operation: callers cannot ask for
    /// a signature over arbitrary bytes.
    pub fn sign_personal_message(&self, message: &[u8]) -> Result<SignatureParts, EvmError> {
        let digest = personal_message_digest(message);
        self.sign_digest(&digest)
    }

    /// Sign an EIP-712 typed-data digest.
    ///
    /// The caller is responsible for computing the EIP-712 digest; this
    /// method exists so that the intent is explicit at the call site.
    pub fn sign_typed_data_digest(
        &self,
        digest: &[u8; 32],
    ) -> Result<SignatureParts, EvmError> {
        self.sign_digest(digest)
    }

    /// Constant-time comparison of the secret scalar against another
    /// 32-byte buffer.
    ///
    /// Returns `true` iff the bytes match. The comparison runs in constant
    /// time with respect to the contents of both buffers.
    pub fn secret_eq(&self, other: &[u8; 32]) -> bool {
        self.secret.as_ref().ct_eq(other).into()
    }

    /// Seal this signer's secret scalar using [`octo_crypto`] with a
    /// chain-scoped AAD context.
    ///
    /// The `chain_id` is folded into the AAD as `octo:eip155:<chain_id>`,
    /// so a sealed EVM key cannot be opened in a Stellar context (which
    /// uses a different AAD string).
    pub fn seal(&self, chain_id: u64, passphrase: &[u8]) -> Result<Vec<u8>, EvmError> {
        let context = seal_context(chain_id);
        octo_crypto::seal(&self.secret[..], passphrase, context.as_bytes())
            .map_err(|_| EvmError::SealingFailed)
    }

    /// Open a sealed secret scalar using [`octo_crypto`] with a
    /// chain-scoped AAD context, returning a signer.
    ///
    /// Opening with the wrong `chain_id` (or a Stellar context) fails.
    pub fn unseal(
        sealed: &[u8],
        chain_id: u64,
        passphrase: &[u8],
    ) -> Result<Self, EvmError> {
        let context = seal_context(chain_id);
        let plaintext = octo_crypto::open(sealed, passphrase, context.as_bytes())
            .map_err(|_| EvmError::UnsealingFailed)?;
        let plaintext = Zeroizing::new(plaintext);
        if plaintext.len() != 32 {
            return Err(EvmError::InvalidSecretKey);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&plaintext);
        Self::from_bytes(&bytes)
    }
}

impl core::fmt::Debug for EvmSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print secret material.
        f.debug_struct("EvmSigner")
            .field("address", &self.address())
            .finish_non_exhaustive()
    }
}

/// The `(r, s, v)` components of an EVM signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureParts {
    /// The `r` scalar, big-endian, 32 bytes.
    pub r: [u8; 32],
    /// The `s` scalar, big-endian, 32 bytes (low-`s` normalised).
    pub s: [u8; 32],
    /// The EIP-155 recovery id (`0` or `1`).
    pub v: u8,
}

impl SignatureParts {
    /// Build `SignatureParts` from a [`Signature`] and [`RecoveryId`].
    ///
    /// The recovery id is converted to its `u8` representation; `k256`
    /// guarantees it is `0` or `1` for secp256k1.
    pub fn from_parts(sig: Signature, recid: RecoveryId) -> Self {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig.r().to_bytes());
        s.copy_from_slice(&sig.s().to_bytes());
        Self {
            r,
            s,
            v: recid.to_byte(),
        }
    }

    /// Serialise to the 65-byte `r || s || v` representation.
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
        out[64] = self.v;
        out
    }

    /// Parse a 65-byte `r || s || v` buffer.
    ///
    /// Returns [`EvmError::InvalidSignature`] if the recovery id is not
    /// `0` or `1`, or if the `(r, s)` scalars are not a valid signature.
    pub fn from_bytes(bytes: &[u8; 65]) -> Result<Self, EvmError> {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..64]);
        let v = bytes[64];
        // Reject out-of-range recovery ids instead of panicking.
        let recid = RecoveryId::from_byte(v).ok_or(EvmError::InvalidSignature)?;
        let sig = Signature::from_scalars(r, s).map_err(|_| EvmError::InvalidSignature)?;
        let _ = recid;
        Ok(Self { r, s, v })
    }
}

/// Compute the EIP-191 personal-message digest for `message`.
pub fn personal_message_digest(message: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message);
    hasher.finalize().into()
}

/// Derive the 20-byte EVM address from a verifying key.
pub fn address_from_verifying_key(key: &VerifyingKey) -> Address {
    let point = key.to_encoded_point(false);
    let mut hasher = Keccak256::new();
    hasher.update(&point.as_bytes()[1..]);
    let hash = hasher.finalize();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Address(addr)
}

/// Recover the signer address from a 32-byte digest and 65-byte
/// `r || s || v` signature.
///
/// Returns [`EvmError::InvalidSignature`] if the recovery id is out of
/// range or the signature cannot be recovered.
pub fn recover_address(digest: &[u8; 32], sig_bytes: &[u8; 65]) -> Result<Address, EvmError> {
    let parts = SignatureParts::from_bytes(sig_bytes)?;
    let recid = RecoveryId::from_byte(parts.v).ok_or(EvmError::InvalidSignature)?;
    let sig = Signature::from_scalars(parts.r, parts.s)
        .map_err(|_| EvmError::InvalidSignature)?;
    let key = VerifyingKey::recover_from_prehash(digest, &sig, recid)
        .map_err(|_| EvmError::InvalidSignature)?;
    Ok(address_from_verifying_key(&key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_rejects_out_of_range_recovery_id() {
        let mut bytes = [0u8; 65];
        bytes[64] = 2;
        assert_eq!(SignatureParts::from_bytes(&bytes), Err(EvmError::InvalidSignature));
    }

    #[test]
    fn recover_address_rejects_out_of_range_recovery_id() {
        let digest = [0u8; 32];
        let mut sig = [0u8; 65];
        sig[64] = 27;
        assert_eq!(recover_address(&digest, &sig), Err(EvmError::InvalidSignature));
    }
}
