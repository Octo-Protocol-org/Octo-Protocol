//! BIP-32/BIP-44 secp256k1 derivation and EIP-55 addresses for EVM chains — the EVM sibling of
//! [`octo_wallet_core`], which stays Stellar-only. This is the only crate that handles EVM secret
//! key material; decrypted seeds and derived keys are zeroized after use.
//!
//! ## Why EVM needs this crate at all
//!
//! Stellar customer deposit addresses cost nothing: a muxed address is the base account's public
//! key plus a 64-bit id, so allocating one is pure arithmetic (see `docs/deposit-model.md`). EVM
//! has no muxed-account equivalent — every customer needs a real, distinct, HD-derived externally
//! owned account (EOA) at `m/44'/60'/0'/0/{index}`. That means:
//!
//! - The server must hold key material capable of *deriving* (and later, spending from) every
//!   deposit address — a real departure from Stellar's non-custodial posture, narrowly permitted
//!   by AD-4. See `docs/threat-model.md`.
//! - **Non-hardened derivation is a package deal**: it's what makes `m/44'/60'/0'/0/{index}` cheap
//!   to re-derive on demand (no watch-only xpub infrastructure needed), but it also means the
//!   xpub for that branch plus any one leaked child key recovers every sibling key. See
//!   [`derive`]'s module doc for the exact mechanism.
//!
//! ## Modules
//! - [`derive`] — BIP-32 HD derivation restricted to `m/44'/60'/0'/{branch}/{index}`.
//! - [`address`] — keccak256 pubkey → address, EIP-55 checksum encode/validate.
//!
//! No signing/relay support here — that belongs to the outbound-transfer and sweep-engine issues.
//! This crate only derives.
#![forbid(unsafe_code)]
// Secret-handling crate: a panic could surface key material in a backtrace, and lossy/sign
// conversions on amounts are bugs. Deny them (tests may unwrap/panic freely).
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod address;
pub mod derive;
mod error;

pub use derive::{EvmSeed, DEPOSIT_BRANCH, IDENTITY_BRANCH, MAX_NON_HARDENED_INDEX};
pub use error::EvmError;

use octo_crypto::{seal, SealedSeed, MASTER_KEY_LEN};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// A customer deposit address on an EVM chain: the EIP-55 checksummed form (for display) plus
/// the BIP-44 index it was derived at (stored so the address is re-derivable from the seed alone
/// — see [`derive`]'s module doc on why the index, not just the address, must be persisted).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmDepositAddress {
    /// EIP-55 checksummed form, e.g. `0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed`.
    pub address: String,
    /// The BIP-44 non-hardened index this address was derived at (`0..=2^31-1`).
    pub derivation_index: u32,
}

/// Derive the deposit address for `index` on the customer-facing branch
/// (`m/44'/60'/0'/0/{index}`).
pub fn derive_deposit_address(seed: &EvmSeed, index: u32) -> Result<EvmDepositAddress, EvmError> {
    let secret = seed.derive_secret(DEPOSIT_BRANCH, index)?;
    let address = address::address_from_secret(&secret)?;
    Ok(EvmDepositAddress {
        address,
        derivation_index: index,
    })
}

/// Open a sealed seed and derive the deposit address for `index`, without ever persisting the
/// decrypted seed. Mirrors [`octo_wallet_core::signer::account_id_from_sealed`]'s
/// open-derive-drop pattern: the same stored `(sealed_ciphertext, sealed_nonce, sealed_salt,
/// derivation_index)` always reproduces the same address, which is the disaster-recovery
/// guarantee this crate exists to provide.
pub fn deposit_address_from_sealed(
    master_key: &[u8; MASTER_KEY_LEN],
    sealed: &SealedSeed,
    context: &[u8],
    index: u32,
) -> Result<EvmDepositAddress, EvmError> {
    let plaintext = octo_crypto::open(master_key, sealed, context)?;
    let seed = EvmSeed::from_bytes(plaintext.to_vec());
    derive_deposit_address(&seed, index)
}

/// The result of provisioning a new EVM HD wallet: its own identity address (derived on the
/// BIP-44 *change* branch, `m/44'/60'/0'/1/0` — never handed out as a customer deposit address),
/// the sealed seed to persist, and the one-time recovery mnemonic.
pub struct ProvisionedEvmWallet {
    /// The wallet's own address, `m/44'/60'/0'/1/0`. Used only to satisfy the `wallets` table's
    /// existing unique-identity column; it is not, and must never become, a deposit address.
    pub identity_address: String,
    /// The AES-256-GCM-sealed seed to store at rest.
    pub sealed: SealedSeed,
    /// The BIP39 mnemonic — the backup secret. Show once, never persist in plaintext.
    pub mnemonic: Zeroizing<String>,
}

/// Generate a brand-new EVM HD wallet, sealed under `context` (e.g. `b"octo:eip155:1"` — must be
/// distinct per chain so a seed sealed for one EVM chain cannot be opened under another, the same
/// AAD-binding property `octo_wallet_core::signer::StellarNetwork::crypto_context` relies on).
pub fn provision_evm_wallet(
    master_key: &[u8; MASTER_KEY_LEN],
    context: &[u8],
) -> Result<ProvisionedEvmWallet, EvmError> {
    let (mnemonic, seed) = EvmSeed::generate();
    let identity_secret = seed.derive_secret(IDENTITY_BRANCH, 0)?;
    let identity_address = address::address_from_secret(&identity_secret)?;
    let sealed = seal(master_key, seed_bytes_for_sealing(&seed), context)?;
    Ok(ProvisionedEvmWallet {
        identity_address,
        sealed,
        mnemonic,
    })
}

/// Re-provision from an existing mnemonic (recovery / import).
pub fn import_evm_wallet(
    master_key: &[u8; MASTER_KEY_LEN],
    context: &[u8],
    mnemonic: &str,
) -> Result<ProvisionedEvmWallet, EvmError> {
    let seed = EvmSeed::from_phrase(mnemonic)?;
    let identity_secret = seed.derive_secret(IDENTITY_BRANCH, 0)?;
    let identity_address = address::address_from_secret(&identity_secret)?;
    let sealed = seal(master_key, seed_bytes_for_sealing(&seed), context)?;
    Ok(ProvisionedEvmWallet {
        identity_address,
        sealed,
        mnemonic: Zeroizing::new(mnemonic.to_string()),
    })
}

/// Borrow the raw seed bytes for sealing. Kept to one call site so it's obvious the only place
/// seed bytes leave [`EvmSeed`] in plaintext is immediately into [`seal`].
fn seed_bytes_for_sealing(seed: &EvmSeed) -> &[u8] {
    seed.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use octo_crypto::master_key_from_slice;

    fn master_key() -> [u8; MASTER_KEY_LEN] {
        master_key_from_slice(&[7u8; MASTER_KEY_LEN]).unwrap()
    }

    #[test]
    fn provision_then_derive_is_deterministic_from_sealed_form() {
        let mk = master_key();
        let ctx = b"octo:eip155:11155111";
        let provisioned = provision_evm_wallet(&mk, ctx).unwrap();

        let a = deposit_address_from_sealed(&mk, &provisioned.sealed, ctx, 0).unwrap();
        let b = deposit_address_from_sealed(&mk, &provisioned.sealed, ctx, 0).unwrap();
        assert_eq!(a, b);

        // Re-importing from the recovery mnemonic must reproduce the exact same addresses —
        // this is the disaster-recovery guarantee.
        let reimported = import_evm_wallet(&mk, ctx, &provisioned.mnemonic).unwrap();
        assert_eq!(reimported.identity_address, provisioned.identity_address);
        let c = deposit_address_from_sealed(&mk, &reimported.sealed, ctx, 0).unwrap();
        assert_eq!(a, c);
    }

    #[test]
    fn identity_address_is_never_a_deposit_address() {
        let mk = master_key();
        let ctx = b"octo:eip155:11155111";
        let provisioned = provision_evm_wallet(&mk, ctx).unwrap();
        for i in 0..20u32 {
            let deposit = deposit_address_from_sealed(&mk, &provisioned.sealed, ctx, i).unwrap();
            assert_ne!(deposit.address, provisioned.identity_address);
        }
    }

    #[test]
    fn sealed_for_one_chain_context_does_not_open_under_another() {
        let mk = master_key();
        let provisioned = provision_evm_wallet(&mk, b"octo:eip155:1").unwrap();
        assert!(matches!(
            deposit_address_from_sealed(&mk, &provisioned.sealed, b"octo:eip155:11155111", 0),
            Err(EvmError::SeedDecryption)
        ));
    }

    #[test]
    fn distinct_indexes_give_distinct_addresses() {
        let mk = master_key();
        let ctx = b"octo:eip155:11155111";
        let provisioned = provision_evm_wallet(&mk, ctx).unwrap();
        let a = deposit_address_from_sealed(&mk, &provisioned.sealed, ctx, 0).unwrap();
        let b = deposit_address_from_sealed(&mk, &provisioned.sealed, ctx, 1).unwrap();
        assert_ne!(a.address, b.address);
    }
}
