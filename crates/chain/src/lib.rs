//! A minimal `ChainAdapter` boundary, scoped to what issue #220 (EVM deposit-address allocation)
//! needs: one trait method, `derive_deposit_address`, plus a Stellar and an EVM implementation.
//!
//! This is deliberately **not** the full abstraction described for the chain-abstraction epic
//! (capabilities queries, a `ChainRegistry`, CAIP-2 chain identity, `validate_address`,
//! `explain_failure`, object-safety for `Arc<dyn ChainAdapter>` in shared Axum state). That is a
//! separate, larger issue. Building it in full here would mean inventing answers to questions
//! (chain enumeration, RPC wiring, capability flags for chains that don't exist yet in this repo)
//! that issue owns, not this one. What's here is real and used, not a stub: [`StellarAdapter`]
//! forwards unchanged to `octo_wallet_core`, and [`EvmAdapter`] wraps the derivation this issue
//! adds in `octo-evm-core`.
#![forbid(unsafe_code)]

use octo_crypto::{SealedSeed, MASTER_KEY_LEN};

/// Errors from a `ChainAdapter` operation.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// The sealed seed could not be opened (wrong key/context, or tampered).
    #[error("seed decryption failed")]
    SeedDecryption,
    /// The requested derivation index/id was invalid or out of range for this chain.
    #[error("invalid derivation index")]
    InvalidIndex,
    /// Deriving the address failed for a chain-specific reason.
    #[error("address derivation failed")]
    DerivationFailed,
}

impl From<octo_wallet_core::WalletError> for ChainError {
    fn from(_: octo_wallet_core::WalletError) -> Self {
        ChainError::DerivationFailed
    }
}

impl From<octo_evm_core::EvmError> for ChainError {
    fn from(e: octo_evm_core::EvmError) -> Self {
        match e {
            octo_evm_core::EvmError::SeedDecryption => ChainError::SeedDecryption,
            octo_evm_core::EvmError::InvalidDerivationIndex => ChainError::InvalidIndex,
            _ => ChainError::DerivationFailed,
        }
    }
}

/// A customer deposit address, in whichever shape its chain produces. Callers that need a
/// uniform "the string to hand the customer" can match on this; the API layer (which does need
/// chain-appropriate response shapes — see `crates/api/src/routes/addresses.rs`) matches on the
/// concrete variant so it can omit fields that don't apply (EVM has no `memo_id`).
#[derive(Debug, Clone)]
pub enum DepositAddress {
    /// Stellar: muxed `M...` primary + `G...`+memo fallback. No on-chain account created, no
    /// per-customer key — this is a pure encoding of `(base_account, id)`.
    Stellar(octo_wallet_core::DepositAddress),
    /// EVM: a real HD-derived EOA. The server holds the key material to re-derive (and, later,
    /// sweep) this address — see `docs/threat-model.md`.
    Evm(octo_evm_core::EvmDepositAddress),
}

/// The chain-specific input a `ChainAdapter` needs to derive a deposit address. Stellar derives
/// from the wallet's already-public base account (no decryption needed — muxed addresses carry
/// no secret material); EVM derives from the wallet's sealed HD seed.
pub enum DeriveInput<'a> {
    /// Stellar: the wallet's base `G...` account.
    Stellar { base_account: &'a str },
    /// EVM: the wallet's sealed seed, opened under `master_key`/`context` only for the duration
    /// of this call.
    Evm {
        master_key: &'a [u8; MASTER_KEY_LEN],
        sealed: &'a SealedSeed,
        context: &'a [u8],
    },
}

/// The minimal chain boundary this issue needs: given the chain-appropriate input and a
/// caller-assigned id/index, produce the customer's deposit address.
pub trait ChainAdapter: Send + Sync {
    /// Derive the deposit address for `id` (a muxed id for Stellar, a BIP-44 index for EVM).
    /// Implementations must be **pure and deterministic**: the same input always yields the same
    /// address, so the caller's stored `(input, id)` is sufficient for disaster recovery.
    fn derive_deposit_address(
        &self,
        input: DeriveInput<'_>,
        id: u64,
    ) -> Result<DepositAddress, ChainError>;
}

/// Forwards to `octo_wallet_core::deposit_address`, unchanged — Stellar's muxed model needs no
/// new logic, only a place in this trait.
pub struct StellarAdapter;

impl ChainAdapter for StellarAdapter {
    fn derive_deposit_address(
        &self,
        input: DeriveInput<'_>,
        id: u64,
    ) -> Result<DepositAddress, ChainError> {
        let DeriveInput::Stellar { base_account } = input else {
            return Err(ChainError::DerivationFailed);
        };
        let addr = octo_wallet_core::deposit_address(base_account, id)?;
        Ok(DepositAddress::Stellar(addr))
    }
}

/// Wraps `octo_evm_core`'s HD derivation: opens the sealed seed and derives
/// `m/44'/60'/0'/0/{id}`. `id` must fit the BIP-44 non-hardened index space (`0..=2^31-1`).
pub struct EvmAdapter;

impl ChainAdapter for EvmAdapter {
    fn derive_deposit_address(
        &self,
        input: DeriveInput<'_>,
        id: u64,
    ) -> Result<DepositAddress, ChainError> {
        let DeriveInput::Evm {
            master_key,
            sealed,
            context,
        } = input
        else {
            return Err(ChainError::DerivationFailed);
        };
        let index = u32::try_from(id).map_err(|_| ChainError::InvalidIndex)?;
        let addr = octo_evm_core::deposit_address_from_sealed(master_key, sealed, context, index)?;
        Ok(DepositAddress::Evm(addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use octo_crypto::master_key_from_slice;

    #[test]
    fn stellar_adapter_matches_direct_call() {
        let base = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";
        let via_adapter = StellarAdapter
            .derive_deposit_address(DeriveInput::Stellar { base_account: base }, 42)
            .unwrap();
        let direct = octo_wallet_core::deposit_address(base, 42).unwrap();
        let DepositAddress::Stellar(got) = via_adapter else {
            panic!("expected Stellar variant");
        };
        assert_eq!(got, direct);
    }

    #[test]
    fn evm_adapter_matches_direct_call() {
        let mk = master_key_from_slice(&[9u8; MASTER_KEY_LEN]).unwrap();
        let ctx = b"octo:eip155:11155111";
        let provisioned = octo_evm_core::provision_evm_wallet(&mk, ctx).unwrap();

        let via_adapter = EvmAdapter
            .derive_deposit_address(
                DeriveInput::Evm {
                    master_key: &mk,
                    sealed: &provisioned.sealed,
                    context: ctx,
                },
                3,
            )
            .unwrap();
        let direct =
            octo_evm_core::deposit_address_from_sealed(&mk, &provisioned.sealed, ctx, 3).unwrap();
        let DepositAddress::Evm(got) = via_adapter else {
            panic!("expected Evm variant");
        };
        assert_eq!(got, direct);
    }

    #[test]
    fn evm_adapter_rejects_index_above_u32_range() {
        let mk = master_key_from_slice(&[9u8; MASTER_KEY_LEN]).unwrap();
        let ctx = b"octo:eip155:11155111";
        let provisioned = octo_evm_core::provision_evm_wallet(&mk, ctx).unwrap();

        let result = EvmAdapter.derive_deposit_address(
            DeriveInput::Evm {
                master_key: &mk,
                sealed: &provisioned.sealed,
                context: ctx,
            },
            u64::from(u32::MAX) + 1,
        );
        assert!(matches!(result, Err(ChainError::InvalidIndex)));
    }
}
