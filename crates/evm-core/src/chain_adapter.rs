//! `EvmAdapter`: a local stand-in for the `ChainAdapter` trait that issue #213
//! (`crates/chain`, not yet merged at the time this crate was written) will define.
//!
//! #217 requires `EvmAdapter` to implement `ChainAdapter` and pass `crates/chain`'s
//! `chain_conformance_suite`, but #217 depends on #213 and #213 had not landed. Rather than block
//! this crate's derivation/address/signing primitives (the actual security-sensitive surface) on
//! an unmerged dependency, this module defines a minimal trait of the same shape described in
//! #213's issue text and a matching conformance harness, scoped entirely to this crate.
//!
//! **When #213 merges:** delete this module, implement `octo_chain::ChainAdapter` for
//! `EvmAdapter` instead (the method bodies below should transfer close to verbatim), and run the
//! real `chain_conformance_suite` from `crates/chain` against it.

use crate::address::{to_checksum_address, validate_address};
use crate::derive::{uncompressed_public_key, EvmSeed};
use crate::error::EvmCoreError;

/// Local stand-in for `octo_chain::ChainAdapter` (see module docs).
pub trait ChainAdapter: Send + Sync {
    /// The CAIP-2 chain identifier this adapter serves, e.g. `"eip155:1"` for Ethereum mainnet.
    fn chain_id(&self) -> &str;

    /// Whether `address` is a well-formed, correctly-checksummed address for this chain.
    fn validate_address(&self, address: &str) -> bool;

    /// Reduce `address` to its canonical form (EIP-55 checksummed), the generalisation of
    /// `octo_wallet_core::to_base_account` for EVM. Accepts any validly-cased input (lower,
    /// upper, or correctly checksummed) and always returns the checksummed form.
    fn normalize_address(&self, address: &str) -> Result<String, EvmCoreError>;

    /// Derive the deposit address for `index` under `seed`, in canonical (checksummed) form.
    fn derive_deposit_address(&self, seed: &EvmSeed, index: u32) -> Result<String, EvmCoreError>;
}

/// The EVM `ChainAdapter`. One instance per configured EVM chain (mainnet, an L2, ...) —
/// `chain_id` is the only thing that varies between them; derivation and addressing are chain-
/// agnostic (BIP-44 coin type 60 and EIP-55 are shared across every EIP-155 chain).
pub struct EvmAdapter {
    chain_id: String,
}

impl EvmAdapter {
    /// Construct an adapter for the given CAIP-2 chain id (e.g. `"eip155:1"`).
    ///
    /// Does not validate the CAIP-2 syntax — that parsing belongs to #213's `ChainId` type. This
    /// stand-in stores it as an opaque label.
    pub fn new(chain_id: impl Into<String>) -> Self {
        Self {
            chain_id: chain_id.into(),
        }
    }
}

impl ChainAdapter for EvmAdapter {
    fn chain_id(&self) -> &str {
        &self.chain_id
    }

    fn validate_address(&self, address: &str) -> bool {
        validate_address(address).is_ok()
    }

    fn normalize_address(&self, address: &str) -> Result<String, EvmCoreError> {
        // validate_address already enforces the checksum for mixed-case input; re-parsing here
        // and re-encoding gives the canonical checksummed form regardless of the input's casing.
        validate_address(address)?;
        let hex_part = address
            .strip_prefix("0x")
            .ok_or(EvmCoreError::InvalidAddress)?;
        let mut bytes = [0u8; 20];
        hex::decode_to_slice(hex_part, &mut bytes).map_err(|_| EvmCoreError::InvalidAddress)?;
        Ok(to_checksum_address(&bytes))
    }

    fn derive_deposit_address(&self, seed: &EvmSeed, index: u32) -> Result<String, EvmCoreError> {
        let secret = seed.derive_secp256k1_secret(index)?;
        let public_key = uncompressed_public_key(&secret)?;
        let address = crate::address::address_from_uncompressed_public_key(&public_key);
        Ok(to_checksum_address(&address))
    }
}

/// Conformance checks every `ChainAdapter` implementation must satisfy — the local counterpart of
/// #213's `chain_conformance_suite`. Intended to be called from a `#[test]` in each adapter's own
/// test module (see the tests below for `EvmAdapter`); a real second adapter added under this
/// stand-in should be run through it the same way `EvmAdapter` is.
///
/// Test-only (`test-fixtures` feature, mirroring octo-wallet-core's pattern): it asserts
/// invariants with `unwrap`/`assert!`, which this crate's lint wall denies outside test code, and
/// it has no legitimate caller in production — only other crates' test suites use it. `unwrap` is
/// explicitly allowed here (rather than relying on `cfg(test)`'s blanket allow, which does not
/// apply when this is reached only via the `test-fixtures` feature from another crate's tests)
/// because panicking on failure is this function's entire purpose.
#[cfg(any(test, feature = "test-fixtures"))]
#[allow(clippy::unwrap_used)]
pub fn chain_conformance_suite(adapter: &impl ChainAdapter, seed: &EvmSeed) {
    assert!(!adapter.chain_id().is_empty(), "chain_id must not be empty");

    // Deriving the same index twice must be deterministic.
    let a = adapter.derive_deposit_address(seed, 0).unwrap();
    let b = adapter.derive_deposit_address(seed, 0).unwrap();
    assert_eq!(a, b, "deposit address derivation must be deterministic");

    // Distinct indices must yield distinct addresses.
    let c = adapter.derive_deposit_address(seed, 1).unwrap();
    assert_ne!(a, c, "distinct indices must yield distinct addresses");

    // A derived address must itself validate and normalize to a fixed point.
    assert!(
        adapter.validate_address(&a),
        "derived address must validate"
    );
    let normalized = adapter.normalize_address(&a).unwrap();
    assert_eq!(
        normalized, a,
        "a checksummed address must normalize to itself"
    );
    assert_eq!(
        adapter.normalize_address(&normalized).unwrap(),
        normalized,
        "normalize_address must be idempotent"
    );

    // Case variants of a valid address must normalize to the same checksummed form.
    let lower = a.to_lowercase();
    assert!(
        adapter.validate_address(&lower),
        "all-lowercase form must validate"
    );
    assert_eq!(
        adapter.normalize_address(&lower).unwrap(),
        a,
        "lowercase input must normalize to the checksummed form"
    );

    // Garbage input must be rejected, not panic.
    assert!(!adapter.validate_address("not-an-address"));
    assert!(adapter.normalize_address("not-an-address").is_err());
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTOR_MNEMONIC: &str =
        "illness spike retreat truth genius clock brain pass fit cave bargain toe";

    #[test]
    fn evm_adapter_passes_chain_conformance_suite() {
        let seed = EvmSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        let adapter = EvmAdapter::new("eip155:1");
        chain_conformance_suite(&adapter, &seed);
    }

    #[test]
    fn chain_id_is_reported_verbatim() {
        let adapter = EvmAdapter::new("eip155:11155111");
        assert_eq!(adapter.chain_id(), "eip155:11155111");
    }

    #[test]
    fn derive_deposit_address_matches_independent_vector() {
        // Same mnemonic + index-0 vector as crate::derive's cross-checked test.
        let seed = EvmSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        let adapter = EvmAdapter::new("eip155:1");
        let addr = adapter.derive_deposit_address(&seed, 0).unwrap();
        assert_eq!(addr, "0x6b30c7d7657A83141186Cd8c155CDB90C8750371");
    }
}
