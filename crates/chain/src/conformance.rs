//! A reusable [`ChainAdapter`] conformance harness.
//!
//! Every adapter — Stellar today, EVM in a future issue — must behave consistently with its own
//! declared [`ChainCapabilities`] and satisfy the same basic contracts (idempotent normalization,
//! deterministic derivation, no panics on garbage input). Rather than each adapter crate
//! reinventing those checks, it calls [`chain_conformance_suite`] with chain-specific test
//! vectors. This is deliberately not gated behind `cfg(test)` — a downstream adapter crate (e.g.
//! the future `octo-chain-evm`) needs to call it from its own tests, which only sees this crate's
//! public, non-test API.

use crate::adapter::ChainAdapter;
use crate::capabilities::ChainCapabilities;

/// Chain-specific fixtures for [`chain_conformance_suite`].
pub struct ConformanceVectors<'a> {
    /// A well-formed address on this chain, in its most common form.
    pub valid_address: &'a str,
    /// The same underlying address/account as `valid_address`, but in a different valid form
    /// (e.g. Stellar's muxed `M...` vs. plain `G...`), if the chain has more than one. `None` for
    /// chains with a single canonical address form.
    pub valid_address_alt_form: Option<&'a str>,
    /// A string that is not a valid address on this chain in any form.
    pub invalid_address: &'a str,
    /// The chain-specific base identity to derive a deposit address from (for Stellar, a `G...`
    /// master account).
    pub base_identity: &'a str,
    /// A customer id to derive a deposit address for.
    pub customer_id: u64,
    /// A failure/result code the adapter is not expected to recognise.
    pub unknown_failure_code: &'a str,
}

/// Run the shared adapter-honesty checks against `adapter` using `vectors`.
///
/// Panics (via `assert!`) on the first violation, so callers just invoke this from a
/// `#[tokio::test]` and let a failure surface as an ordinary test failure.
pub async fn chain_conformance_suite(adapter: &dyn ChainAdapter, vectors: ConformanceVectors<'_>) {
    // chain_id: must be present and its Display form must round-trip through ChainId::parse
    // (guaranteed by construction, but a smoke check catches an adapter that somehow bypassed it).
    let id = adapter.chain_id();
    assert!(!id.as_str().is_empty(), "chain_id must not be empty");
    assert_eq!(
        crate::ChainId::parse(id.as_str()).as_ref(),
        Ok(id),
        "chain_id() must itself be a valid CAIP-2 id"
    );

    // capabilities: must be a coherent, non-panicking call. native_decimals has no hard bound to
    // assert beyond "the call succeeds" — different chains legitimately vary widely (Stellar: 7,
    // ETH: 18).
    let caps: ChainCapabilities = adapter.capabilities();

    // validate_address: the valid vector must pass, the invalid vector must fail, and doing so
    // must not panic on adversarial-looking input either.
    assert!(
        adapter
            .validate_address(vectors.valid_address)
            .await
            .is_ok(),
        "valid_address vector must validate"
    );
    assert!(
        adapter
            .validate_address(vectors.invalid_address)
            .await
            .is_err(),
        "invalid_address vector must be rejected"
    );
    for garbage in ["", " ", "\0", "not valid at all!!"] {
        // Must return an error, not panic — the assertion is just that this line is reached.
        let _ = adapter.validate_address(garbage).await;
    }
    if let Some(alt) = vectors.valid_address_alt_form {
        assert!(
            adapter.validate_address(alt).await.is_ok(),
            "valid_address_alt_form vector must validate"
        );
    }

    // normalize_address: idempotent, and both forms of the same address must normalize to the
    // same canonical string.
    let normalized = adapter
        .normalize_address(vectors.valid_address)
        .await
        .expect("valid_address must normalize");
    let normalized_again = adapter
        .normalize_address(&normalized)
        .await
        .expect("an already-normalized address must still normalize");
    assert_eq!(
        normalized, normalized_again,
        "normalize_address must be idempotent"
    );
    if let Some(alt) = vectors.valid_address_alt_form {
        let alt_normalized = adapter
            .normalize_address(alt)
            .await
            .expect("valid_address_alt_form must normalize");
        assert_eq!(
            normalized, alt_normalized,
            "two forms of the same address must normalize to the same canonical form"
        );
    }
    assert!(
        adapter
            .normalize_address(vectors.invalid_address)
            .await
            .is_err(),
        "normalize_address must reject an invalid address rather than passing it through"
    );

    // derive_deposit_address: deterministic, and shaped consistently with the adapter's own
    // declared capabilities.
    let first = adapter
        .derive_deposit_address(vectors.base_identity, vectors.customer_id)
        .await
        .expect("derive_deposit_address must succeed for the given vectors");
    let second = adapter
        .derive_deposit_address(vectors.base_identity, vectors.customer_id)
        .await
        .expect("derive_deposit_address must succeed for the given vectors");
    assert_eq!(
        first, second,
        "derive_deposit_address must be deterministic for the same inputs"
    );
    assert!(
        !first.primary.is_empty(),
        "primary address must not be empty"
    );
    if caps.supports_muxed_addresses {
        assert!(
            first.fallback.is_some(),
            "a chain that supports muxed addresses must provide a base+memo fallback"
        );
    }
    if let Some(fallback) = &first.fallback {
        assert!(
            !fallback.address.is_empty(),
            "fallback address must not be empty"
        );
        assert!(!fallback.memo.is_empty(), "fallback memo must not be empty");
    }
    // Two distinct customer ids must not collide on the same primary address.
    let other = adapter
        .derive_deposit_address(vectors.base_identity, vectors.customer_id.wrapping_add(1))
        .await
        .expect("derive_deposit_address must succeed for a second customer id");
    assert_ne!(
        first.primary, other.primary,
        "distinct customer ids must not derive the same primary address"
    );

    // explain_failure: never panics, always returns something non-empty, and an unrecognised
    // code still gets an honest (non-empty) explanation rather than silently succeeding.
    let explanation = adapter.explain_failure(vectors.unknown_failure_code).await;
    assert!(
        !explanation.is_empty(),
        "explain_failure must not return an empty explanation, even for an unknown code"
    );
}
