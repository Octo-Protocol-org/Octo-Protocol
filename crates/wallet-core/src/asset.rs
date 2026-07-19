//! Stellar credit-asset code validation — the single shared primitive for every call site that
//! accepts, constructs, or forwards a caller/network-supplied asset code string.
//!
//! ## Finding: this validator is deliberately length-only, not alphanumeric-only
//!
//! The XDR type names `AssetCode4`/`AssetCode12` (and stellar-core's ledger-level
//! `isAssetValid` check, used when a **new** trustline/asset is issued via `ChangeTrust`)
//! suggest an ASCII-alphanumeric character-set restriction. But this codebase never issues an
//! asset or opens a trustline — every call site here only ever *references* an asset that
//! (by assumption) already exists on-chain, by code + issuer, to build a `Payment` operation.
//! For that use, the acceptance boundary that actually matters is the one enforced by
//! `stellar_base::asset::Asset::new_credit` (via `CreditAsset::new`), the constructor this crate
//! calls to build that operation: it validates **only the byte length** of the code (1 to 12
//! UTF-8 bytes; 1-4 becomes `AlphaNum4`, 5-12 becomes `AlphaNum12`) and copies the raw bytes into
//! a zero-padded fixed-size buffer with no ASCII or alphanumeric check at all — see
//! `stellar-base-0.7.0/src/asset.rs`, `CreditAsset::new`.
//!
//! A stricter validator that also rejected non-alphanumeric bytes would therefore *disagree*
//! with `Asset::new_credit`'s real behavior — rejecting codes the library (and thus a real
//! Payment operation) would actually accept — which is exactly the trap this ticket's own
//! description warns against. Any code that doesn't match a real trustline simply fails
//! downstream (no such trustline / no matching balance) regardless of its character content, so
//! rejecting non-alphanumeric bytes here would not prevent anything the network doesn't already
//! prevent — it would only make this crate's pre-validation diverge from the library it wraps.
//! `custom_validation_never_disagrees_with_asset_new_credits_actual_acceptance` below proves this
//! equivalence with a property-test corpus, cross-validating directly against `Asset::new_credit`
//! rather than against an independent reimplementation of the spec.
//!
//! If a future product requirement wants to *additionally* reject non-alphanumeric codes as a
//! UX / defense-in-depth measure (independent of what the network would accept), that should be
//! a separate, clearly-named check layered on top of — not folded into — this function, since
//! folding it in would make this function disagree with `Asset::new_credit`.

/// Returns `true` iff `code` is an acceptable Stellar credit-asset code: 1 to 12 UTF-8 bytes.
///
/// This is the shared primitive for every site in this codebase that accepts or forwards a
/// caller-supplied asset code destined for [`stellar_base::asset::Asset::new_credit`] — it
/// exactly matches that function's real acceptance boundary (see the module doc-comment for why
/// this is length-only rather than alphanumeric-only). Never reimplement this check locally at a
/// call site.
///
/// `code.len()` is the UTF-8 **byte** length (not char count), matching how `Asset::new_credit`
/// measures it — a multi-byte character can push a short-looking code over the boundary.
pub fn is_valid_asset_code(code: &str) -> bool {
    (1..=12).contains(&code.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use stellar_base::asset::Asset;
    use stellar_base::crypto::PublicKey;

    // Any valid strkey works as the issuer for these tests — only the code's acceptance is under
    // test, not the issuer's.
    const ISSUER: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";

    fn issuer() -> PublicKey {
        PublicKey::from_account_id(ISSUER).expect("valid issuer strkey")
    }

    /// Ground truth: does `stellar_base::asset::Asset::new_credit` actually accept `code`?
    fn asset_new_credit_accepts(code: &str) -> bool {
        Asset::new_credit(code.to_string(), issuer()).is_ok()
    }

    // --- explicit boundary tests -------------------------------------------------------------

    #[test]
    fn accepts_exactly_4_characters() {
        assert!(is_valid_asset_code("USDC"));
        assert!(asset_new_credit_accepts("USDC"));
    }

    #[test]
    fn accepts_exactly_12_characters() {
        let code = "ABCDEFGHIJKL";
        assert_eq!(code.len(), 12);
        assert!(is_valid_asset_code(code));
        assert!(asset_new_credit_accepts(code));
    }

    #[test]
    fn rejects_0_characters() {
        assert!(!is_valid_asset_code(""));
        assert!(!asset_new_credit_accepts(""));
    }

    #[test]
    fn rejects_13_characters() {
        let code = "ABCDEFGHIJKLM";
        assert_eq!(code.len(), 13);
        assert!(!is_valid_asset_code(code));
        assert!(!asset_new_credit_accepts(code));
    }

    #[test]
    fn accepts_1_character_the_smallest_valid_code() {
        assert!(is_valid_asset_code("X"));
        assert!(asset_new_credit_accepts("X"));
    }

    // --- regression / edge cases the description called out explicitly ----------------------

    #[test]
    fn embedded_space_within_length_bounds_is_accepted_like_the_library() {
        // Not "alphanumeric" by the strict spec reading, but `Asset::new_credit` only checks
        // byte length, so this must be accepted to stay in sync with it (see module doc).
        let code = "AB D";
        assert_eq!(code.len(), 4);
        assert_eq!(is_valid_asset_code(code), asset_new_credit_accepts(code));
        assert!(is_valid_asset_code(code));
    }

    #[test]
    fn non_ascii_multibyte_code_is_measured_in_bytes_not_chars() {
        // 4 chars, but each is a 2-byte UTF-8 sequence => 8 bytes. Confirms both this function
        // and the library key off byte length, not char count.
        let code = "éééé";
        assert_eq!(code.chars().count(), 4);
        assert_eq!(code.len(), 8);
        assert_eq!(is_valid_asset_code(code), asset_new_credit_accepts(code));
        assert!(is_valid_asset_code(code));
    }

    #[test]
    fn embedded_null_byte_within_length_bounds_is_accepted_like_the_library() {
        let code = "A\0B";
        assert_eq!(code.len(), 3);
        assert_eq!(is_valid_asset_code(code), asset_new_credit_accepts(code));
    }

    #[test]
    fn whitespace_only_code_within_bounds_is_accepted_like_the_library() {
        // Confirms our validator does not treat trailing/internal whitespace as padding-only:
        // a literal space character is just another byte to `Asset::new_credit`.
        let code = "   ";
        assert_eq!(is_valid_asset_code(code), asset_new_credit_accepts(code));
        assert!(is_valid_asset_code(code));
    }

    // --- proptest cross-validation corpus: the central point of this ticket -----------------

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]

        /// Generates a wide, adversarial range of code strings — empty, too long, too short,
        /// non-ASCII, embedded whitespace/nulls, mixed multi-byte UTF-8 — and asserts our
        /// verdict always matches whether `Asset::new_credit` actually succeeds or fails.
        /// `chars` (rather than raw bytes) is used because `code: String` must be valid UTF-8
        /// (as every real call site's input is, via strkey/serde), and because generating by
        /// char count vs. measuring by byte length is exactly the boundary this ticket asked to
        /// cross-check.
        #[test]
        fn custom_validation_never_disagrees_with_asset_new_credits_actual_acceptance(
            chars in prop::collection::vec(any::<char>(), 0..20)
        ) {
            let code: String = chars.into_iter().collect();
            let ours = is_valid_asset_code(&code);
            let library = asset_new_credit_accepts(&code);
            prop_assert_eq!(
                ours,
                library,
                "disagreement for code={:?} (byte len {})",
                code,
                code.len()
            );
        }

        /// Same corpus, but generated directly over raw (non-UTF-8-constrained) byte-length
        /// intent by biasing toward the boundary: short ASCII strings of every length 0..=16,
        /// which is where a length-only check is most likely to be off-by-one.
        #[test]
        fn boundary_biased_ascii_lengths_never_disagree(
            len in 0usize..=16,
            byte in any::<u8>(),
        ) {
            // Printable ASCII only, so this always round-trips through String validly.
            let b = (byte % (0x7e - 0x20) + 0x20) as u8;
            let code: String = std::iter::repeat(b as char).take(len).collect();
            prop_assert_eq!(is_valid_asset_code(&code), asset_new_credit_accepts(&code));
        }
    }
}
