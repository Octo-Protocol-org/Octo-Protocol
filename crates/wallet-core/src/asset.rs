//! Stellar credit-asset code validation — the single shared primitive for every call site that
//! accepts, constructs, or forwards a caller/network-supplied asset code string.
//!
//! ## Finding: this validator is deliberately length-only, not alphanumeric-only
//!
//! Accepts asset codes matching `Asset::new_credit` — 1 to 12 UTF-8 bytes, no alphanumeric restriction.
//! This mirrors actual Stellar behavior for referencing on-chain assets, not issuing new ones.
//! For stricter (e.g., alphanumeric) checks, layer such validation separately.

/// Returns `true` if `code` is a valid Stellar asset code: 1 to 12 UTF-8 bytes.
/// Matches `Asset::new_credit` acceptance; do not duplicate this logic.
/// Note: len is in bytes, so multi-byte chars may exceed limit.
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
            let b = byte % (0x7e - 0x20) + 0x20;
            let code: String = std::iter::repeat(b as char).take(len).collect();
            prop_assert_eq!(is_valid_asset_code(&code), asset_new_credit_accepts(&code));
        }
    }
}
