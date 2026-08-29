//! CAIP-2 chain identity (`namespace:reference`), e.g. `stellar:pubnet`, `eip155:1`.
//!
//! See <https://chainagnostic.org/CAIPs/caip-2> (AD-1 in `docs/ethereum-expansion-issues.md`).
//! Octo uses this as the sole chain-identity format across the workspace, so a `ChainId` is
//! always validated on construction — nothing downstream needs to re-check the grammar.

use crate::error::ChainError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Namespace length bounds per the CAIP-2 spec regex `[-a-z0-9]{3,8}`.
const NAMESPACE_LEN: std::ops::RangeInclusive<usize> = 3..=8;
/// Reference length bounds per the CAIP-2 spec regex `[-_a-zA-Z0-9]{1,32}`.
const REFERENCE_LEN: std::ops::RangeInclusive<usize> = 1..=32;

/// A validated CAIP-2 chain identifier, e.g. `"stellar:pubnet"` or `"eip155:1"`.
///
/// Construction always validates against the CAIP-2 grammar — there is no way to build a
/// `ChainId` holding a malformed slug.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ChainId(String);

impl ChainId {
    /// Octo's Stellar public (mainnet) network.
    pub const STELLAR_PUBNET: &'static str = "stellar:pubnet";
    /// Octo's Stellar test network.
    pub const STELLAR_TESTNET: &'static str = "stellar:testnet";
    /// Octo's local Stellar standalone (quickstart) network.
    pub const STELLAR_STANDALONE: &'static str = "stellar:standalone";

    /// Parse and validate a CAIP-2 chain id string.
    ///
    /// Rejects: no `:` separator, an empty or over/under-length namespace, an over-length
    /// reference, and any character outside the CAIP-2 alphabets (namespace: lowercase ASCII
    /// letters, digits, `-`; reference: ASCII letters, digits, `-`, `_`).
    pub fn parse(s: &str) -> Result<Self, ChainError> {
        let (namespace, reference) = s
            .split_once(':')
            .ok_or_else(|| ChainError::InvalidChainId(s.to_string()))?;

        let namespace_ok = NAMESPACE_LEN.contains(&namespace.len())
            && namespace
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        let reference_ok = REFERENCE_LEN.contains(&reference.len())
            && reference
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');

        if !namespace_ok || !reference_ok {
            return Err(ChainError::InvalidChainId(s.to_string()));
        }

        Ok(ChainId(s.to_string()))
    }

    /// The full `namespace:reference` slug.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The CAIP-2 namespace (e.g. `"stellar"`, `"eip155"`).
    pub fn namespace(&self) -> &str {
        // Always present and non-empty: guaranteed by `parse`'s split_once + length check.
        self.0.split_once(':').map(|(ns, _)| ns).unwrap_or("")
    }

    /// The CAIP-2 reference (e.g. `"pubnet"`, `"1"`).
    pub fn reference(&self) -> &str {
        self.0.split_once(':').map(|(_, r)| r).unwrap_or("")
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ChainId {
    type Err = ChainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ChainId::parse(s)
    }
}

impl TryFrom<String> for ChainId {
    type Error = ChainError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        ChainId::parse(&s)
    }
}

impl TryFrom<&str> for ChainId {
    type Error = ChainError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        ChainId::parse(s)
    }
}

impl From<ChainId> for String {
    fn from(id: ChainId) -> String {
        id.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Official CAIP-2 examples: https://chainagnostic.org/CAIPs/caip-2
    #[test]
    fn accepts_caip2_spec_examples() {
        for valid in [
            "eip155:1",
            "bip122:000000000019d6689c085ae165831e93",
            "bip122:12a765e31ffd4059bada1e25190f6e98",
            "cosmos:cosmoshub-3",
            "cosmos:Binance-Chain-Tigris",
            "polkadot:b0a8d493285c2df73290dfb7e61f870f",
            "chainstd:8c3444cf8970a9e41a706fab93e7a6c4",
        ] {
            let id = ChainId::parse(valid).unwrap_or_else(|e| panic!("{valid:?} rejected: {e}"));
            assert_eq!(id.as_str(), valid);
        }
    }

    #[test]
    fn accepts_octo_stellar_ids() {
        for valid in [
            ChainId::STELLAR_PUBNET,
            ChainId::STELLAR_TESTNET,
            ChainId::STELLAR_STANDALONE,
        ] {
            assert!(ChainId::parse(valid).is_ok(), "{valid} should be valid");
        }
    }

    #[test]
    fn namespace_and_reference_split_correctly() {
        let id = ChainId::parse("eip155:8453").unwrap();
        assert_eq!(id.namespace(), "eip155");
        assert_eq!(id.reference(), "8453");
    }

    #[test]
    fn rejects_missing_separator() {
        assert!(matches!(
            ChainId::parse("nocolonatall"),
            Err(ChainError::InvalidChainId(_))
        ));
        assert!(ChainId::parse("").is_err());
    }

    #[test]
    fn rejects_empty_namespace() {
        assert!(ChainId::parse(":1").is_err());
    }

    #[test]
    fn rejects_under_length_namespace() {
        // Namespace must be at least 3 chars.
        assert!(ChainId::parse("ab:1").is_err());
    }

    #[test]
    fn rejects_over_length_namespace() {
        // Namespace must be at most 8 chars — this one is 9.
        assert!(ChainId::parse("toolongns:1").is_err());
    }

    #[test]
    fn rejects_over_length_reference() {
        // Reference must be at most 32 chars — this one is 33.
        let over = "a".repeat(33);
        assert!(ChainId::parse(&format!("eip155:{over}")).is_err());
        // Exactly 32 is still valid.
        let max = "a".repeat(32);
        assert!(ChainId::parse(&format!("eip155:{max}")).is_ok());
    }

    #[test]
    fn rejects_empty_reference() {
        assert!(ChainId::parse("eip155:").is_err());
    }

    #[test]
    fn rejects_invalid_characters() {
        // Uppercase is not in the namespace alphabet.
        assert!(ChainId::parse("EIP155:1").is_err());
        // Space is in neither alphabet.
        assert!(ChainId::parse("eip155:has space").is_err());
        // A second colon puts ':' into what would be the reference — not in its alphabet.
        assert!(ChainId::parse("eip155:1:2").is_err());
        // Underscore is not valid in the namespace alphabet (only reference allows it).
        assert!(ChainId::parse("eip_155:1").is_err());
    }

    #[test]
    fn display_and_fromstr_roundtrip() {
        let id: ChainId = "stellar:pubnet".parse().unwrap();
        assert_eq!(id.to_string(), "stellar:pubnet");
        assert_eq!(id, ChainId::parse("stellar:pubnet").unwrap());
    }

    #[test]
    fn ordering_and_hashing_are_by_slug() {
        use std::collections::HashSet;
        let a = ChainId::parse("eip155:1").unwrap();
        let b = ChainId::parse("stellar:pubnet").unwrap();
        assert!(a < b, "eip155:1 sorts before stellar:pubnet lexically");

        let mut set = HashSet::new();
        set.insert(a.clone());
        assert!(set.contains(&a));
        assert!(!set.contains(&b));
    }
}
