//! Ethereum addresses: keccak-256 derivation from a public key, and EIP-55 mixed-case checksum
//! encoding / validation.
//!
//! An EVM address is the last 20 bytes of `keccak256(uncompressed_public_key[1..])` (the
//! uncompressed public key with its leading `0x04` prefix stripped). EIP-55 layers a mixed-case
//! checksum onto the hex encoding so a single-character typo is very likely to produce an address
//! that fails validation instead of silently routing funds elsewhere.

use crate::error::EvmCoreError;
use sha3::{Digest, Keccak256};

/// Derive the 20-byte EVM address from an uncompressed secp256k1 public key
/// (`0x04 || X(32) || Y(32)`, 65 bytes).
pub(crate) fn address_from_uncompressed_public_key(public_key: &[u8; 65]) -> [u8; 20] {
    debug_assert_eq!(public_key[0], 0x04, "must be an uncompressed SEC1 point");
    let hash = Keccak256::digest(&public_key[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    address
}

/// Encode `address` as an EIP-55 mixed-case checksummed string (with `0x` prefix).
///
/// Per the spec: hash the ASCII bytes of the *lowercase* hex address (not the raw 20 bytes), then
/// uppercase each hex letter whose corresponding nibble of the hash is >= 8.
pub fn to_checksum_address(address: &[u8; 20]) -> String {
    let lower_hex = hex::encode(address);
    let hash = Keccak256::digest(lower_hex.as_bytes());

    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, ch) in lower_hex.chars().enumerate() {
        if !ch.is_ascii_alphabetic() {
            out.push(ch);
            continue;
        }
        let hash_byte = hash[i / 2];
        let nibble = if i % 2 == 0 {
            hash_byte >> 4
        } else {
            hash_byte & 0x0f
        };
        if nibble >= 8 {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Parse a `0x`-prefixed 40-hex-character string into its 20 raw bytes, independent of case.
/// Does **not** check the EIP-55 checksum — see [`validate_address`] for that.
fn parse_hex_address(address: &str) -> Result<[u8; 20], EvmCoreError> {
    let hex_part = address
        .strip_prefix("0x")
        .ok_or(EvmCoreError::InvalidAddress)?;
    if hex_part.len() != 40 {
        return Err(EvmCoreError::InvalidAddress);
    }
    let mut bytes = [0u8; 20];
    hex::decode_to_slice(hex_part, &mut bytes).map_err(|_| EvmCoreError::InvalidAddress)?;
    Ok(bytes)
}

/// Validate an EVM address string.
///
/// Accepts:
/// - all-lowercase hex (`0x5aaeb6...`) — no checksum claimed, so none is checked.
/// - all-uppercase hex letters (`0x5AAEB6...`) — same.
/// - a correctly EIP-55-checksummed mixed case.
///
/// Rejects a mixed-case address whose checksum does not match — this is the typo-detection
/// property EIP-55 exists for. Lowercasing the input before comparison (as a naive validator
/// might) would silently defeat it, so the case pattern is inspected before any normalization.
pub fn validate_address(address: &str) -> Result<(), EvmCoreError> {
    let bytes = parse_hex_address(address)?;
    let hex_part = &address[2..];

    let is_all_lower = hex_part
        .chars()
        .all(|c| !c.is_ascii_alphabetic() || c.is_ascii_lowercase());
    let is_all_upper = hex_part
        .chars()
        .all(|c| !c.is_ascii_alphabetic() || c.is_ascii_uppercase());
    if is_all_lower || is_all_upper {
        return Ok(());
    }

    let checksummed = to_checksum_address(&bytes);
    if checksummed[2..] == *hex_part {
        Ok(())
    } else {
        Err(EvmCoreError::InvalidChecksum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // EIP-55 test vectors.
    // Source: https://eips.ethereum.org/EIPS/eip-55 ("Test Cases" section), fetched 2026-08-25.
    // ---------------------------------------------------------------------

    const ALL_CAPS: [&str; 2] = [
        "0x52908400098527886E0F7030069857D2E4169EE7",
        "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
    ];
    const ALL_LOWER: [&str; 2] = [
        "0xde709f2102306220921060314715629080e2fb77",
        "0x27b1fdb04752bbc536007a920d24acb045561c26",
    ];
    const NORMAL: [&str; 4] = [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ];

    #[test]
    fn eip55_all_caps_vectors_are_valid() {
        for addr in ALL_CAPS {
            assert!(validate_address(addr).is_ok(), "{addr} should validate");
        }
    }

    #[test]
    fn eip55_all_lower_vectors_are_valid() {
        for addr in ALL_LOWER {
            assert!(validate_address(addr).is_ok(), "{addr} should validate");
        }
    }

    #[test]
    fn eip55_mixed_case_vectors_round_trip_through_checksum_encoder() {
        for addr in NORMAL {
            assert!(validate_address(addr).is_ok(), "{addr} should validate");
            let bytes = parse_hex_address(addr).unwrap();
            assert_eq!(
                to_checksum_address(&bytes),
                addr,
                "to_checksum_address must reproduce the spec's own checksummed form"
            );
        }
    }

    #[test]
    fn wrong_checksum_mixed_case_is_rejected() {
        for addr in NORMAL {
            // Flip the case of every alphabetic character in the hex payload (not the "0x"
            // prefix — flipping its 'x' to 'X' would break prefix parsing before the checksum is
            // even reached) — guaranteed to break the checksum (the all-flipped form differs from
            // the correct checksum unless there are zero checksum-eligible bit positions, which
            // none of the spec's vectors are) without becoming an all-lower/all-upper string,
            // which validate_address would wave through unchecked.
            let flipped: String = "0x"
                .chars()
                .chain(addr[2..].chars().map(|c| {
                    if c.is_ascii_lowercase() {
                        c.to_ascii_uppercase()
                    } else if c.is_ascii_uppercase() {
                        c.to_ascii_lowercase()
                    } else {
                        c
                    }
                }))
                .collect();
            assert_ne!(flipped, *addr);
            assert!(
                matches!(
                    validate_address(&flipped),
                    Err(EvmCoreError::InvalidChecksum)
                ),
                "case-flipped {addr} -> {flipped} must be rejected as a bad checksum"
            );
        }
    }

    #[test]
    fn single_character_typo_in_case_is_rejected() {
        // A minimal, realistic typo: flip exactly one letter's case in a valid checksummed
        // address. This is the exact failure mode EIP-55 exists to catch.
        let addr = NORMAL[0];
        let mut chars: Vec<char> = addr.chars().collect();
        // Search from index 2 onward so the 'x' in the "0x" prefix is never a candidate —
        // flipping it would break prefix parsing before the checksum is even reached.
        let flip_at = chars
            .iter()
            .enumerate()
            .skip(2)
            .find(|(_, c)| c.is_ascii_alphabetic())
            .map(|(i, _)| i)
            .expect("address has at least one letter after the 0x prefix");
        chars[flip_at] = if chars[flip_at].is_ascii_uppercase() {
            chars[flip_at].to_ascii_lowercase()
        } else {
            chars[flip_at].to_ascii_uppercase()
        };
        let typoed: String = chars.into_iter().collect();
        assert_ne!(typoed, addr);
        assert!(matches!(
            validate_address(&typoed),
            Err(EvmCoreError::InvalidChecksum)
        ));
    }

    #[test]
    fn malformed_addresses_are_rejected_not_panicking() {
        for bad in [
            "",
            "0x",
            "not-an-address",
            "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", // missing 0x
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeA", // too short
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAedFF", // too long
            "0xZZZZb6053F3E94C9b9A09f33669435E7Ef1BeAe", // non-hex chars
        ] {
            assert!(
                matches!(validate_address(bad), Err(EvmCoreError::InvalidAddress)),
                "{bad:?} should be InvalidAddress"
            );
        }
    }

    #[test]
    fn checksum_encoding_is_deterministic() {
        let bytes = [0xABu8; 20];
        assert_eq!(to_checksum_address(&bytes), to_checksum_address(&bytes));
    }
}
