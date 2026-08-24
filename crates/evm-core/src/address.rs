//! EVM address derivation (keccak256 of the uncompressed public key) and
//! [EIP-55](https://eips.ethereum.org/EIPS/eip-55) mixed-case checksum encode/validate.

use crate::error::EvmError;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use sha3::{Digest, Keccak256};

/// Derive the EIP-55 checksummed address for a 32-byte secp256k1 secret key.
pub fn address_from_secret(secret: &[u8; 32]) -> Result<String, EvmError> {
    let sk = SecretKey::from_slice(secret).map_err(|_| EvmError::InvalidChildKey)?;
    let uncompressed = sk.public_key().to_encoded_point(false);
    // Uncompressed SEC1 point is 0x04 || X (32) || Y (32); the address hashes X||Y only.
    let pubkey_bytes = uncompressed.as_bytes();
    debug_assert_eq!(pubkey_bytes.len(), 65);
    let hash = Keccak256::digest(&pubkey_bytes[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Ok(to_checksum(&addr))
}

/// Encode a raw 20-byte address as an EIP-55 mixed-case checksummed `0x...` string.
pub fn to_checksum(addr: &[u8; 20]) -> String {
    let hex_lower = hex::encode(addr);
    let hash = Keccak256::digest(hex_lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in hex_lower.chars().enumerate() {
        if c.is_ascii_digit() {
            out.push(c);
            continue;
        }
        // Nibble i of the hash: high nibble for even i, low nibble for odd i.
        let hash_byte = hash[i / 2];
        let nibble = if i % 2 == 0 {
            hash_byte >> 4
        } else {
            hash_byte & 0x0f
        };
        if nibble >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Parse a `0x`-prefixed 40-hex-char address into raw bytes, without checking casing.
fn parse_hex_bytes(address: &str) -> Result<[u8; 20], EvmError> {
    let hex_part = address.strip_prefix("0x").ok_or(EvmError::InvalidAddress)?;
    if hex_part.len() != 40 {
        return Err(EvmError::InvalidAddress);
    }
    let bytes = hex::decode(hex_part).map_err(|_| EvmError::InvalidAddress)?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Validate an address string per the EIP-55 rules: accepts all-lowercase, all-uppercase (of the
/// hex digits after `0x`), or a correctly-checksummed mixed case, and **rejects** an incorrect
/// mixed-case checksum. This is EIP-55's typo-detection property: a mixed-case string that isn't
/// the exact checksum encoding is far more likely a corrupted address than a stylistic choice, so
/// treating it as valid-but-different-case (as lowercasing-then-comparing would) throws away the
/// detection.
pub fn validate_address(address: &str) -> bool {
    let Some(hex_part) = address.strip_prefix("0x") else {
        return false;
    };
    if hex_part.len() != 40 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    let is_all_lower = hex_part.chars().all(|c| !c.is_ascii_uppercase());
    let is_all_upper = hex_part.chars().all(|c| !c.is_ascii_lowercase());
    if is_all_lower || is_all_upper {
        return true;
    }
    let Ok(bytes) = parse_hex_bytes(address) else {
        return false;
    };
    to_checksum(&bytes) == address
}

/// Normalize an address to its lowercase form for storage-key comparison. Case is not
/// semantically meaningful on-chain (EIP-55 casing is a checksum, not a distinct address), so
/// lookups and uniqueness must key off this form — see `docs/deposit-model.md`.
pub fn to_lower(address: &str) -> String {
    address.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Official EIP-55 test vectors (all four from the spec's "Test Cases" section).
    // https://github.com/ethereum/ercs/blob/master/ERCS/erc-55.md
    const EIP55_VECTORS: [&str; 4] = [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ];

    #[test]
    fn eip55_vectors_round_trip_and_validate() {
        for &expected in &EIP55_VECTORS {
            let bytes = parse_hex_bytes(expected).unwrap();
            assert_eq!(to_checksum(&bytes), expected);
            assert!(validate_address(expected));
        }
    }

    #[test]
    fn all_lowercase_and_all_uppercase_are_valid() {
        for &expected in &EIP55_VECTORS {
            let lower = expected.to_ascii_lowercase();
            let upper = format!("0x{}", &expected[2..].to_ascii_uppercase());
            assert!(validate_address(&lower), "{lower} should validate");
            assert!(validate_address(&upper), "{upper} should validate");
        }
    }

    #[test]
    fn wrong_mixed_case_checksum_is_rejected() {
        // Flip the case of exactly one alphabetic character in a valid checksummed address —
        // this is precisely the typo EIP-55 exists to catch.
        for &expected in &EIP55_VECTORS {
            let mut chars: Vec<char> = expected.chars().collect();
            let flip_pos = chars
                .iter()
                .position(|c| c.is_ascii_alphabetic())
                .expect("has a hex letter");
            chars[flip_pos] = if chars[flip_pos].is_ascii_uppercase() {
                chars[flip_pos].to_ascii_lowercase()
            } else {
                chars[flip_pos].to_ascii_uppercase()
            };
            let tampered: String = chars.into_iter().collect();
            assert!(
                !validate_address(&tampered),
                "{tampered} (from {expected}) must be rejected"
            );
        }
    }

    #[test]
    fn malformed_addresses_are_rejected() {
        assert!(!validate_address("not an address"));
        assert!(!validate_address("0x1234")); // too short
        assert!(!validate_address(
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAedFF" // too long
        ));
        assert!(!validate_address(
            "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed" // missing 0x
        ));
        assert!(!validate_address(
            "0xZZAeb6053F3E94C9b9A09f33669435E7Ef1BeAed" // non-hex chars
        ));
    }

    #[test]
    fn to_lower_normalizes_case_only() {
        for &expected in &EIP55_VECTORS {
            let lower = expected.to_ascii_lowercase();
            assert_eq!(to_lower(expected), lower);
            assert_eq!(to_lower(&lower), lower);
            let upper = format!("0x{}", &expected[2..].to_ascii_uppercase());
            assert_eq!(to_lower(&upper), lower);
        }
    }

    // Cross-checked against eth-account (Ethereum Foundation reference implementation): the
    // private key for m/44'/60'/0'/0/0 under mnemonic "test test test ... junk" (Hardhat's
    // well-known test mnemonic) and its address. Kept independent of derive.rs (a hardcoded key
    // here, not this crate's own derivation) so this test can't pass by mirroring the same bug.
    #[test]
    fn known_secret_derives_known_address() {
        let bytes = hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
            .unwrap();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);
        let addr = address_from_secret(&secret).unwrap();
        assert_eq!(addr, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    }
}
