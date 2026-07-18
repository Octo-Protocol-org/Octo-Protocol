//! Customer deposit addresses: muxed (`M...`) primary + `G...`+memo fallback.
//!
//! A muxed account is the base account's ed25519 key plus a 64-bit id. octo gives each customer a
//! unique id; funds sent to their `M...` land in the single base account and carry the id, so we
//! attribute deposits with no sweep and no per-user reserve. For senders that can't send to `M...`
//! (some exchanges), the same id is exposed as a numeric **memo** against the base `G...`.
//!
//! See `docs/deposit-model.md`.

use crate::error::WalletError;
use serde::{Deserialize, Serialize};
use stellar_strkey::ed25519::{MuxedAccount, PublicKey};

/// Both forms of a customer deposit address, derived from one base account + id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositAddress {
    /// The muxed address (`M...`) — the default form handed to customers.
    pub muxed_address: String,
    /// The base account (`G...`) — the fallback destination for `G...`+memo senders.
    pub base_address: String,
    /// The numeric id encoded in the muxed address; also the memo id for the fallback path.
    pub memo_id: u64,
}

/// Build both address forms for `base_account` (`G...`) and `id`.
///
/// `base_account` must be a valid ed25519 public-key strkey (`G...`).
pub fn deposit_address(base_account: &str, id: u64) -> Result<DepositAddress, WalletError> {
    let pk = PublicKey::from_string(base_account).map_err(|_| WalletError::InvalidAddress)?;
    let muxed = MuxedAccount { ed25519: pk.0, id };
    Ok(DepositAddress {
        // stellar-strkey's inherent to_string() returns a heapless::String; `format!` via Display
        // yields a std String.
        muxed_address: format!("{muxed}"),
        base_address: base_account.to_string(),
        memo_id: id,
    })
}

/// Encode a base account (`G...`) + id into a muxed address (`M...`).
pub fn encode_muxed(base_account: &str, id: u64) -> Result<String, WalletError> {
    let pk = PublicKey::from_string(base_account).map_err(|_| WalletError::InvalidAddress)?;
    let muxed = MuxedAccount { ed25519: pk.0, id };
    Ok(format!("{muxed}"))
}

/// The base account + id recovered from a muxed address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedMuxed {
    /// The base ed25519 public key bytes.
    pub ed25519: [u8; 32],
    /// The 64-bit id (customer id / memo id).
    pub id: u64,
}

impl DecodedMuxed {
    /// The base account as a `G...` strkey.
    pub fn base_account(&self) -> String {
        let pk = PublicKey(self.ed25519);
        format!("{pk}")
    }
}

/// Decode a muxed address (`M...`) back into its base account and id.
pub fn decode_muxed(muxed_address: &str) -> Result<DecodedMuxed, WalletError> {
    let mux = MuxedAccount::from_string(muxed_address).map_err(|_| WalletError::InvalidAddress)?;
    Ok(DecodedMuxed {
        ed25519: mux.ed25519,
        id: mux.id,
    })
}

/// Validate that a string is a well-formed base account address (`G...`).
pub fn is_valid_account(address: &str) -> bool {
    PublicKey::from_string(address).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A valid testnet/mainnet-format account (the SEP-0005 Test 1 account 0).
    const BASE: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";

    #[test]
    fn deposit_address_has_both_forms() {
        let addr = deposit_address(BASE, 42).unwrap();
        assert!(addr.muxed_address.starts_with('M'));
        assert_eq!(addr.base_address, BASE);
        assert_eq!(addr.memo_id, 42);
    }

    #[test]
    fn muxed_roundtrip() {
        let m = encode_muxed(BASE, 1234567890).unwrap();
        assert!(m.starts_with('M'));
        let decoded = decode_muxed(&m).unwrap();
        assert_eq!(decoded.id, 1234567890);
        assert_eq!(decoded.base_account(), BASE);
    }

    #[test]
    fn different_ids_differ_but_share_base() {
        let a = decode_muxed(&encode_muxed(BASE, 1).unwrap()).unwrap();
        let b = decode_muxed(&encode_muxed(BASE, 2).unwrap()).unwrap();
        assert_ne!(a.id, b.id);
        assert_eq!(a.base_account(), b.base_account());
        assert_eq!(a.base_account(), BASE);
    }

    #[test]
    fn id_zero_and_max_roundtrip() {
        for id in [0u64, u64::MAX] {
            let decoded = decode_muxed(&encode_muxed(BASE, id).unwrap()).unwrap();
            assert_eq!(decoded.id, id);
        }
    }

    #[test]
    fn rejects_invalid_base_account() {
        assert!(matches!(
            encode_muxed("not-an-address", 1),
            Err(WalletError::InvalidAddress)
        ));
        assert!(!is_valid_account("not-an-address"));
        assert!(is_valid_account(BASE));
    }

    #[test]
    fn rejects_invalid_muxed() {
        assert!(matches!(
            decode_muxed("MABADDRESS"),
            Err(WalletError::InvalidAddress)
        ));
        // A G... address is not a muxed address.
        assert!(matches!(
            decode_muxed(BASE),
            Err(WalletError::InvalidAddress)
        ));
    }

    // -----------------------------------------------------------------------
    // Strkey-level corruption tests
    //
    // A muxed strkey encodes: version_byte(1) || ed25519(32) || id_u64_be(8) || crc16(2)
    // = 43 bytes → 69 base-32 characters (no padding, per SEP-0023 §Specification).
    //
    // These tests guard the deposit-attribution path: decode_muxed is called from
    // octo-ingest on every incoming Horizon payment record, so a panic or silent
    // misparse here would crash or misattribute the ingest worker.
    //
    // All cases below are sourced from a valid muxed address built with encode_muxed
    // (BASE, 1) plus the canonical invalid-strkey corpus from SEP-0023 §Tests.
    // -----------------------------------------------------------------------

    /// A helper so the table-driven tests read cleanly: asserts the input produces
    /// `Err(WalletError::InvalidAddress)` and – critically – does NOT panic.
    fn assert_invalid_address(input: &str) {
        let result = decode_muxed(input);
        assert!(
            matches!(result, Err(WalletError::InvalidAddress)),
            "expected Err(InvalidAddress) for {:?}, got {:?}",
            input,
            result
        );
    }

    /// Flip the last base-32 character of a valid muxed address.
    ///
    /// The last symbol covers bits that include the CRC16 trailer, so any single-
    /// character change at the end corrupts the checksum and must be rejected.
    #[test]
    fn corrupted_checksum_is_rejected() {
        let valid = encode_muxed(BASE, 1).unwrap();
        assert_eq!(valid.len(), 69, "muxed address must be 69 chars");

        // Rotate the last character to something different (stay in base-32 alphabet:
        // A-Z + 2-7).
        let last = valid.chars().last().unwrap();
        let replacement = if last == 'A' { 'B' } else { 'A' };
        let corrupted = format!("{}{}", &valid[..valid.len() - 1], replacement);
        assert_ne!(corrupted, valid);

        assert_invalid_address(&corrupted);

        // SEP-0023 §Tests invalid case 10: known-bad checksum from the spec itself.
        assert_invalid_address(
            "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUO",
        );
    }

    /// A muxed strkey must be exactly 69 characters (43 decoded bytes).
    /// One character short or one character long must both be rejected.
    #[test]
    fn truncated_and_extended_muxed_are_rejected() {
        let valid = encode_muxed(BASE, 1).unwrap();
        assert_eq!(valid.len(), 69);

        // One character truncated.
        let truncated = &valid[..68];
        assert_invalid_address(truncated);

        // One character extended (append a valid base-32 character).
        let extended = format!("{}A", valid);
        assert_invalid_address(&extended);

        // SEP-0023 §Tests invalid case 6: length congruent to 6 mod 8.
        assert_invalid_address(
            "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLKA",
        );

        // SEP-0023 §Tests invalid case 7: base-32 decodes to 44 bytes instead of 43.
        assert_invalid_address(
            "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAAV75I",
        );

        // SEP-0023 §Tests invalid case 2: unused trailing bit is non-zero (off-by-one
        // in the last symbol, correct length).
        assert_invalid_address(
            "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUR",
        );
    }

    /// A `G...` public-key strkey uses a different version byte (6<<3 = 48) than the
    /// muxed version byte (12<<3 = 96).  Passing a G... address – even one that is the
    /// exact right length if it happened to decode to 43 bytes – must be rejected
    /// because the version byte marks it as a non-muxed key.
    ///
    /// We also test with the muxed-length strings from SEP-0023 that carry the wrong
    /// version byte (invalid algorithm bits).
    #[test]
    fn wrong_version_byte_is_rejected() {
        // Plain G... (35 decoded bytes, wrong version byte).
        assert_invalid_address(BASE);

        // SEP-0023 §Tests invalid case 8: M-prefix but low 3 bits of version byte == 7.
        assert_invalid_address(
            "M47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ",
        );

        // A valid G... account is 56 chars.  Decode it to bytes and re-encode – the
        // leading version byte differs, so decode_muxed must reject it.
        let other_g = "GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR";
        assert_invalid_address(other_g);
    }

    /// Non-base-32 characters (bytes outside A-Z and 2-7) must be rejected outright.
    /// We inject '0', '1', '8', '9', and the lowercase equivalents, which are all
    /// outside the RFC 4648 base-32 alphabet.
    #[test]
    fn non_base32_payload_is_rejected() {
        let valid = encode_muxed(BASE, 1).unwrap();
        assert_eq!(valid.len(), 69);

        // Characters that look like base-32 but aren't (0, 1, 8, 9 are not in A-Z/2-7).
        let invalid_chars = ['0', '1', '8', '9'];
        for ch in invalid_chars {
            // Replace a character deep in the payload (position 10, well inside the
            // ed25519 bytes, away from the version byte and the checksum tail).
            let mut chars: Vec<char> = valid.chars().collect();
            chars[10] = ch;
            let mangled: String = chars.into_iter().collect();
            assert_invalid_address(&mangled);
        }

        // Lowercase letters are also outside the base-32 alphabet.
        let lower: String = valid.to_lowercase();
        assert_invalid_address(&lower);

        // A string with a space embedded.
        let with_space = format!("{} {}", &valid[..34], &valid[34..]);
        assert_invalid_address(&with_space);

        // Completely non-base32: arbitrary printable ASCII.
        assert_invalid_address("not-a-muxed-address-at-all!!");
    }
}
