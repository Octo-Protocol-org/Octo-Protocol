//! Minimal hand-rolled ABI encoding — just enough to construct and call the one contract this
//! harness deploys (`MockERC20`). Not a general ABI codec.

use sha3::{Digest, Keccak256};

const WORD: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(pub [u8; 20]);

impl Address {
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.trim_start_matches("0x");
        let bytes = hex::decode(s).ok()?;
        let arr: [u8; 20] = bytes.try_into().ok()?;
        Some(Address(arr))
    }

    pub fn to_hex(self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

/// The first 4 bytes of `keccak256(signature)` — the standard Solidity function/constructor
/// selector (constructors don't actually use a selector on-chain, but the hash is a convenient
/// self-check that the crate's Keccak wiring matches known values; see the unit tests).
pub fn selector(signature: &str) -> [u8; 4] {
    let mut hasher = Keccak256::new();
    hasher.update(signature.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 4];
    out.copy_from_slice(&digest[..4]);
    out
}

pub fn encode_uint256(value: u128) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

pub fn encode_uint8(value: u8) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[31] = value;
    word
}

pub fn encode_address(addr: Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&addr.0);
    word
}

/// ABI-encodes a `string` as a standalone dynamic tail: a 32-byte length prefix followed by the
/// UTF-8 bytes, right-padded to a multiple of 32 bytes.
fn encode_string_tail(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let padding = (WORD - (bytes.len() % WORD)) % WORD;
    let mut out = Vec::with_capacity(WORD + bytes.len() + padding);
    out.extend_from_slice(&encode_uint256(bytes.len() as u128));
    out.extend_from_slice(bytes);
    out.extend(std::iter::repeat_n(0u8, padding));
    out
}

/// Encodes `constructor(string name, string symbol, uint8 decimals, uint256 initialSupply)`
/// arguments per the standard ABI head/tail layout for two dynamic + two static parameters.
pub fn encode_constructor_args(
    name: &str,
    symbol: &str,
    decimals: u8,
    initial_supply: u128,
) -> Vec<u8> {
    let head_len = 4 * WORD;
    let name_tail = encode_string_tail(name);
    let symbol_offset = head_len + name_tail.len();

    let mut out = Vec::new();
    out.extend_from_slice(&encode_uint256(head_len as u128));
    out.extend_from_slice(&encode_uint256(symbol_offset as u128));
    out.extend_from_slice(&encode_uint8(decimals));
    out.extend_from_slice(&encode_uint256(initial_supply));
    out.extend_from_slice(&name_tail);
    out.extend_from_slice(&encode_string_tail(symbol));
    out
}

/// Encodes a call to a two-argument `(address, uint256)` function — covers `mint` and `transfer`.
pub fn encode_address_uint256_call(signature: &str, addr: Address, amount: u128) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 2 * WORD);
    out.extend_from_slice(&selector(signature));
    out.extend_from_slice(&encode_address(addr));
    out.extend_from_slice(&encode_uint256(amount));
    out
}

/// Encodes a call to a one-argument `(address)` function — covers `balanceOf`.
pub fn encode_address_call(signature: &str, addr: Address) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + WORD);
    out.extend_from_slice(&selector(signature));
    out.extend_from_slice(&encode_address(addr));
    out
}

/// Decodes a single right-aligned `uint256` return value, truncated to `u128` (sufficient for
/// harness fixture amounts).
pub fn decode_uint256(data: &[u8]) -> u128 {
    let word = &data[data.len().saturating_sub(WORD)..];
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&word[16..32]);
    u128::from_be_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cross-checked against `cast keccak "transfer(address,uint256)"` (Foundry) — these are also
    // the well-known standard ERC-20 selectors.
    #[test]
    fn selector_matches_known_erc20_signatures() {
        assert_eq!(
            hex::encode(selector("transfer(address,uint256)")),
            "a9059cbb"
        );
        assert_eq!(hex::encode(selector("mint(address,uint256)")), "40c10f19");
        assert_eq!(hex::encode(selector("balanceOf(address)")), "70a08231");
    }

    #[test]
    fn uint256_round_trips_through_decode() {
        let encoded = encode_uint256(123_456_789);
        assert_eq!(decode_uint256(&encoded), 123_456_789);
    }
}
