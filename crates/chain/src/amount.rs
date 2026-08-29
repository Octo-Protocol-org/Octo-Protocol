//! [`Amount`] — an arbitrary-precision, non-negative integer count of on-chain base units.
//!
//! # Why not `i64`, `u64`, or `rust_decimal`?
//!
//! Stellar stroops fit comfortably in an `i64` (7 decimal places, and the entire XLM supply is
//! nowhere near `i64::MAX`). EVM chains break both of the assumptions that fact encodes:
//!
//! - ETH and most ERC-20s use **18** decimal places, not 7. `1 ETH = 10^18` base units, and
//!   `i64::MAX ≈ 9.22 × 10^18` — a balance of ~9.3 ETH already overflows a signed 64-bit integer.
//! - ERC-20 balances are `uint256`, with a range up to `2^256 - 1 ≈ 1.16 × 10^77`. That is far
//!   beyond even `u128`.
//! - `rust_decimal` was considered and rejected: its backing integer is 96 bits, which still
//!   cannot represent the full `uint256` range.
//!
//! `Amount` wraps [`primitive_types::U256`] instead.
//!
//! # Why `primitive-types` and not `alloy-primitives` or `ruint`?
//!
//! All three could represent a `U256`. The deciding factors here:
//!
//! - **MSRV.** The workspace pins `rust-version = "1.84"` (see the root `Cargo.toml`).
//!   `primitive-types` has tracked a low MSRV for years (it's the `U256` used by `parity`/
//!   `substrate`-lineage code) and has no history of MSRV churn that would fight that pin.
//! - **No premature coupling to an EVM RPC stack.** `alloy-primitives` is the type `alloy` (the
//!   EVM RPC client ecosystem) is built on, but *which* EVM RPC client octo uses is explicitly
//!   out of scope here — that's issue #217. Pulling in `alloy-primitives` now would silently
//!   pre-decide that choice and pull its dependency tree into every crate that touches an amount,
//!   including ones (like `octo-store`) that have nothing to do with EVM RPC. `octo-chain` only
//!   needs a `U256` value type, not an RPC client's type system.
//! - **Decimal `Display`/`FromStr` out of the box.** `primitive_types::U256`'s `Display` prints
//!   decimal (via the `uint` crate's `construct_uint!` macro), matching the JSON-string,
//!   no-floats representation this type needs. `alloy_primitives::U256` defaults to *hex*
//!   `Display`, which would need extra decimal-formatting code anyway.
//!
//! `ruint` is the modern general-purpose alternative (and what `alloy-primitives` is itself built
//! on under the hood in recent versions) but pulls in more machinery than a single value type
//! needs here. If #217 standardizes on `ruint`/`alloy-primitives` for the EVM RPC path, `Amount`'s
//! *public* API (string/`BigDecimal`/`i64` conversions) does not need to change — only its private
//! backing type would, which is exactly the point of wrapping it in a newtype instead of exposing
//! `U256` directly.
//!
//! # Invariant
//!
//! An `Amount` is always a non-negative integer count of base units. There is no sign, no
//! fractional component, and no notion of decimals — decimal places belong to the token registry
//! (see issue #223), never to the amount itself. `U256` being unsigned makes "non-negative" true
//! by construction; the "integer, no fraction" half of the invariant is enforced at every
//! conversion boundary (`TryFrom<BigDecimal>`, `Deserialize`) by rejecting non-integer input
//! outright rather than rounding or truncating it.

use bigdecimal::BigDecimal;
use primitive_types::U256;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// An arbitrary-precision, non-negative integer count of base units (stroops, wei, or any other
/// chain's smallest indivisible unit). See the module docs for the full rationale.
///
/// `Amount` never exposes a lossy conversion: every conversion that can fail (out of range,
/// negative, or non-integer input) returns a [`AmountError`] instead of truncating, saturating,
/// or rounding. An unchecked `as i64` on an amount is a fund-loss bug — see the crate-level lint
/// wall — so every narrowing conversion in this module goes through a fallible path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Amount(U256);

/// Errors produced when converting into or out of an [`Amount`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AmountError {
    /// The source value was negative. Amounts are always non-negative.
    #[error("amount cannot be negative")]
    Negative,
    /// The source value does not fit in the target representation (e.g. a `U256` larger than
    /// `i64::MAX` being narrowed to `i64`, or a decimal string longer than 78 digits overflowing
    /// `U256` itself).
    #[error("amount is out of range for the target type")]
    Overflow,
    /// The source decimal value had a non-zero fractional component. `Amount` only ever
    /// represents whole base units.
    #[error("amount must be a whole number of base units, not a fractional value")]
    NonInteger,
    /// The source string was not a valid non-negative decimal integer.
    #[error("amount is not a valid non-negative decimal integer")]
    Malformed,
}

impl Amount {
    /// The zero amount.
    pub const ZERO: Amount = Amount(U256::zero());

    /// The largest value an `Amount` can represent: `2^256 - 1`.
    pub const MAX: Amount = Amount(U256::MAX);

    /// Wrap a raw base-unit count. Since `U256` is unsigned, every value is a valid `Amount` —
    /// this constructor cannot fail.
    #[must_use]
    pub const fn from_base_units(units: U256) -> Self {
        Amount(units)
    }

    /// The raw base-unit count.
    #[must_use]
    pub const fn base_units(self) -> U256 {
        self.0
    }

    /// Fallibly convert to `i64` (the Stellar stroops representation). Fails with
    /// [`AmountError::Overflow`] rather than truncating when the value exceeds `i64::MAX`.
    pub fn to_i64(self) -> Result<i64, AmountError> {
        if self.0 > U256::from(i64::MAX as u64) {
            return Err(AmountError::Overflow);
        }
        // `self.0` is now known to be <= i64::MAX (which fits in u64), so this parse cannot fail
        // in practice; a parse error here would indicate a bug in `U256`'s `Display`, not bad
        // input, so it is still routed through the fallible path rather than `unwrap`/`expect`.
        self.0
            .to_string()
            .parse::<i64>()
            .map_err(|_| AmountError::Overflow)
    }

    /// Fallibly convert to `u64`.
    pub fn to_u64(self) -> Result<u64, AmountError> {
        if self.0 > U256::from(u64::MAX) {
            return Err(AmountError::Overflow);
        }
        self.0
            .to_string()
            .parse::<u64>()
            .map_err(|_| AmountError::Overflow)
    }

    /// Convert to a [`BigDecimal`] with scale 0 — the representation used at the storage boundary
    /// (`NUMERIC(78,0)`). This conversion cannot fail: every `U256` value has an exact decimal
    /// representation.
    #[must_use]
    pub fn to_decimal(self) -> BigDecimal {
        // `U256::to_string()` always produces a non-negative ASCII decimal string, which is
        // always a valid `BigDecimal` literal — this cannot fail.
        BigDecimal::from_str(&self.0.to_string())
            .unwrap_or_else(|_| BigDecimal::from(0u32).with_scale(0))
    }

    /// Fallibly convert from a [`BigDecimal`]. Rejects negative values ([`AmountError::Negative`]),
    /// non-integer values ([`AmountError::NonInteger`]), and values too large for `U256`
    /// ([`AmountError::Overflow`]) instead of rounding, truncating, or wrapping.
    pub fn try_from_decimal(value: &BigDecimal) -> Result<Self, AmountError> {
        if value.sign() == bigdecimal::num_bigint::Sign::Minus {
            return Err(AmountError::Negative);
        }
        // A value is a whole number iff rescaling to 0 fractional digits doesn't change it
        // numerically (BigDecimal's `PartialEq` compares by value, independent of scale).
        if value.with_scale(0) != *value {
            return Err(AmountError::NonInteger);
        }
        let (digits, _exponent) = value.with_scale(0).into_bigint_and_exponent();
        let (_sign, bytes) = digits.to_bytes_be();
        if bytes.len() > 32 {
            return Err(AmountError::Overflow);
        }
        Ok(Amount(U256::from_big_endian(&bytes)))
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Amount {
    type Err = AmountError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // `U256::from_dec_str` accepts an empty string as zero, which is not a valid decimal
        // integer literal — reject it explicitly rather than silently treating absence as zero.
        if s.is_empty() {
            return Err(AmountError::Malformed);
        }
        // `U256::from_dec_str` rejects leading '+'/'-', non-ASCII-digit characters, and overflow
        // past 2^256-1 — exactly the "malformed or out of range, never truncated" behavior this
        // type requires.
        U256::from_dec_str(s)
            .map(Amount)
            .map_err(|_| AmountError::Malformed)
    }
}

impl TryFrom<i64> for Amount {
    type Error = AmountError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        if value < 0 {
            return Err(AmountError::Negative);
        }
        // value is now known non-negative, so this cast is lossless. `#[allow]` is scoped to this
        // single expression, not the crate, and is safe only because of the guard above.
        #[allow(clippy::cast_sign_loss)]
        let units = value as u64;
        Ok(Amount(U256::from(units)))
    }
}

impl TryFrom<u64> for Amount {
    type Error = AmountError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Ok(Amount(U256::from(value)))
    }
}

impl From<Amount> for BigDecimal {
    fn from(amount: Amount) -> Self {
        amount.to_decimal()
    }
}

impl TryFrom<BigDecimal> for Amount {
    type Error = AmountError;

    fn try_from(value: BigDecimal) -> Result<Self, Self::Error> {
        Amount::try_from_decimal(&value)
    }
}

impl Serialize for Amount {
    /// Serializes as a JSON **string** (e.g. `"1000000000000000000"`), never a bare number. A
    /// `uint256` in a JSON number silently loses precision in every JavaScript client (doubles
    /// only safely represent integers up to `2^53 - 1`, far below even `i64::MAX`), so this type
    /// never round-trips through a JSON number.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

struct AmountVisitor;

impl Visitor<'_> for AmountVisitor {
    type Value = Amount;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a non-negative decimal integer encoded as a JSON string")
    }

    // Deliberately no `visit_u64`/`visit_i64`/`visit_f64` overrides: the default `Visitor`
    // implementations for those already return a "invalid type" error, which is exactly the
    // "reject JSON numbers outright" behavior this type requires — a bare JSON number must never
    // be silently coerced into an amount.
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Amount::from_str(v).map_err(|e| E::custom(format!("invalid amount string: {e}")))
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(AmountVisitor)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn u256_strategy() -> impl Strategy<Value = U256> {
        any::<[u64; 4]>().prop_map(|limbs| {
            let mut bytes = [0u8; 32];
            for (i, limb) in limbs.iter().enumerate() {
                bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
            }
            U256::from_little_endian(&bytes)
        })
    }

    proptest! {
        /// Amount -> BigDecimal (NUMERIC(78,0) representation) -> Amount round-trips exactly for
        /// the full uint256 range.
        #[test]
        fn roundtrip_via_bigdecimal(units in u256_strategy()) {
            let amount = Amount::from_base_units(units);
            let decimal = amount.to_decimal();
            let back = Amount::try_from_decimal(&decimal).expect("valid non-negative integer");
            prop_assert_eq!(amount, back);
        }

        /// Amount -> JSON string -> Amount round-trips exactly for the full uint256 range.
        #[test]
        fn roundtrip_via_json_string(units in u256_strategy()) {
            let amount = Amount::from_base_units(units);
            let json = serde_json::to_string(&amount).unwrap();
            prop_assert!(json.starts_with('"') && json.ends_with('"'), "must serialize as a JSON string: {json}");
            let back: Amount = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(amount, back);
        }
    }

    #[test]
    fn boundary_zero() {
        let a = Amount::from_base_units(U256::zero());
        assert_eq!(a.to_i64(), Ok(0));
        assert_eq!(a.to_string(), "0");
    }

    #[test]
    fn boundary_one() {
        let a = Amount::try_from(1i64).unwrap();
        assert_eq!(a.to_i64(), Ok(1));
        assert_eq!(a.to_string(), "1");
    }

    #[test]
    fn boundary_i64_max() {
        let a = Amount::try_from(i64::MAX).unwrap();
        assert_eq!(a.to_i64(), Ok(i64::MAX));
        assert_eq!(a.to_string(), i64::MAX.to_string());
    }

    #[test]
    fn boundary_i64_max_plus_one_does_not_fit_i64() {
        // i64::MAX + 1, expressed as a u64 (doesn't fit in i64).
        let value = (i64::MAX as u64) + 1;
        let a = Amount::try_from(value).unwrap();
        assert_eq!(a.to_i64(), Err(AmountError::Overflow));
        assert_eq!(a.to_u64(), Ok(value));
    }

    #[test]
    fn boundary_u64_max() {
        let a = Amount::try_from(u64::MAX).unwrap();
        assert_eq!(a.to_u64(), Ok(u64::MAX));
        assert_eq!(a.to_i64(), Err(AmountError::Overflow));
        assert_eq!(a.to_string(), u64::MAX.to_string());
    }

    #[test]
    fn boundary_u256_max_2_pow_256_minus_1() {
        let a = Amount::MAX;
        let expected =
            "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert_eq!(a.to_string(), expected);
        assert_eq!(a.to_u64(), Err(AmountError::Overflow));
        // Round-trips through BigDecimal and JSON without loss.
        let decimal = a.to_decimal();
        assert_eq!(Amount::try_from_decimal(&decimal), Ok(a));
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, format!("\"{expected}\""));
        let back: Amount = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn negative_i64_is_rejected() {
        assert_eq!(Amount::try_from(-1i64), Err(AmountError::Negative));
    }

    #[test]
    fn negative_decimal_is_rejected() {
        let d = BigDecimal::from_str("-1").unwrap();
        assert_eq!(Amount::try_from_decimal(&d), Err(AmountError::Negative));
    }

    #[test]
    fn non_integer_decimal_is_rejected() {
        let d = BigDecimal::from_str("1.5").unwrap();
        assert_eq!(Amount::try_from_decimal(&d), Err(AmountError::NonInteger));
    }

    #[test]
    fn trailing_zero_fraction_is_accepted_as_integer() {
        // "3.00" is numerically an integer even though it has a nonzero scale.
        let d = BigDecimal::from_str("3.00").unwrap();
        assert_eq!(
            Amount::try_from_decimal(&d),
            Ok(Amount::try_from(3u64).unwrap())
        );
    }

    /// Regression: a JSON *number* must be rejected outright, never silently coerced/truncated
    /// into an amount. This is the central AD-3 requirement — a bare JSON number amount is a
    /// precision-loss bug in every JavaScript client.
    #[test]
    fn json_number_is_rejected_not_coerced() {
        let err = serde_json::from_str::<Amount>("123").unwrap_err();
        assert!(
            err.to_string().contains("string"),
            "error should mention the string requirement: {err}"
        );

        let err = serde_json::from_str::<Amount>("1.5").unwrap_err();
        assert!(err.to_string().contains("string"));
    }

    #[test]
    fn json_malformed_string_is_rejected() {
        assert!(serde_json::from_str::<Amount>("\"-1\"").is_err());
        assert!(serde_json::from_str::<Amount>("\"abc\"").is_err());
        assert!(serde_json::from_str::<Amount>("\"1.5\"").is_err());
        assert!(serde_json::from_str::<Amount>("\"\"").is_err());
    }

    /// The exact case the old i64/f64-JSON-number schema could not represent safely: 1 ETH in
    /// wei (10^18) exceeds 2^53 - 1 (JavaScript's largest safely-representable double integer),
    /// so a JSON *number* would silently lose precision in every JS client. The string encoding
    /// must survive bit-identically.
    #[test]
    fn one_eth_in_wei_survives_json_string_round_trip_bit_identically() {
        let one_eth_wei = Amount::from_base_units(U256::from(10u64).pow(U256::from(18u64)));
        assert!(U256::from(10u64).pow(U256::from(18u64)) > U256::from(2u64).pow(U256::from(53u64)));

        let json = serde_json::to_string(&one_eth_wei).unwrap();
        assert_eq!(json, "\"1000000000000000000\"");

        let back: Amount = serde_json::from_str(&json).unwrap();
        assert_eq!(back, one_eth_wei);
        assert_eq!(back.to_decimal(), one_eth_wei.to_decimal());
    }
}
