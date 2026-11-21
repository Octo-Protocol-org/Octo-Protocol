//! Cross-check wallet-core address, muxed-id and signature output against
//! fixtures generated from an independent Stellar SDK implementation
//! (JS `@stellar/stellar-sdk` / Go `github.com/stellar/go`).
//!
//! The fixtures live under `tests/fixtures/stellar-sdk/` and are committed
//! alongside the generation script (`generate.sh`). Each assertion compares
//! byte-for-byte so that any drift from the reference SDK is caught loudly,
//! reporting the fixture name plus expected/actual values.
//!
//! These tests are gated behind the `test-fixtures` feature so that the
//! default test run does not depend on the committed fixture files.

#![cfg(feature = "test-fixtures")]

use serde::Deserialize;

use wallet_core::{
    deposit_address, derive_account_id, encode_muxed, sign_payment, PaymentRequest,
};

// ---------------------------------------------------------------------------
// Fixture loading
// ---------------------------------------------------------------------------

const MUXED_FIXTURES: &str = include_str!("fixtures/stellar-sdk/muxed_addresses.json");
const SEP5_FIXTURES: &str = include_str!("fixtures/stellar-sdk/sep5_accounts.json");
const ENVELOPE_FIXTURES: &str = include_str!("fixtures/stellar-sdk/signed_envelopes.json");

#[derive(Debug, Deserialize)]
struct MuxedFixture {
    /// Human-readable fixture name for failure messages.
    name: String,
    /// Base (unmuxed) account address, e.g. `G...`.
    base_account: String,
    /// Muxed id as a decimal string (u64 range).
    id: String,
    /// Expected `M...` muxed address string.
    muxed_address: String,
    /// Expected `M...` deposit address string (may equal `muxed_address`).
    deposit_address: String,
}

#[derive(Debug, Deserialize)]
struct Sep5Fixture {
    name: String,
    mnemonic: String,
    index: u32,
    account_id: String,
}

#[derive(Debug, Deserialize)]
struct EnvelopeFixture {
    name: String,
    /// Source account secret seed (`S...`).
    source_secret: String,
    destination: String,
    /// Amount as a decimal string, e.g. `"1.0000000"`.
    amount: String,
    /// Optional memo text.
    #[serde(default)]
    memo: Option<String>,
    /// Optional network passphrase; defaults to the public network.
    #[serde(default)]
    network_passphrase: Option<String>,
    /// Sequence number as a decimal string.
    sequence: String,
    /// Expected base64-encoded signed envelope XDR.
    envelope_xdr: String,
}

fn load_muxed_fixtures() -> Vec<MuxedFixture> {
    serde_json::from_str(MUXED_FIXTURES).expect("failed to parse muxed_addresses.json fixtures")
}

fn load_sep5_fixtures() -> Vec<Sep5Fixture> {
    serde_json::from_str(SEP5_FIXTURES).expect("failed to parse sep5_accounts.json fixtures")
}

fn load_envelope_fixtures() -> Vec<EnvelopeFixture> {
    serde_json::from_str(ENVELOPE_FIXTURES).expect("failed to parse signed_envelopes.json fixtures")
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

fn assert_bytes_eq(fixture: &str, field: &str, expected: &str, actual: &str) {
    if expected != actual {
        panic!(
            "fixture mismatch [{fixture}] field `{field}`:\n  expected: {expected}\n  actual:   {actual}",
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn muxed_addresses_match_sdk_fixtures() {
    let fixtures = load_muxed_fixtures();
    assert!(
        !fixtures.is_empty(),
        "muxed_addresses.json contains no fixtures"
    );

    for fixture in fixtures {
        let id: u64 = fixture
            .id
            .parse()
            .unwrap_or_else(|e| panic!("fixture [{}] has invalid id: {e}", fixture.name));

        let muxed = encode_muxed(&fixture.base_account, id).unwrap_or_else(|e| {
            panic!("fixture [{}] encode_muxed failed: {e}", fixture.name)
        });
        assert_bytes_eq(
            &fixture.name,
            "muxed_address",
            &fixture.muxed_address,
            &muxed,
        );

        let deposit = deposit_address(&fixture.base_account, id).unwrap_or_else(|e| {
            panic!("fixture [{}] deposit_address failed: {e}", fixture.name)
        });
        assert_bytes_eq(
            &fixture.name,
            "deposit_address",
            &fixture.deposit_address,
            &deposit,
        );
    }
}

#[test]
fn sep5_account_ids_match_sdk_fixtures() {
    let fixtures = load_sep5_fixtures();
    assert!(
        !fixtures.is_empty(),
        "sep5_accounts.json contains no fixtures"
    );

    for fixture in fixtures {
        let account_id = derive_account_id(&fixture.mnemonic, fixture.index).unwrap_or_else(|e| {
            panic!(
                "fixture [{}] derive_account_id(index={}) failed: {e}",
                fixture.name, fixture.index
            )
        });
        assert_bytes_eq(
            &fixture.name,
            "account_id",
            &fixture.account_id,
            &account_id,
        );
    }
}

#[test]
fn signed_envelopes_match_sdk_fixtures() {
    let fixtures = load_envelope_fixtures();
    assert!(
        !fixtures.is_empty(),
        "signed_envelopes.json contains no fixtures"
    );

    for fixture in fixtures {
        let sequence: i64 = fixture
            .sequence
            .parse()
            .unwrap_or_else(|e| panic!("fixture [{}] has invalid sequence: {e}", fixture.name));

        let request = PaymentRequest {
            source_secret: fixture.source_secret.clone(),
            destination: fixture.destination.clone(),
            amount: fixture.amount.clone(),
            memo: fixture.memo.clone(),
            network_passphrase: fixture.network_passphrase.clone(),
            sequence,
        };

        let envelope = sign_payment(&request).unwrap_or_else(|e| {
            panic!("fixture [{}] sign_payment failed: {e}", fixture.name)
        });
        assert_bytes_eq(
            &fixture.name,
            "envelope_xdr",
            &fixture.envelope_xdr,
            &envelope,
        );
    }
}