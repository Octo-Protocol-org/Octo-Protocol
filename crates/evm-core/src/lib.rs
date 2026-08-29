//! secp256k1 BIP-44 derivation, EIP-55 addresses, and low-s normalised ECDSA signing for EVM
//! chains. This crate handles secret key material for EVM accounts — the EVM counterpart of
//! `octo-wallet-core` (which is entirely Stellar/SEP-0005/ed25519). Decrypted seeds and derived
//! keys are zeroized after use.
//!
//! Modules:
//! - [`derive`]        — BIP-32/BIP-44 secp256k1 key derivation (`m/44'/60'/0'/0/{index}`) from a
//!   BIP-39 mnemonic, and the sealed-seed AAD context helper.
//! - [`address`]        — keccak-256 address derivation and EIP-55 checksum encode/validate.
//! - [`signer`]         — sign a 32-byte digest, low-s normalised, and recover the signer address
//!   (no raw-XDR-style signing oracle — see the module docs).
//! - [`chain_adapter`]  — `EvmAdapter`, a local stand-in for #213's `ChainAdapter` trait (see its
//!   module docs for why, and what to do when #213 lands).
//!
//! # Non-hardened derivation tail — read [`derive`]'s module docs before using an xpub anywhere
//!
//! Unlike Stellar's all-hardened SEP-0005 path, BIP-44's last two levels are non-hardened. That is
//! what makes xpub-based address derivation possible, and it is also why a leaked child private
//! key plus the account-level xpub compromises every sibling key. This is not a hypothetical edge
//! case — #220 (xpub-based per-customer addresses) and #224 (the sweep engine) both depend on
//! understanding it before building on top of this crate.
//!
//! See `docs/architecture.md` for the crate-selection ADR (why k256 + sha3 + a from-scratch
//! BIP-32 implementation over alloy-primitives or coins-bip32).
#![forbid(unsafe_code)]
// Secret-handling crate: a panic could surface key material in a backtrace, and lossy/sign
// conversions on amounts or scalars are bugs. Deny them (tests may unwrap/panic freely).
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod address;
pub mod chain_adapter;
pub mod derive;
mod error;
pub mod signer;

pub use address::{to_checksum_address, validate_address};
#[cfg(any(test, feature = "test-fixtures"))]
pub use chain_adapter::chain_conformance_suite;
pub use chain_adapter::{ChainAdapter, EvmAdapter};
pub use derive::{crypto_context, EvmSeed};
pub use error::EvmCoreError;
pub use signer::{recover_address, sign_digest, EvmSignature};
