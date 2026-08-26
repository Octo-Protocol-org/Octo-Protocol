//! Chain-agnostic value types shared across octo.
//!
//! Today this is just [`Amount`] — the arbitrary-precision base-unit integer that replaces `i64`
//! stroops as the amount representation safe for both Stellar and EVM chains (see the module docs
//! on [`amount`] for the full rationale). This crate is deliberately small: it defines shapes, not
//! chain adapters. The `ChainAdapter` trait, `ChainId`/CAIP-2 parsing, and multi-chain capability
//! model described in issue #213 are a separate, not-yet-landed piece of work that this crate will
//! grow into — this PR only adds what issue #215 needs.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod amount;

pub use amount::{Amount, AmountError};
