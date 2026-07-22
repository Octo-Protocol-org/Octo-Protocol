//! SEP-0005 (SLIP-0010 ed25519) derivation, muxed address encode/decode, and Stellar
//! transaction signing. This is the only crate that handles secret key material; decrypted
//! seeds and derived keys are zeroized after use.
//!
//! Modules:
//! - [`derive`]  — SEP-0005 key derivation from a BIP39 mnemonic (`m/44'/148'/index'`).
//! - [`address`] — muxed (`M...`) primary + `G...`+memo fallback deposit addresses.
//! - [`asset`]   — shared Stellar credit-asset code validation.
//! - [`signer`]  — open a sealed seed, build & sign a **payment** (no raw-XDR oracle), zeroize.
//!
//! See `docs/architecture.md` and `docs/threat-model.md`.
#![forbid(unsafe_code)]
// Secret-handling crate: a panic could surface key material in a backtrace, and lossy/sign
// conversions on amounts are bugs. Deny them (tests may unwrap/panic freely).
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod address;
pub mod amount;
pub mod asset;
pub mod derive;
mod error;
pub mod provision;
pub mod signer;

pub use address::{
    decode_muxed, deposit_address, encode_muxed, is_valid_account, DecodedMuxed, DepositAddress,
};
pub use amount::to_stroops;
pub use asset::is_valid_asset_code;
pub use derive::WalletSeed;
pub use error::WalletError;
pub use provision::{import_wallet, provision_wallet, ProvisionedWallet};
pub use signer::{
    account_id_from_sealed, compute_inner_tx_hash, inner_operation_count, sign_fee_bump,
    sign_payment, FeeBumpRequest, PaymentRequest, SignedPayment, StellarNetwork,
};
