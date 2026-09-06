//! The boundary between Octo's business logic and any specific blockchain.
//!
//! `octo-api` and `octo-ingest` should depend on [`ChainAdapter`] and [`ChainId`], never on a
//! chain-specific crate or format (Stellar's XDR, muxed addresses, EVM's checksum addresses, ...)
//! directly. Stellar is the first adapter ([`stellar::StellarAdapter`]); it is a thin forwarding
//! layer over `octo-wallet-core` — this crate reimplements none of Stellar's address or signing
//! logic.
//!
//! See `docs/architecture.md` for the full adapter-vs-business-logic boundary, and
//! [`ChainAdapter`]'s own docs for what each method's caller may assume.
//!
//! Security: this crate never depends on `octo-crypto` and never touches raw key material —
//! adapters hold secrets (by delegating to a chain's own signing crate), this crate only defines
//! shapes.
#![forbid(unsafe_code)]

mod adapter;
mod capabilities;
pub mod conformance;
mod error;
mod id;
mod registry;
pub mod stellar;

pub use adapter::{ChainAdapter, DepositAddress, DepositFallback};
pub use capabilities::{ChainCapabilities, ChainKind};
pub use error::ChainError;
pub use id::ChainId;
pub use registry::ChainRegistry;
