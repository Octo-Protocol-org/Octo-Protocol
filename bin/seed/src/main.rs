#![forbid(unsafe_code)]

//! # Octo Seed
//!
//! Idempotent demo-data seeder for local and staging environments.
//!
//! This binary creates a verified demo user, one or more wallets, and sample
//! deposit history so that frontend and API development can work against
//! realistic data. All writes are idempotent upserts: re-running the seeder is
//! a no-op (stable identifiers such as `stellar_tx_hash` / `horizon_op_id` are
//! used for deposits).
//!
//! ## Safety
//!
//! The seeder refuses to run against mainnet configurations. When
//! `NETWORK=mainnet` is detected the process aborts with a clear error before
//! touching the database.
//!
//! ## Usage
//!
//! ```text
//! # Uses the same config loading as the rest of the workspace.
//! NETWORK=testnet DATABASE_URL=postgres://... cargo run -p octo-seed
//! ```
//!
//! Environment variables:
//!
//! - `NETWORK` — network name; `mainnet` is refused.
//! - `DATABASE_URL` — Postgres connection string used by `octo-store`.
//!
//! Re-running the binary is safe and produces no duplicate rows.

use anyhow::{bail, Context, Result};
use tracing::{info, warn};

use octo_store::{NewDeposit, Store};

/// Demo user email used for the seeded verified account.
const DEMO_USER_EMAIL: &str = "demo@octo.local";

/// Demo user display name.
const DEMO_USER_NAME: &str = "Demo User";

/// Stable Stellar transaction hash for the first sample deposit.
const DEMO_DEPOSIT_TX_HASH_1: &str =
    "0000000000000000000000000000000000000000000000000000000000000001";

/// Stable Horizon operation id for the first sample deposit.
const DEMO_DEPOSIT_OP_ID_1: &str = "seed-demo-deposit-op-1";

/// Stable Stellar transaction hash for the second sample deposit.
const DEMO_DEPOSIT_TX_HASH_2: &str =
    "0000000000000000000000000000000000000000000000000000000000000002";

/// Stable Horizon operation id for the second sample deposit.
const DEMO_DEPOSIT_OP_ID_2: &str = "seed-demo-deposit-op-2";

/// Returns the configured network name, defaulting to `testnet`.
fn configured_network() -> String {
    std::env::var("NETWORK").unwrap_or_else(|_| "testnet".to_string())
}

/// Reuses the workspace mainnet guard logic: abort when the configured network
/// is mainnet. This is a hard refusal — the seeder must never write demo data
/// to a production database.
fn guard_against_mainnet() -> Result<()> {
    let network = configured_network();
    if network.eq_ignore_ascii_case("mainnet") {
        bail!(
            "refusing to seed demo data on NETWORK=mainnet; \
             set NETWORK to a non-mainnet value (e.g. testnet) to proceed"
        );
    }
    info!(network = %network, "network guard passed");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing; ignore if a subscriber is already installed.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    // Safe refusal on mainnet configs.
    guard_against_mainnet()?;

    // Load config / connect to the store.
    let store = Store::from_env()
        .await
        .context("failed to initialize octo-store from environment")?;

    info!("seeding demo data");

    // 1. Verified demo user (idempotent upsert by email).
    let user = store
        .upsert_verified_user(DEMO_USER_EMAIL, DEMO_USER_NAME)
        .await
        .context("failed to upsert demo user")?;
    info!(user_id = %user.id, email = DEMO_USER_EMAIL, "demo user ready");

    // 2. Wallets for the demo user (idempotent upsert).
    let wallets = store
        .upsert_demo_wallets(user.id)
        .await
        .context("failed to upsert demo wallets")?;
    if wallets.is_empty() {
        warn!("no demo wallets were created");
    } else {
        for wallet in &wallets {
            info!(wallet_id = %wallet.id, address = %wallet.address, "demo wallet ready");
        }
    }

    // 3. Sample deposit history. Stable identifiers make re-runs no-ops.
    let primary_wallet = wallets
        .first()
        .context("expected at least one demo wallet for deposit seeding")?;

    let deposits = [
        NewDeposit {
            user_id: user.id,
            wallet_id: primary_wallet.id,
            stellar_tx_hash: DEMO_DEPOSIT_TX_HASH_1.to_string(),
            horizon_op_id: DEMO_DEPOSIT_OP_ID_1.to_string(),
            amount: 100_0000000,
            asset_code: "USDC".to_string(),
        },
        NewDeposit {
            user_id: user.id,
            wallet_id: primary_wallet.id,
            stellar_tx_hash: DEMO_DEPOSIT_TX_HASH_2.to_string(),
            horizon_op_id: DEMO_DEPOSIT_OP_ID_2.to_string(),
            amount: 25_0000000,
            asset_code: "USDC".to_string(),
        },
    ];

    for deposit in deposits {
        let record = store
            .upsert_deposit(deposit)
            .await
            .context("failed to upsert demo deposit")?;
        info!(
            deposit_id = %record.id,
            tx_hash = %record.stellar_tx_hash,
            "demo deposit ready"
        );
    }

    info!("seed complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes tests that mutate the process-wide `NETWORK` env var.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn guard_refuses_mainnet() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("NETWORK", "mainnet");
        let result = guard_against_mainnet();
        std::env::remove_var("NETWORK");
        assert!(result.is_err(), "guard must refuse NETWORK=mainnet");
    }

    #[test]
    fn guard_allows_testnet() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("NETWORK", "testnet");
        let result = guard_against_mainnet();
        std::env::remove_var("NETWORK");
        assert!(result.is_ok(), "guard must allow NETWORK=testnet");
    }
}