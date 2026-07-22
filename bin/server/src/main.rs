//! octo service entry point.
//!
//! Loads configuration from the environment (`.env` supported), connects and migrates the
//! database, then runs two things in one process:
//!   1. the REST API (axum), and
//!   2. the deposit ingest supervisor (polls Horizon for all wallets).
//!
//! These can later be split into separate processes for scale without code changes — the ingest
//! cursor makes the worker restart-safe and independently runnable.
#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use octo_api::{build_router, AppState};
use octo_ingest::Supervisor;
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use octo_webhooks::WebhookSender;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env if present (no-op in production where env is set directly).
    let _ = dotenvy::dotenv();
    init_tracing();

    let cfg = Config::from_env()?;
    tracing::info!(network = cfg.network.as_str(), bind = %cfg.bind_addr, "starting octo-server");

    // Database.
    let store = Store::connect(&cfg.database_url)
        .await
        .context("connect to database")?;
    store.migrate().await.context("run migrations")?;
    tracing::info!("database connected and migrated");

    // Shared state.
    let state = AppState::new(
        store.clone(),
        cfg.master_key,
        cfg.network,
        cfg.horizon_url.clone(),
        cfg.friendbot_url.clone(),
    )
    .with_jwt_secret(cfg.jwt_secret.clone());

    // Ingest supervisor (background task).
    let supervisor = Supervisor::new(
        store.clone(),
        cfg.horizon_url.clone(),
        WebhookSender::new(store.clone()),
        cfg.network.as_str(),
    );
    tokio::spawn(async move {
        supervisor
            .run(
                Duration::from_secs(cfg.ingest_interval_secs),
                cfg.ingest_page_limit,
            )
            .await;
    });
    tracing::info!(
        interval_secs = cfg.ingest_interval_secs,
        "deposit ingest supervisor started"
    );

    // REST API.
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr)
        .await
        .with_context(|| format!("bind {}", cfg.bind_addr))?;
    tracing::info!(addr = %cfg.bind_addr, "API listening");
    axum::serve(listener, app).await.context("serve API")?;
    Ok(())
}

fn init_tracing() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info,octo=debug".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .init();
}

/// Server configuration, read from environment variables.
struct Config {
    database_url: String,
    network: StellarNetwork,
    horizon_url: String,
    friendbot_url: Option<String>,
    master_key: [u8; 32],
    jwt_secret: Vec<u8>,
    bind_addr: String,
    ingest_interval_secs: u64,
    ingest_page_limit: u32,
}

impl Config {
    fn from_env() -> Result<Config> {
        let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;

        let network_str = std::env::var("NETWORK").unwrap_or_else(|_| "testnet".to_string());
        // Accepted values: "mainnet" | "public", "testnet" | "test", "standalone".
        let network = StellarNetwork::parse(&network_str)
            .with_context(|| format!("invalid NETWORK: {network_str}"))?;

        let horizon_url = std::env::var("HORIZON_URL")
            .unwrap_or_else(|_| "https://horizon-testnet.stellar.org".to_string());
        let friendbot_url = std::env::var("FRIENDBOT_URL").ok();

        let master_key_b64 = std::env::var("MASTER_KEY").context("MASTER_KEY is required")?;
        let master_key = AppState::decode_master_key(&master_key_b64)
            .map_err(|_| anyhow::anyhow!("MASTER_KEY must be base64-encoded 32 bytes"))?;

        let jwt_secret = std::env::var("JWT_SECRET")
            .context("JWT_SECRET is required (used to sign dashboard auth tokens)")?
            .into_bytes();
        if jwt_secret.len() < 16 {
            anyhow::bail!("JWT_SECRET must be at least 16 bytes");
        }

        let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

        let ingest_interval_secs = std::env::var("INGEST_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);
        let ingest_page_limit = std::env::var("INGEST_PAGE_LIMIT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(50);

        Ok(Config {
            database_url,
            network,
            horizon_url,
            friendbot_url,
            master_key,
            jwt_secret,
            bind_addr,
            ingest_interval_secs,
            ingest_page_limit,
        })
    }
}
