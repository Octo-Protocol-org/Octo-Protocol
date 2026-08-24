//! octo service entry point.
//!
// Loads config from env, connects & migrates the DB, then runs both the REST API (axum)
// and the deposit ingest supervisor (polls Horizon for all wallets) in one process.
// Can be split for scale — ingest cursor makes the worker restart-safe and rerunnable.
#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use octo_api::{build_router, AppState};
use octo_email::EmailSender;
use octo_ingest::confirmation::EvmSupervisor;
use octo_ingest::Supervisor;
use octo_resilience::ResilienceConfig;
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

    // Resilience config (shared between API Horizon client and ingest HorizonPayments client).
    let resilience = cfg.resilience.clone();
    tracing::info!(
        max_attempts = resilience.max_attempts,
        base_delay_ms = resilience.base_delay_ms,
        max_delay_ms = resilience.max_delay_ms,
        cb_failure_threshold = resilience.cb_failure_threshold,
        cb_reset_timeout_secs = resilience.cb_reset_timeout_secs,
        "horizon resilience config"
    );

    // Shared state (includes the API's Horizon client wired with resilience).
    let email = EmailSender::new(cfg.resend_api_key.clone(), cfg.email_from_address.clone());
    let mut state = AppState::new_with_resilience(
        store.clone(),
        cfg.master_key,
        cfg.network,
        cfg.horizon_url.clone(),
        cfg.friendbot_url.clone(),
        cfg.public_app_url.clone(),
        email,
        resilience.retry_policy(),
        resilience.circuit_breaker(),
    )
    .with_jwt_secret(cfg.jwt_secret.clone());
    // MASTER_KEY_NEXT, when set, activates zero-downtime key rotation: already-migrated rows
    // (by sealed_scheme) sign with this key; un-migrated rows still use `master_key`. Without
    // this call the parsed env var was read into config and then never used anywhere.
    if let Some(next) = cfg.master_key_next {
        state = state.with_master_key_next(next);
    }

    // Ingest supervisor (background task) — uses its own HorizonPayments client with the same
    // resilience config (separate circuit-breaker instance so ingest and API failures are counted
    // independently).
    let ingest_retry = cfg.resilience.retry_policy();
    let ingest_circuit = cfg.resilience.circuit_breaker();
    let supervisor = Supervisor::new_with_resilience(
        store.clone(),
        cfg.horizon_url.clone(),
        WebhookSender::new(store.clone()),
        cfg.network.as_str(),
        ingest_retry,
        ingest_circuit,
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

    // EVM confirmation tracker (background task) — only runs when an RPC endpoint is
    // configured. Not every deployment has EVM wallets yet, and there is no sane default RPC
    // URL to fall back to (unlike Horizon, which has a public testnet endpoint).
    if let Some(evm_rpc_url) = cfg.evm_rpc_url.clone() {
        let evm_supervisor = EvmSupervisor::new_with_resilience(
            store.clone(),
            evm_rpc_url,
            WebhookSender::new(store.clone()),
            cfg.network.as_str(),
            cfg.resilience.retry_policy(),
            cfg.resilience.circuit_breaker(),
        );
        let interval = Duration::from_secs(cfg.evm_confirmation_interval_secs);
        tokio::spawn(async move {
            evm_supervisor.run(interval).await;
        });
        tracing::info!(
            interval_secs = cfg.evm_confirmation_interval_secs,
            "evm confirmation tracker started"
        );
    } else {
        tracing::info!("EVM_RPC_URL not set; evm confirmation tracker not started");
    }

    // REST API.
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr)
        .await
        .with_context(|| format!("bind {}", cfg.bind_addr))?;
    tracing::info!(addr = %cfg.bind_addr, "API listening");
    // `into_make_service_with_connect_info` is what makes the peer address available to the
    // rate limiter's `ConnectInfo` extractor; without it every caller looks like one client.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .context("serve API")?;
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
    /// Base URL of the hosted checkout frontend (e.g. `https://app.octo.dev`), used to build the
    /// `url` field on payment-link responses. Defaults to the local frontend dev server.
    public_app_url: String,
    resend_api_key: String,
    email_from_address: String,
    master_key: [u8; 32],
    /// Optional next master key for zero-downtime rotation. Present only during the rotation
    /// window while `octo-migrate-keys` is backfilling. When set, the server uses this key as
    /// the primary signing key (for already-migrated rows) and falls back to `master_key` for
    /// rows not yet re-sealed. See `docs/key-rotation.md` for the full runbook.
    master_key_next: Option<[u8; 32]>,
    jwt_secret: Vec<u8>,
    bind_addr: String,
    ingest_interval_secs: u64,
    ingest_page_limit: u32,
    /// JSON-RPC endpoint for the EVM confirmation tracker. Optional: unset means no EVM wallets
    /// are in use yet, and the tracker simply doesn't start (see `docs/deposit-model.md`).
    evm_rpc_url: Option<String>,
    evm_confirmation_interval_secs: u64,
    /// Resilience settings for all Horizon clients (API + ingest).
    ///
    /// | Variable | Default | Description |
    /// |---|---|---|
    /// | `HORIZON_MAX_ATTEMPTS` | 3 | Retry attempts for read-only calls |
    /// | `HORIZON_BASE_DELAY_MS` | 200 | Base backoff delay (ms) |
    /// | `HORIZON_MAX_DELAY_MS` | 5000 | Max backoff delay (ms) |
    /// | `HORIZON_CB_FAILURE_THRESHOLD` | 5 | Consecutive failures before circuit opens |
    /// | `HORIZON_CB_RESET_TIMEOUT_SECS` | 30 | Seconds before circuit allows a probe |
    resilience: ResilienceConfig,
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

        let public_app_url = std::env::var("PUBLIC_APP_URL")
            .unwrap_or_else(|_| "http://localhost:3000".to_string())
            .trim_end_matches('/')
            .to_string();

        let resend_api_key =
            std::env::var("RESEND_API_KEY").context("RESEND_API_KEY is required")?;
        let email_from_address =
            std::env::var("EMAIL_FROM_ADDRESS").context("EMAIL_FROM_ADDRESS is required")?;

        let master_key_b64 = std::env::var("MASTER_KEY").context("MASTER_KEY is required")?;
        let master_key = AppState::decode_master_key(&master_key_b64)
            .map_err(|_| anyhow::anyhow!("MASTER_KEY must be base64-encoded 32 bytes"))?;

        // During key rotation, MASTER_KEY_NEXT lets the server sign with the new key (if present)
        // and fall back to the old key for unmigrated rows. Both must remain secure at all times.
        let master_key_next = std::env::var("MASTER_KEY_NEXT")
            .ok()
            .map(|b64| {
                AppState::decode_master_key(&b64)
                    .map_err(|_| anyhow::anyhow!("MASTER_KEY_NEXT must be base64-encoded 32 bytes"))
            })
            .transpose()?;

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

        let resilience = ResilienceConfig::from_env();

        let evm_rpc_url = std::env::var("EVM_RPC_URL").ok();
        let evm_confirmation_interval_secs = std::env::var("EVM_CONFIRMATION_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(15);

        Ok(Config {
            database_url,
            network,
            horizon_url,
            friendbot_url,
            public_app_url,
            resend_api_key,
            email_from_address,
            master_key,
            master_key_next,
            jwt_secret,
            bind_addr,
            ingest_interval_secs,
            ingest_page_limit,
            evm_rpc_url,
            evm_confirmation_interval_secs,
            resilience,
        })
    }
}
