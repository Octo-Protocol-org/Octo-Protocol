//! octo service entry point.
//!
// Loads config from env, connects & migrates the DB, then runs both the REST API (axum)
// and the deposit ingest supervisor (polls Horizon for all wallets) in one process.
// Can be split for scale — ingest cursor makes the worker restart-safe and rerunnable.
#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use octo_api::chain_config::{AppConfig, ChainConfig, ChainKind, RedactedUrl};
use octo_api::chain_registry::ChainRegistry;
use octo_api::{build_router, AppState};
use octo_email::EmailSender;
use octo_ingest::confirmation::EvmSupervisor;
use octo_ingest::Supervisor;
use octo_resilience::ResilienceConfig;
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use octo_webhooks::WebhookSender;
use std::sync::Arc;
use std::time::Duration;

/// How long the startup liveness probe waits per chain before treating it as unreachable.
const LIVENESS_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env if present (no-op in production where env is set directly).
    let _ = dotenvy::dotenv();
    init_tracing();

    let cfg = Config::from_env()?;

    let app_config = load_chain_config(&cfg)?;
    for chain in &app_config.chains {
        tracing::info!(
            chain_id = %chain.chain_id,
            kind = ?chain.kind,
            enabled = chain.enabled,
            rpc_url = ?chain.rpc_url, // redacted Debug impl — never the raw URL.
            "configured chain"
        );
    }

    // Database.
    let store = Store::connect(&cfg.database_url)
        .await
        .context("connect to database")?;
    store.migrate().await.context("run migrations")?;
    tracing::info!("database connected and migrated");

    // Resolve into the runtime registry, then fail fast and loudly if any enabled chain's RPC
    // doesn't answer — a bad endpoint must abort boot, not surface lazily on the first deposit.
    let registry = ChainRegistry::new(&app_config).context("build chain registry")?;
    registry
        .probe_liveness(LIVENESS_PROBE_TIMEOUT)
        .await
        .context("chain liveness probe failed at startup")?;
    tracing::info!("all enabled chains passed the startup liveness probe");
    let registry = Arc::new(registry);

    // Shared state (includes the API's Horizon client(s), wired with each chain's own
    // resilience config).
    let email = EmailSender::new(cfg.resend_api_key.clone(), cfg.email_from_address.clone());
    let mut state = AppState::from_chain_registry(
        store.clone(),
        cfg.master_key,
        registry.clone(),
        cfg.public_app_url.clone(),
        email,
    )
    .with_jwt_secret(cfg.jwt_secret.clone());
    // MASTER_KEY_NEXT, when set, activates zero-downtime key rotation: already-migrated rows
    // (by sealed_scheme) sign with this key; un-migrated rows still use `master_key`. Without
    // this call the parsed env var was read into config and then never used anywhere.
    if let Some(next) = cfg.master_key_next {
        state = state.with_master_key_next(next);
    }

    // One ingest supervisor per enabled Stellar-kind chain, each with that chain's OWN retry
    // policy and circuit breaker — a degraded RPC on one chain must never open another chain's
    // circuit. (Today there is at most one; the loop is structural so a second Stellar network,
    // or a future non-Stellar adapter, slots in without changing this shape.)
    for chain in app_config.chains.iter().filter(|c| c.enabled) {
        match chain.kind {
            ChainKind::Stellar => {
                spawn_stellar_ingest(&registry, &store, chain, cfg.ingest_page_limit)
            }
            // `ChainKind` is `#[non_exhaustive]` so this crate compiles unchanged when a future
            // kind (EVM) is added elsewhere — until an adapter exists for it, an enabled chain of
            // an unknown kind gets no ingest supervisor, loudly, rather than silently.
            other => tracing::warn!(
                chain_id = %chain.chain_id,
                kind = ?other,
                "no ingest adapter for this chain kind yet; chain is configured but will not be polled"
            ),
        }
    }

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
    /// Path to a `[[chains]]` TOML file (see [`load_chain_config`]). `None` means no file was
    /// found and the legacy flat env vars below (`network`/`horizon_url`/`friendbot_url`/
    /// `resilience`) build a single implicit Stellar chain instead.
    chain_config_path: Option<String>,
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

        // Precedence: CHAIN_CONFIG_PATH if set (the file MUST exist — a typo'd path is a startup
        // error, not a silent fallback); else `octo.chains.toml` in the working directory, if
        // present; else `None`, meaning `main` builds one implicit chain from the legacy env vars
        // read below (NETWORK/HORIZON_URL/FRIENDBOT_URL/HORIZON_*).
        let chain_config_path = match std::env::var("CHAIN_CONFIG_PATH") {
            Ok(path) => {
                if !std::path::Path::new(&path).is_file() {
                    anyhow::bail!("CHAIN_CONFIG_PATH={path} does not exist");
                }
                Some(path)
            }
            Err(_) => {
                let default_path = "octo.chains.toml";
                std::path::Path::new(default_path)
                    .is_file()
                    .then(|| default_path.to_string())
            }
        };

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
            chain_config_path,
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

/// Resolve the chain configuration: a TOML file if [`Config::chain_config_path`] names one (with
/// each chain's `rpc_url` overridable via `OCTO_CHAIN_<CHAIN_ID>_RPC_URL`), else a single implicit
/// Stellar chain built from the legacy flat env vars. Either way the result passes through
/// [`AppConfig::new`]'s validation (unique/non-empty chain ids, at least one enabled).
fn load_chain_config(cfg: &Config) -> Result<AppConfig> {
    let mut app_config = match &cfg.chain_config_path {
        Some(path) => {
            let toml_str = std::fs::read_to_string(path)
                .with_context(|| format!("read chain config file {path}"))?;
            AppConfig::from_toml_str(&toml_str)
                .with_context(|| format!("parse chain config file {path}"))?
        }
        None => {
            let chain = ChainConfig {
                chain_id: cfg.network.as_str().to_string(),
                kind: ChainKind::Stellar,
                rpc_url: RedactedUrl::new(cfg.horizon_url.clone()),
                enabled: true,
                confirmation_depth: 1,
                poll_interval: Duration::from_secs(cfg.ingest_interval_secs),
                retry: cfg.resilience.retry_policy(),
                circuit: cfg.resilience.circuit_breaker(),
                faucet_url: cfg.friendbot_url.clone(),
            };
            AppConfig::new(vec![chain]).context("build legacy single-chain config")?
        }
    };
    app_config.apply_env_overrides(|key| std::env::var(key).ok());
    Ok(app_config)
}

/// Spawn the ingest supervisor loop for one enabled Stellar-kind chain, using that chain's own
/// `retry`/`circuit` (never a shared process-global one — a degraded RPC on one chain must not
/// open another chain's breaker) and recording each successful poll into the shared registry so
/// `/health/chains` can report it.
fn spawn_stellar_ingest(
    registry: &Arc<ChainRegistry>,
    store: &Store,
    chain: &ChainConfig,
    page_limit: u32,
) {
    let Some(network) = registry.chain_stellar_network(&chain.chain_id) else {
        tracing::warn!(chain_id = %chain.chain_id, "no resolved Stellar network for chain; skipping ingest");
        return;
    };
    let supervisor = Supervisor::new_with_resilience(
        store.clone(),
        chain.rpc_url.expose_secret().to_string(),
        WebhookSender::new(store.clone()),
        network.as_str(),
        chain.retry.clone(),
        chain.circuit.clone(),
    );
    let registry = registry.clone();
    let chain_id = chain.chain_id.clone();
    let interval = chain.poll_interval;

    tokio::spawn(async move {
        loop {
            match supervisor.tick(page_limit).await {
                Ok(n) => {
                    if n > 0 {
                        tracing::debug!(chain_id = %chain_id, processed = n, "ingest poll");
                    }
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
                        .unwrap_or(0);
                    registry.record_chain_poll_success(&chain_id, now);
                }
                Err(e) => {
                    tracing::warn!(chain_id = %chain_id, error = ?e, "ingest supervisor tick failed; will retry")
                }
            }
            tokio::time::sleep(interval).await;
        }
    });
    tracing::info!(chain_id = %chain.chain_id, "deposit ingest supervisor started");
}
