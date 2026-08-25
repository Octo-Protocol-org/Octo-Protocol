//! Per-chain configuration: `ChainConfig` / `AppConfig`, TOML parsing, env-var override, and
//! validation.
//!
//! # Precedence
//!
//! 1. A TOML file (path from `CHAIN_CONFIG_PATH`, default `octo.chains.toml` if present in the
//!    working directory) defines the chain list — one `[[chains]]` entry per chain, with
//!    `[chains.retry]` / `[chains.circuit]` sub-tables for resilience tuning.
//! 2. For each chain, the env var `OCTO_CHAIN_<CHAIN_ID>_RPC_URL` (chain id upper-cased,
//!    non-alphanumeric characters replaced with `_`) overrides that chain's `rpc_url` — this is
//!    the field most likely to carry a secret (Alchemy/Infura API keys) and most likely to differ
//!    per deploy environment, so it is the one override worth a documented env var rather than
//!    forcing secrets into a config file.
//! 3. If no TOML file is present at all, a single implicit chain is built from the legacy flat
//!    env vars (`NETWORK`, `HORIZON_URL`, `FRIENDBOT_URL`, `HORIZON_*`) so existing `.env`-only
//!    single-chain deployments keep working unmodified.
//!
//! This crate does not implement CAIP-2 parsing/validation for `chain_id` — that belongs to the
//! chain-abstraction trait crate (tracked separately). Here a chain id is just a non-empty,
//! whitespace-free, unique string.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use octo_resilience::{CircuitBreaker, RetryPolicy};
use serde::Deserialize;
use std::collections::HashSet;
use std::fmt;
use std::time::Duration;

/// A URL that is never printed in full — `Debug` shows only `scheme://host/***`, stripping path,
/// query, and userinfo, which is where provider API keys (Alchemy, Infura, ...) live. Reaching the
/// real value requires the deliberate [`RedactedUrl::expose_secret`] call, so leaking it into a
/// log line or error message takes an explicit choice rather than an accidental `{:?}`/`{}`.
#[derive(Clone, PartialEq, Eq)]
pub struct RedactedUrl(String);

impl RedactedUrl {
    pub fn new(url: impl Into<String>) -> Self {
        Self(url.into())
    }

    /// The raw URL, secrets and all. Only call this where the value is actually needed to make a
    /// network request (constructing an HTTP client) — never to log, display, or include it in an
    /// error.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    fn redacted(&self) -> String {
        match self.0.find("://") {
            Some(scheme_end) => {
                let scheme = &self.0[..scheme_end];
                let rest = &self.0[scheme_end + 3..];
                let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
                let host_part = &rest[..host_end];
                // Strip userinfo (user:pass@host) if present — also potentially a secret.
                let host_only = host_part.rsplit('@').next().unwrap_or(host_part);
                format!("{scheme}://{host_only}/***")
            }
            None => "***".to_string(),
        }
    }
}

impl fmt::Debug for RedactedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RedactedUrl({:?})", self.redacted())
    }
}

impl fmt::Display for RedactedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.redacted())
    }
}

/// Which chain implementation a [`ChainConfig`] entry describes. Only `Stellar` is a real, working
/// adapter today — this codebase has no EVM RPC client yet. `#[non_exhaustive]` so adding `Evm`
/// later is not a breaking change for this crate's dependents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ChainKind {
    Stellar,
}

impl Default for ChainKind {
    fn default() -> Self {
        Self::Stellar
    }
}

/// Resolved, validated configuration for one chain.
#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub chain_id: String,
    pub kind: ChainKind,
    pub rpc_url: RedactedUrl,
    pub enabled: bool,
    pub confirmation_depth: u32,
    pub poll_interval: Duration,
    pub retry: RetryPolicy,
    pub circuit: CircuitBreaker,
    /// Stellar-only: testnet friendbot endpoint. `None` for mainnet chains and non-Stellar kinds.
    pub faucet_url: Option<String>,
}

/// The full set of configured chains.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub chains: Vec<ChainConfig>,
}

#[derive(Debug, thiserror::Error)]
pub enum ChainConfigError {
    #[error("failed to parse chain config TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("chain id must not be empty or whitespace-only")]
    EmptyChainId,
    #[error("chain id {0:?} must not contain whitespace")]
    WhitespaceInChainId(String),
    #[error("duplicate chain id: {0:?}")]
    DuplicateChainId(String),
    #[error("no chains are enabled — at least one enabled chain is required")]
    NoEnabledChains,
    #[error("chain {chain_id:?}: {reason}")]
    Invalid { chain_id: String, reason: String },
}

impl AppConfig {
    /// Build and validate from an already-resolved chain list (used by both the TOML path and the
    /// legacy single-chain env fallback).
    pub fn new(chains: Vec<ChainConfig>) -> Result<Self, ChainConfigError> {
        validate(&chains)?;
        Ok(Self { chains })
    }

    /// Parse a TOML document into an `AppConfig`. Pure parsing + validation — no env vars, no I/O
    /// — so it's easy to unit test.
    pub fn from_toml_str(toml_str: &str) -> Result<Self, ChainConfigError> {
        let doc: TomlDoc = toml::from_str(toml_str)?;
        let chains = doc
            .chains
            .into_iter()
            .map(ChainConfig::from)
            .collect::<Vec<_>>();
        Self::new(chains)
    }

    /// Apply per-chain RPC URL overrides from environment variables named
    /// `OCTO_CHAIN_<CHAIN_ID>_RPC_URL` (chain id upper-cased, non-alphanumeric chars replaced with
    /// `_`). `lookup` is injectable so tests don't have to mutate real process env vars.
    pub fn apply_env_overrides(&mut self, lookup: impl Fn(&str) -> Option<String>) {
        for chain in &mut self.chains {
            let var_name = format!("OCTO_CHAIN_{}_RPC_URL", env_key(&chain.chain_id));
            if let Some(url) = lookup(&var_name) {
                chain.rpc_url = RedactedUrl::new(url);
            }
        }
    }
}

/// Upper-case a chain id and replace every non-alphanumeric byte with `_`, for building the env
/// var name that overrides that chain's RPC URL.
fn env_key(chain_id: &str) -> String {
    chain_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn validate(chains: &[ChainConfig]) -> Result<(), ChainConfigError> {
    let mut seen = HashSet::new();
    for chain in chains {
        let id = chain.chain_id.trim();
        if id.is_empty() {
            return Err(ChainConfigError::EmptyChainId);
        }
        if chain.chain_id.chars().any(char::is_whitespace) {
            return Err(ChainConfigError::WhitespaceInChainId(
                chain.chain_id.clone(),
            ));
        }
        if !seen.insert(chain.chain_id.clone()) {
            return Err(ChainConfigError::DuplicateChainId(chain.chain_id.clone()));
        }
    }
    if !chains.iter().any(|c| c.enabled) {
        return Err(ChainConfigError::NoEnabledChains);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TOML wire format — deliberately separate from the resolved `ChainConfig` so the file format can
// stay stable (defaults, optional sub-tables) independent of the runtime type's shape.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct TomlDoc {
    #[serde(default)]
    chains: Vec<ChainConfigToml>,
}

#[derive(Debug, Deserialize)]
struct ChainConfigToml {
    chain_id: String,
    #[serde(default)]
    kind: ChainKind,
    rpc_url: String,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_confirmation_depth")]
    confirmation_depth: u32,
    #[serde(default = "default_poll_interval_secs")]
    poll_interval_secs: u64,
    #[serde(default)]
    faucet_url: Option<String>,
    #[serde(default)]
    retry: RetryConfigToml,
    #[serde(default)]
    circuit: CircuitConfigToml,
}

fn default_true() -> bool {
    true
}
fn default_confirmation_depth() -> u32 {
    1
}
fn default_poll_interval_secs() -> u64 {
    5
}

impl From<ChainConfigToml> for ChainConfig {
    fn from(t: ChainConfigToml) -> Self {
        Self {
            chain_id: t.chain_id,
            kind: t.kind,
            rpc_url: RedactedUrl::new(t.rpc_url),
            enabled: t.enabled,
            confirmation_depth: t.confirmation_depth,
            poll_interval: Duration::from_secs(t.poll_interval_secs),
            retry: t.retry.into(),
            circuit: t.circuit.into(),
            faucet_url: t.faucet_url,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct RetryConfigToml {
    max_attempts: u32,
    base_delay_ms: u64,
    max_delay_ms: u64,
    multiplier: f64,
    jitter_factor: f64,
}

impl Default for RetryConfigToml {
    fn default() -> Self {
        let d = RetryPolicy::default();
        Self {
            max_attempts: d.max_attempts,
            base_delay_ms: d.base_delay_ms,
            max_delay_ms: d.max_delay_ms,
            multiplier: d.multiplier,
            jitter_factor: d.jitter_factor,
        }
    }
}

impl From<RetryConfigToml> for RetryPolicy {
    fn from(t: RetryConfigToml) -> Self {
        RetryPolicy {
            max_attempts: t.max_attempts,
            base_delay_ms: t.base_delay_ms,
            max_delay_ms: t.max_delay_ms,
            multiplier: t.multiplier,
            jitter_factor: t.jitter_factor,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct CircuitConfigToml {
    failure_threshold: u32,
    reset_timeout_secs: u64,
}

impl Default for CircuitConfigToml {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            reset_timeout_secs: 30,
        }
    }
}

impl From<CircuitConfigToml> for CircuitBreaker {
    fn from(t: CircuitConfigToml) -> Self {
        CircuitBreaker::new(
            t.failure_threshold,
            Duration::from_secs(t.reset_timeout_secs),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_MULTI_CHAIN: &str = r#"
        [[chains]]
        chain_id = "stellar:testnet"
        kind = "stellar"
        rpc_url = "https://horizon-testnet.stellar.org"
        enabled = true
        faucet_url = "https://friendbot.stellar.org"

        [[chains]]
        chain_id = "base:mainnet"
        kind = "stellar"
        rpc_url = "https://eth-mainnet.g.alchemy.com/v2/super-secret-key-123"
        enabled = false
    "#;

    #[test]
    fn parses_valid_multi_chain_file() {
        let cfg = AppConfig::from_toml_str(VALID_MULTI_CHAIN).expect("parses");
        assert_eq!(cfg.chains.len(), 2);
        assert_eq!(cfg.chains[0].chain_id, "stellar:testnet");
        assert!(cfg.chains[0].enabled);
        assert_eq!(cfg.chains[0].confirmation_depth, 1); // default
        assert!(!cfg.chains[1].enabled);
    }

    #[test]
    fn rejects_duplicate_chain_id() {
        let toml = r#"
            [[chains]]
            chain_id = "stellar:testnet"
            rpc_url = "https://a.example"

            [[chains]]
            chain_id = "stellar:testnet"
            rpc_url = "https://b.example"
        "#;
        let err = AppConfig::from_toml_str(toml).unwrap_err();
        assert!(matches!(err, ChainConfigError::DuplicateChainId(_)));
    }

    #[test]
    fn rejects_empty_chain_id() {
        let toml = r#"
            [[chains]]
            chain_id = "   "
            rpc_url = "https://a.example"
        "#;
        let err = AppConfig::from_toml_str(toml).unwrap_err();
        assert!(matches!(err, ChainConfigError::EmptyChainId));
    }

    #[test]
    fn rejects_no_enabled_chains() {
        let toml = r#"
            [[chains]]
            chain_id = "stellar:testnet"
            rpc_url = "https://a.example"
            enabled = false
        "#;
        let err = AppConfig::from_toml_str(toml).unwrap_err();
        assert!(matches!(err, ChainConfigError::NoEnabledChains));
    }

    #[test]
    fn env_override_takes_precedence_over_toml() {
        let mut cfg = AppConfig::from_toml_str(VALID_MULTI_CHAIN).expect("parses");
        cfg.apply_env_overrides(|key| {
            if key == "OCTO_CHAIN_STELLAR_TESTNET_RPC_URL" {
                Some("https://overridden.example".to_string())
            } else {
                None
            }
        });
        assert_eq!(
            cfg.chains[0].rpc_url.expose_secret(),
            "https://overridden.example"
        );
        // Unrelated chain is untouched.
        assert!(cfg.chains[1]
            .rpc_url
            .expose_secret()
            .contains("super-secret-key-123"));
    }

    #[test]
    fn redacted_url_never_prints_path_or_query() {
        let url = RedactedUrl::new("https://eth-mainnet.g.alchemy.com/v2/super-secret-key-123");
        let debug = format!("{url:?}");
        let display = format!("{url}");
        assert!(
            !debug.contains("super-secret-key-123"),
            "debug leaked: {debug}"
        );
        assert!(
            !display.contains("super-secret-key-123"),
            "display leaked: {display}"
        );
        assert!(debug.contains("eth-mainnet.g.alchemy.com"));
    }

    #[test]
    fn env_key_replaces_non_alphanumeric() {
        assert_eq!(env_key("stellar:testnet"), "STELLAR_TESTNET");
        assert_eq!(env_key("base-sepolia.dev"), "BASE_SEPOLIA_DEV");
    }
}
