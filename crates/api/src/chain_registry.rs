//! Runtime registry resolved from [`crate::chain_config::AppConfig`] at startup: one entry per
//! configured chain, each with its own resilience state (so a degraded chain can never open
//! another chain's circuit breaker) and, for Stellar chains, a live [`crate::horizon::Horizon`]
//! client.
//!
//! This is deliberately a **lightweight, config-and-resilience-only** registry — it does not
//! define a chain-adapter trait or hold `dyn` adapter objects. A future trait-based registry
//! (covering address validation, deposit derivation, EVM adapters, ...) can supersede or wrap
//! this one without disturbing the config/validation/isolation work done here.

use crate::chain_config::{AppConfig, ChainConfig, ChainConfigError, ChainKind};
use crate::horizon::Horizon;
use octo_wallet_core::StellarNetwork;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct ChainEntry {
    config: ChainConfig,
    /// `Some` for Stellar-kind chains — the only kind with a real client today.
    horizon: Option<Horizon>,
    stellar_network: Option<StellarNetwork>,
    /// Mirrors `octo_ingest::LastPollTracker`'s shape (a `chain_id`-keyed timestamp map) rather
    /// than depending on the `octo-ingest` crate directly — `octo-api` has no other reason to
    /// depend on `octo-ingest` outside of tests, and pulling it in just for this one type would
    /// be a heavier coupling than the one field it's used for.
    last_poll_unix: Mutex<Option<i64>>,
}

/// A resolved set of chains, built from validated [`AppConfig`].
pub struct ChainRegistry {
    entries: HashMap<String, ChainEntry>,
    /// The chain id `AppState`'s legacy single-network accessors (`network()`, `horizon()`, ...)
    /// delegate to. The first enabled Stellar-kind chain in configuration order.
    primary_stellar_chain_id: Option<String>,
}

impl ChainRegistry {
    /// Build a registry from validated config. Does not touch the network — call
    /// [`ChainRegistry::probe_liveness`] separately before serving traffic.
    pub fn new(cfg: &AppConfig) -> Result<Self, ChainConfigError> {
        let mut entries = HashMap::with_capacity(cfg.chains.len());
        let mut primary_stellar_chain_id = None;

        for chain in &cfg.chains {
            let stellar_network = match chain.kind {
                ChainKind::Stellar => {
                    let network = resolve_stellar_network(&chain.chain_id).ok_or_else(|| {
                        ChainConfigError::Invalid {
                            chain_id: chain.chain_id.clone(),
                            reason: "stellar chain_id must be (or contain, after ':') one of \
                                     mainnet/public, testnet/test, or standalone"
                                .to_string(),
                        }
                    })?;
                    if primary_stellar_chain_id.is_none() && chain.enabled {
                        primary_stellar_chain_id = Some(chain.chain_id.clone());
                    }
                    Some(network)
                }
            };

            let horizon = match chain.kind {
                ChainKind::Stellar => Some(Horizon::with_resilience(
                    chain.rpc_url.expose_secret().to_string(),
                    chain.retry.clone(),
                    chain.circuit.clone(),
                )),
            };

            entries.insert(
                chain.chain_id.clone(),
                ChainEntry {
                    config: chain.clone(),
                    horizon,
                    stellar_network,
                    last_poll_unix: Mutex::new(None),
                },
            );
        }

        Ok(Self {
            entries,
            primary_stellar_chain_id,
        })
    }

    /// Build a registry holding exactly one Stellar chain, bypassing the full multi-chain
    /// construction path. Used by `AppState::new`/`new_with_resilience` so the many existing
    /// single-chain tests and call sites keep working unchanged.
    pub fn single_stellar(
        chain_id: impl Into<String>,
        network: StellarNetwork,
        horizon_url: String,
        friendbot_url: Option<String>,
        retry: octo_resilience::RetryPolicy,
        circuit: octo_resilience::CircuitBreaker,
    ) -> Self {
        let chain_id = chain_id.into();
        let config = ChainConfig {
            chain_id: chain_id.clone(),
            kind: ChainKind::Stellar,
            rpc_url: crate::chain_config::RedactedUrl::new(horizon_url.clone()),
            enabled: true,
            confirmation_depth: 1,
            poll_interval: Duration::from_secs(5),
            retry: retry.clone(),
            circuit: circuit.clone(),
            faucet_url: friendbot_url,
        };
        let horizon = Horizon::with_resilience(horizon_url, retry, circuit);
        let mut entries = HashMap::with_capacity(1);
        entries.insert(
            chain_id.clone(),
            ChainEntry {
                config,
                horizon: Some(horizon),
                stellar_network: Some(network),
                last_poll_unix: Mutex::new(None),
            },
        );
        Self {
            entries,
            primary_stellar_chain_id: Some(chain_id),
        }
    }

    /// Probe every enabled chain's RPC with a short timeout. Returns the first failure — callers
    /// should treat any error here as fatal at startup ("fail fast and loudly"). Never includes
    /// the raw RPC URL or the underlying transport error's `Display` in the returned message —
    /// `reqwest::Error` often embeds the request URL, which would leak the same secrets
    /// `RedactedUrl` exists to hide.
    pub async fn probe_liveness(&self, timeout: Duration) -> Result<(), ChainConfigError> {
        for entry in self.entries.values() {
            if !entry.config.enabled {
                continue;
            }
            match entry.config.kind {
                ChainKind::Stellar => {
                    let Some(horizon) = &entry.horizon else {
                        continue;
                    };
                    if let Err(reason) = horizon.liveness_probe(timeout).await {
                        return Err(ChainConfigError::Invalid {
                            chain_id: entry.config.chain_id.clone(),
                            reason,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    pub fn chains(&self) -> impl Iterator<Item = &ChainConfig> {
        self.entries.values().map(|e| &e.config)
    }

    pub fn get(&self, chain_id: &str) -> Option<&ChainConfig> {
        self.entries.get(chain_id).map(|e| &e.config)
    }

    /// The resolved `StellarNetwork` for a Stellar-kind chain entry, if `chain_id` names one.
    /// Used by `bin/server` to spawn one ingest `Supervisor` per enabled Stellar chain — the
    /// supervisor's network-filter argument needs the canonical `StellarNetwork`, not the
    /// possibly-arbitrary configured chain id string.
    pub fn chain_stellar_network(&self, chain_id: &str) -> Option<StellarNetwork> {
        self.entries.get(chain_id)?.stellar_network
    }

    /// Record a successful poll for `chain_id` (a no-op if the id is unknown).
    pub fn record_chain_poll_success(&self, chain_id: &str, timestamp_unix: i64) {
        if let Some(entry) = self.entries.get(chain_id) {
            if let Ok(mut guard) = entry.last_poll_unix.lock() {
                *guard = Some(timestamp_unix);
            }
        }
    }

    /// `(last_poll_unix, seconds_since)` for `chain_id`, if it's known and has polled at least
    /// once.
    pub fn chain_poll_status(&self, chain_id: &str) -> Option<(i64, i64)> {
        let entry = self.entries.get(chain_id)?;
        let last = (*entry.last_poll_unix.lock().ok()?)?;
        let now = now_unix();
        Some((last, (now - last).max(0)))
    }

    // -- legacy single-Stellar-chain accessors, used by `AppState` so route handlers written
    // -- against "the" Stellar network keep compiling unchanged. --

    fn primary_entry(&self) -> &ChainEntry {
        let id = self
            .primary_stellar_chain_id
            .as_deref()
            .expect("ChainRegistry always has at least one enabled Stellar chain (enforced by AppConfig::new's validation and single_stellar's construction)");
        self.entries
            .get(id)
            .expect("primary_stellar_chain_id always names an entry inserted into `entries`")
    }

    pub fn stellar_network(&self) -> StellarNetwork {
        self.primary_entry()
            .stellar_network
            .expect("primary chain is always Stellar-kind")
    }

    pub fn stellar_horizon(&self) -> &Horizon {
        self.primary_entry()
            .horizon
            .as_ref()
            .expect("primary chain is always Stellar-kind")
    }

    pub fn stellar_horizon_url(&self) -> &str {
        self.primary_entry().config.rpc_url.expose_secret()
    }

    pub fn stellar_friendbot_url(&self) -> Option<&str> {
        self.primary_entry().config.faucet_url.as_deref()
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Resolve a `StellarNetwork` from a chain id, accepting either a bare legacy id ("testnet") or a
/// forward-compatible slug ("stellar:testnet") — tries the whole string first, then the part
/// after the last `:`.
fn resolve_stellar_network(chain_id: &str) -> Option<StellarNetwork> {
    StellarNetwork::parse(chain_id)
        .or_else(|| chain_id.rsplit(':').next().and_then(StellarNetwork::parse))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_config::{ChainConfig, RedactedUrl};
    use octo_resilience::{CircuitBreaker, RetryPolicy};

    fn test_chain(chain_id: &str) -> ChainConfig {
        ChainConfig {
            chain_id: chain_id.to_string(),
            kind: ChainKind::Stellar,
            rpc_url: RedactedUrl::new("https://horizon-testnet.stellar.org"),
            enabled: true,
            confirmation_depth: 1,
            poll_interval: Duration::from_secs(5),
            retry: RetryPolicy::default(),
            // Low threshold so the isolation test can open the circuit in a couple of calls.
            circuit: CircuitBreaker::new(2, Duration::from_secs(30)),
            faucet_url: None,
        }
    }

    #[test]
    fn one_chains_circuit_breaker_opening_does_not_affect_another() {
        let cfg = AppConfig::new(vec![test_chain("testnet"), test_chain("standalone")])
            .expect("valid config");
        let registry = ChainRegistry::new(&cfg).expect("registry builds");

        let a = registry.get("testnet").unwrap();
        let b = registry.get("standalone").unwrap();

        a.circuit.on_failure();
        a.circuit.on_failure();
        assert!(
            a.circuit.check().is_err(),
            "chain a's circuit should be open"
        );
        assert!(
            b.circuit.check().is_ok(),
            "chain b's circuit must be unaffected by chain a's failures"
        );
    }

    #[test]
    fn resolves_stellar_network_from_legacy_and_slug_ids() {
        assert_eq!(
            resolve_stellar_network("testnet"),
            Some(StellarNetwork::Testnet)
        );
        assert_eq!(
            resolve_stellar_network("stellar:testnet"),
            Some(StellarNetwork::Testnet)
        );
        assert_eq!(resolve_stellar_network("not-a-network"), None);
    }

    #[test]
    fn poll_status_tracks_per_chain_independently() {
        let cfg = AppConfig::new(vec![test_chain("testnet"), test_chain("standalone")])
            .expect("valid config");
        let registry = ChainRegistry::new(&cfg).expect("registry builds");

        registry.record_chain_poll_success("testnet", 1_000);
        assert!(registry.chain_poll_status("testnet").is_some());
        assert!(registry.chain_poll_status("standalone").is_none());
    }
}
