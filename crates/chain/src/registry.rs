//! A lookup table from [`ChainId`] to the adapter that handles it.

use crate::adapter::ChainAdapter;
use crate::error::ChainError;
use crate::id::ChainId;
use std::collections::HashMap;
use std::sync::Arc;

/// Maps each configured [`ChainId`] to its [`ChainAdapter`].
///
/// `Arc<dyn ChainAdapter>` (not a bare adapter) so the registry, and each adapter it hands out,
/// can be cloned cheaply into `AppState` and per-wallet ingest tasks alike.
#[derive(Clone, Default)]
pub struct ChainRegistry {
    adapters: HashMap<ChainId, Arc<dyn ChainAdapter>>,
}

impl ChainRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `adapter` under its own [`ChainAdapter::chain_id`]. Replaces any adapter
    /// previously registered for that id, returning it.
    pub fn register(&mut self, adapter: Arc<dyn ChainAdapter>) -> Option<Arc<dyn ChainAdapter>> {
        self.adapters.insert(adapter.chain_id().clone(), adapter)
    }

    /// Look up the adapter for `id`.
    ///
    /// Never panics on a miss — a chain id from external input (e.g. an API request) that isn't
    /// configured is an ordinary, expected error, not a bug.
    pub fn get(&self, id: &ChainId) -> Result<Arc<dyn ChainAdapter>, ChainError> {
        self.adapters
            .get(id)
            .cloned()
            .ok_or_else(|| ChainError::UnsupportedChain(id.to_string()))
    }

    /// Every chain id currently registered.
    pub fn chain_ids(&self) -> impl Iterator<Item = &ChainId> {
        self.adapters.keys()
    }

    /// How many adapters are registered.
    pub fn len(&self) -> usize {
        self.adapters.len()
    }

    /// Whether no adapters are registered.
    pub fn is_empty(&self) -> bool {
        self.adapters.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::DepositAddress;
    use crate::capabilities::{ChainCapabilities, ChainKind};
    use async_trait::async_trait;

    struct StubAdapter(ChainId);

    #[async_trait]
    impl ChainAdapter for StubAdapter {
        fn chain_id(&self) -> &ChainId {
            &self.0
        }
        fn capabilities(&self) -> ChainCapabilities {
            ChainCapabilities {
                kind: ChainKind::Stellar,
                supports_memo: true,
                supports_muxed_addresses: true,
                has_reorgs: false,
                native_decimals: 7,
            }
        }
        async fn validate_address(&self, _address: &str) -> Result<(), ChainError> {
            Ok(())
        }
        async fn normalize_address(&self, address: &str) -> Result<String, ChainError> {
            Ok(address.to_string())
        }
        async fn derive_deposit_address(
            &self,
            _base_identity: &str,
            _customer_id: u64,
        ) -> Result<DepositAddress, ChainError> {
            unimplemented!("not exercised by registry tests")
        }
        async fn explain_failure(&self, code: &str) -> String {
            code.to_string()
        }
    }

    #[test]
    fn lookup_returns_registered_adapter() {
        let mut registry = ChainRegistry::new();
        let id = ChainId::parse("stellar:testnet").unwrap();
        registry.register(Arc::new(StubAdapter(id.clone())));

        let found = registry.get(&id).unwrap();
        assert_eq!(found.chain_id(), &id);
    }

    #[test]
    fn lookup_of_unregistered_chain_errors_not_panics() {
        let registry = ChainRegistry::new();
        let id = ChainId::parse("eip155:1").unwrap();
        assert!(matches!(
            registry.get(&id),
            Err(ChainError::UnsupportedChain(s)) if s == "eip155:1"
        ));
    }

    #[test]
    fn registering_same_chain_id_replaces_and_returns_previous() {
        let mut registry = ChainRegistry::new();
        let id = ChainId::parse("stellar:testnet").unwrap();
        let first = Arc::new(StubAdapter(id.clone()));
        let second = Arc::new(StubAdapter(id.clone()));

        assert!(registry.register(first).is_none());
        let replaced = registry.register(second);
        assert!(replaced.is_some());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn empty_registry_reports_empty() {
        let registry = ChainRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.chain_ids().count(), 0);
    }
}
