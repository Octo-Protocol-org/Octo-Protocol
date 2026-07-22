//! Shared application state: DB handle, master key, network, and Horizon config.

use crate::error::ApiError;
use crate::horizon::Horizon;
use base64::Engine;
use octo_crypto::{master_key_from_slice, MASTER_KEY_LEN};
use octo_resilience::{CircuitBreaker, RetryPolicy};
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use octo_webhooks::WebhookSender;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Cloneable, shared API state.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

#[derive(Clone)]
struct Inner {
    store: Store,
    /// AES-256 master key used to seal/open seeds. Held zeroized.
    master_key: Zeroizing<[u8; MASTER_KEY_LEN]>,
    /// Optional next master key present only during a rotation window.
    /// When set, the server tries this key first (for already-migrated rows) and falls back to
    /// `master_key` for rows not yet re-sealed by `octo-migrate-keys`.
    master_key_next: Option<Zeroizing<[u8; MASTER_KEY_LEN]>>,
    network: StellarNetwork,
    horizon: Horizon,
    horizon_url: String,
    friendbot_url: Option<String>,
    /// HMAC secret for signing dashboard auth JWTs.
    jwt_secret: Vec<u8>,
    /// Fires signed webhooks (e.g. `transaction.sponsored`) to registered endpoints.
    webhooks: WebhookSender,
}

impl AppState {
    /// Build state. The JWT secret defaults to a random per-process value (fine for tests/dev;
    /// tokens won't survive a restart). Use [`AppState::with_jwt_secret`] in production.
    pub fn new(
        store: Store,
        master_key: [u8; MASTER_KEY_LEN],
        network: StellarNetwork,
        horizon_url: String,
        friendbot_url: Option<String>,
    ) -> Self {
        let mut secret = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
        Self::build(
            store,
            master_key,
            None,
            network,
            horizon_url,
            friendbot_url,
            secret,
            octo_resilience::RetryPolicy::default(),
            octo_resilience::CircuitBreaker::new(5, std::time::Duration::from_secs(30)),
        )
    }

    /// Build state with explicit resilience configuration (used by `bin/server`).
    pub fn new_with_resilience(
        store: Store,
        master_key: [u8; MASTER_KEY_LEN],
        network: StellarNetwork,
        horizon_url: String,
        friendbot_url: Option<String>,
        retry: octo_resilience::RetryPolicy,
        circuit: octo_resilience::CircuitBreaker,
    ) -> Self {
        let mut secret = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
        Self::build(store, master_key, network, horizon_url, friendbot_url, secret, retry, circuit)
    }

    /// Set the JWT signing secret (e.g. from the `JWT_SECRET` env var) so tokens survive restarts.
    pub fn with_jwt_secret(mut self, secret: Vec<u8>) -> Self {
        // Arc is unique here in practice (called right after `new`), so rebuild the inner.
        let inner = Arc::make_mut(&mut self.inner);
        inner.jwt_secret = secret;
        self
    }

    /// Set the next master key for zero-downtime key rotation.
    /// When set, routes select the key based on the `sealed_scheme` of each wallet row:
    /// already-migrated rows use `master_key_next`; un-migrated rows use `master_key`.
    pub fn with_master_key_next(mut self, key: [u8; MASTER_KEY_LEN]) -> Self {
        let inner = Arc::make_mut(&mut self.inner);
        inner.master_key_next = Some(Zeroizing::new(key));
        self
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        store: Store,
        master_key: [u8; MASTER_KEY_LEN],
        master_key_next: Option<[u8; MASTER_KEY_LEN]>,
        network: StellarNetwork,
        horizon_url: String,
        friendbot_url: Option<String>,
        jwt_secret: Vec<u8>,
        retry: RetryPolicy,
        circuit: CircuitBreaker,
    ) -> Self {
        let horizon = Horizon::with_resilience(horizon_url.clone(), retry, circuit);
        let webhooks = WebhookSender::new(store.clone());
        Self {
            inner: Arc::new(Inner {
                store,
                master_key: Zeroizing::new(master_key),
                master_key_next: master_key_next.map(Zeroizing::new),
                network,
                horizon,
                horizon_url,
                friendbot_url,
                jwt_secret,
                webhooks,
            }),
        }
    }

    /// Decode a base64 32-byte master key (from KMS/env) into raw bytes.
    pub fn decode_master_key(b64: &str) -> Result<[u8; MASTER_KEY_LEN], ApiError> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|_| ApiError::BadRequest("invalid MASTER_KEY (base64)".into()))?;
        master_key_from_slice(&raw)
            .map_err(|_| ApiError::BadRequest("MASTER_KEY must be 32 bytes".into()))
    }

    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    pub fn master_key(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.inner.master_key
    }

    /// Return the next master key, if one is configured for a rotation window.
    pub fn master_key_next(&self) -> Option<&[u8; MASTER_KEY_LEN]> {
        self.inner.master_key_next.as_deref()
    }

    /// Select the correct master key for a wallet given its `sealed_scheme`.
    ///
    /// During a rotation window (`MASTER_KEY_NEXT` is set):
    /// - Rows already migrated to the target scheme use `master_key_next` (the new key).
    /// - Rows not yet migrated use `master_key` (the old key).
    ///
    /// When no next key is configured, always returns `master_key`.
    pub fn master_key_for_scheme(&self, sealed_scheme: i16) -> &[u8; MASTER_KEY_LEN] {
        use octo_crypto::SCHEME_V1;
        match &self.inner.master_key_next {
            Some(next_key) if sealed_scheme == SCHEME_V1 as i16 => next_key,
            _ => &self.inner.master_key,
        }
    }

    pub fn jwt_secret(&self) -> &[u8] {
        &self.inner.jwt_secret
    }

    pub fn network(&self) -> StellarNetwork {
        self.inner.network
    }

    pub fn horizon(&self) -> &Horizon {
        &self.inner.horizon
    }

    pub fn webhooks(&self) -> &WebhookSender {
        &self.inner.webhooks
    }

    pub fn horizon_url(&self) -> &str {
        &self.inner.horizon_url
    }

    pub fn friendbot_url(&self) -> Option<&str> {
        self.inner.friendbot_url.as_deref()
    }
}
