//! Per-key fixed-window rate limiting for public and auth endpoints.
//!
//! Counters live behind a [`RateLimitStore`]: [`MemoryRateLimitStore`] is per-process (tests,
//! single-instance dev), while [`PostgresRateLimitStore`] is shared by every replica and survives
//! restarts — with N in-memory replicas the effective limit would be N times higher. Handlers call
//! [`RateLimiter::check`] explicitly, the same way auth is enforced per-handler here — there is
//! no tower middleware layer to configure or bypass.

use axum::http::HeaderMap;
use octo_store::{Store, StoreError};
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Cap on tracked (key, class) buckets before expired entries are swept.
const SWEEP_THRESHOLD: usize = 10_000;

// Rate limit thresholds and fixed windows for API endpoints.
pub const AUTH_RATE_LIMIT: u32 = 10;
pub const AUTH_RATE_WINDOW: Duration = Duration::from_secs(60);
pub const OTP_RESEND_USER_LIMIT: u32 = 3;
pub const OTP_RESEND_USER_WINDOW: Duration = Duration::from_secs(3600);
pub const OTP_RESEND_IP_LIMIT: u32 = 10;
pub const OTP_RESEND_IP_WINDOW: Duration = Duration::from_secs(3600);
pub const PAY_READ_LIMIT: u32 = 60;
pub const PAY_READ_WINDOW: Duration = Duration::from_secs(60);
pub const PAY_INTENT_LIMIT: u32 = 5;
pub const PAY_INTENT_WINDOW: Duration = Duration::from_secs(60);
pub const PAY_STATUS_LIMIT: u32 = 60;
pub const PAY_STATUS_WINDOW: Duration = Duration::from_secs(60);
pub const PAY_SIGNING_INFO_LIMIT: u32 = 60;
pub const PAY_SIGNING_INFO_WINDOW: Duration = Duration::from_secs(60);
// Owner-triggered outbound webhook sends, keyed per endpoint so one key can't flood a receiver.
pub const WEBHOOK_TEST_LIMIT: u32 = 5;
pub const WEBHOOK_TEST_WINDOW: Duration = Duration::from_secs(60);
pub const WEBHOOK_REDELIVER_LIMIT: u32 = 10;
pub const WEBHOOK_REDELIVER_WINDOW: Duration = Duration::from_secs(60);
pub const PAY_SUBMIT_LIMIT: u32 = 20;
pub const PAY_SUBMIT_WINDOW: Duration = Duration::from_secs(60);
// Seed-backup retrieval: legitimate use is a rare new-device recovery, so keep this tight.
pub const BACKUP_USER_LIMIT: u32 = 5;
pub const BACKUP_USER_WINDOW: Duration = Duration::from_secs(3600);
/// CSV history exports scan a whole wallet's ledger, so starts are capped per wallet.
pub const CSV_EXPORT_LIMIT: u32 = 10;
pub const CSV_EXPORT_WINDOW: Duration = Duration::from_secs(60);

/// Boxed future so [`RateLimitStore`] stays object-safe without an `async-trait` dependency.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Whole seconds left until `expires`, rounded up and never zero (a `Retry-After` of 0 is useless).
fn remaining_secs(expires: Instant, now: Instant) -> u64 {
    let left = expires.saturating_duration_since(now);
    let secs = left.as_secs() + u64::from(left.subsec_nanos() > 0);
    secs.max(1)
}

/// A backend that counts hits per `(key, class)` fixed window.
pub trait RateLimitStore: Send + Sync {
    /// Record one hit and return the hits in the current window, this one included.
    fn hit<'a>(
        &'a self,
        key: &'a str,
        class: &'static str,
        window: Duration,
    ) -> BoxFuture<'a, Result<u64, StoreError>>;

    /// Drop expired windows; returns how many were removed.
    fn prune(&self) -> BoxFuture<'_, Result<u64, StoreError>>;
}

/// Bucket key: the limited subject (IP, `otp:{user}`, ...) plus the endpoint class.
type BucketKey = (String, &'static str);
/// Bucket value: when the current fixed window ends, and hits so far within it.
type Bucket = (Instant, u64);

/// Per-process counters. Limits multiply with replica count and reset on restart.
#[derive(Clone, Default)]
pub struct MemoryRateLimitStore {
    buckets: Arc<Mutex<HashMap<BucketKey, Bucket>>>,
}

impl MemoryRateLimitStore {
    /// Synchronous hit counter shared by the trait impl and the [`RateLimiter`] fallback path.
    fn count(&self, key: &str, class: &'static str, window: Duration) -> u64 {
        self.count_with_remaining(key, class, window).0
    }

    /// Like [`Self::count`], but also returns the seconds left in the current fixed window.
    fn count_with_remaining(
        &self,
        key: &str,
        class: &'static str,
        window: Duration,
    ) -> (u64, u64) {
        let now = Instant::now();
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if buckets.len() > SWEEP_THRESHOLD {
            buckets.retain(|_, (expires, _)| *expires > now);
        }

        let entry = buckets
            .entry((key.to_string(), class))
            .or_insert((now + window, 0));
        if now >= entry.0 {
            *entry = (now + window, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        (entry.1, remaining_secs(entry.0, now))
    }

    fn prune_expired(&self) -> u64 {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let before = buckets.len();
        buckets.retain(|_, (expires, _)| *expires > now);
        (before - buckets.len()) as u64
    }
}

impl RateLimitStore for MemoryRateLimitStore {
    fn hit<'a>(
        &'a self,
        key: &'a str,
        class: &'static str,
        window: Duration,
    ) -> BoxFuture<'a, Result<u64, StoreError>> {
        Box::pin(std::future::ready(Ok(self.count(key, class, window))))
    }

    fn prune(&self) -> BoxFuture<'_, Result<u64, StoreError>> {
        Box::pin(std::future::ready(Ok(self.prune_expired())))
    }
}

/// Counters in the `rate_limit_buckets` table, shared by every instance on the database.
#[derive(Clone)]
pub struct PostgresRateLimitStore {
    store: Store,
}

impl PostgresRateLimitStore {
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

impl RateLimitStore for PostgresRateLimitStore {
    fn hit<'a>(
        &'a self,
        key: &'a str,
        class: &'static str,
        window: Duration,
    ) -> BoxFuture<'a, Result<u64, StoreError>> {
        Box::pin(async move {
            let hits = self.store.rate_limit_hit(key, class, window).await?;
            Ok(u64::try_from(hits).unwrap_or(0))
        })
    }

    fn prune(&self) -> BoxFuture<'_, Result<u64, StoreError>> {
        Box::pin(self.store.prune_rate_limit_buckets())
    }
}

/// Which [`RateLimitStore`] the server uses, selected by `RATE_LIMIT_BACKEND`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitBackend {
    Memory,
    Postgres,
}

impl RateLimitBackend {
    /// Accepts `memory` or `postgres` (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "memory" => Some(Self::Memory),
            "postgres" => Some(Self::Postgres),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Postgres => "postgres",
        }
    }
}

/// The limiter handlers call; cheap to clone.
#[derive(Clone)]
pub struct RateLimiter {
    backend: Arc<dyn RateLimitStore>,
    /// Used only when `backend` errors: a database blip degrades to per-process limits rather
    /// than disabling limits (fail-open) or rejecting every request (fail-closed).
    fallback: MemoryRateLimitStore,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::memory()
    }
}

impl RateLimiter {
    /// Per-process limiter (tests and single-instance dev).
    pub fn memory() -> Self {
        Self::with_backend(Arc::new(MemoryRateLimitStore::default()))
    }

    /// Limiter shared across replicas through Postgres.
    pub fn postgres(store: Store) -> Self {
        Self::with_backend(Arc::new(PostgresRateLimitStore::new(store)))
    }

    pub fn with_backend(backend: Arc<dyn RateLimitStore>) -> Self {
        Self {
            backend,
            fallback: MemoryRateLimitStore::default(),
        }
    }

    /// Build the limiter for a configured backend.
    pub fn for_backend(backend: RateLimitBackend, store: Store) -> Self {
        match backend {
            RateLimitBackend::Memory => Self::memory(),
            RateLimitBackend::Postgres => Self::postgres(store),
        }
    }

    /// Record a hit for `(key, class)`; false when the fixed window's limit is exceeded.
    pub async fn check(&self, key: &str, class: &'static str, limit: u32, window: Duration) -> bool {
        self.check_with_retry_after(key, class, limit, window)
            .await
            .is_ok()
    }

    /// Like [`Self::check`], but on rejection returns the seconds left in the fixed window so
    /// callers can emit a `Retry-After` header.
    pub async fn check_with_retry_after(
        &self,
        key: &str,
        class: &'static str,
        limit: u32,
        window: Duration,
    ) -> Result<(), u64> {
        let (hits, retry_after) = match self.backend.hit(key, class, window).await {
            Ok(hits) => (hits, remaining_secs(Instant::now() + window, Instant::now())),
            Err(e) => {
                tracing::warn!(error = ?e, class, "rate-limit backend failed; using per-process fallback");
                self.fallback.count_with_remaining(key, class, window)
            }
        };
        if hits <= u64::from(limit) {
            Ok(())
        } else {
            Err(retry_after)
        }
    }

    /// Prune expired windows in the backend and the fallback. Run periodically.
    pub async fn prune(&self) -> Result<u64, StoreError> {
        self.fallback.prune_expired();
        self.backend.prune().await
    }
}

/// Parse one `TRUSTED_PROXY_CIDRS` entry into `(network, prefix)`; `None` when invalid.
fn parse_cidr(cidr: &str) -> Option<(IpAddr, u8)> {
    let cidr = cidr.trim();
    let (network, prefix) = match cidr.split_once('/') {
        Some((network, prefix)) => (network, prefix.parse::<u8>().ok()?),
        None => return cidr.parse::<IpAddr>().ok().map(|ip| (ip, 32)),
    };
    let network = network.trim().parse::<IpAddr>().ok()?;
    let max = if network.is_ipv4() { 32 } else { 128 };
    (prefix <= max).then_some((network, prefix))
}

/// Parse the whole variable, warning about and skipping entries that fail to parse.
fn parse_trusted_proxies(value: &str) -> Vec<(IpAddr, u8)> {
    value
        .split(',')
        .filter(|entry| !entry.trim().is_empty())
        .filter_map(|entry| match parse_cidr(entry) {
            Some(cidr) => Some(cidr),
            None => {
                tracing::warn!(entry = entry.trim(), "ignoring unparsable TRUSTED_PROXY_CIDRS entry");
                None
            }
        })
        .collect()
}

/// Parsed `TRUSTED_PROXY_CIDRS`, read from the environment once per process.
fn trusted_proxies() -> &'static [(IpAddr, u8)] {
    static TRUSTED_PROXIES: OnceLock<Vec<(IpAddr, u8)>> = OnceLock::new();
    TRUSTED_PROXIES.get_or_init(|| {
        std::env::var("TRUSTED_PROXY_CIDRS")
            .map(|value| parse_trusted_proxies(&value))
            .unwrap_or_default()
    })
}

fn ip_in_cidr(ip: IpAddr, (network, prefix): (IpAddr, u8)) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(network)) => {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            u32::from(ip) & mask == u32::from(network) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(network)) => {
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            u128::from(ip) & mask == u128::from(network) & mask
        }
        _ => false,
    }
}

fn is_trusted_proxy(ip: IpAddr) -> bool {
    trusted_proxies().iter().any(|cidr| ip_in_cidr(ip, *cidr))
}

/// Resolve the client address while honoring forwarding headers only from configured proxies.
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    let Some(peer_ip) = peer.map(|addr| addr.ip()) else {
        return "unknown".to_string();
    };
    if !is_trusted_proxy(peer_ip) {
        return peer_ip.to_string();
    }

    let Some(xff) = headers.get("x-forwarded-for").and_then(|value| value.to_str().ok()) else {
        return peer_ip.to_string();
    };
    let forwarded: Option<Vec<IpAddr>> = xff
        .split(',')
        .map(|value| value.trim().parse::<IpAddr>().ok())
        .collect();
    let Some(forwarded) = forwarded else {
        return peer_ip.to_string();
    };
    forwarded
        .into_iter()
        .rev()
        .find(|ip| !is_trusted_proxy(*ip))
        .unwrap_or(peer_ip)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_up_to_limit_then_rejects() {
        let rl = RateLimiter::default();
        let window = Duration::from_secs(60);
        for _ in 0..5 {
            assert!(rl.check("1.2.3.4", "test", 5, window).await);
        }
        assert!(!rl.check("1.2.3.4", "test", 5, window).await);
        // A different IP has its own bucket.
        assert!(rl.check("5.6.7.8", "test", 5, window).await);
        // A different class on the same IP has its own bucket too.
        assert!(rl.check("1.2.3.4", "other", 5, window).await);
    }

    #[tokio::test]
    async fn check_with_retry_after_reports_positive_remaining_window() {
        let rl = RateLimiter::default();
        let window = Duration::from_secs(60);
        assert!(rl.check_with_retry_after("1.2.3.4", "test", 1, window).await.is_ok());
        let retry_after = rl
            .check_with_retry_after("1.2.3.4", "test", 1, window)
            .await
            .unwrap_err();
        assert!(retry_after > 0, "Retry-After must be a positive integer");
        assert!(retry_after <= window.as_secs());
    }

    #[tokio::test]
    async fn window_resets_after_expiry() {
        let rl = RateLimiter::default();
        let window = Duration::from_millis(30);
        assert!(rl.check("1.2.3.4", "test", 1, window).await);
        assert!(!rl.check("1.2.3.4", "test", 1, window).await);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(rl.check("1.2.3.4", "test", 1, window).await);
    }

    #[test]
    fn poisoned_lock_recovers_for_later_requests() {
        let store = MemoryRateLimitStore::default();
        let buckets = Arc::clone(&store.buckets);
        let _ = std::thread::spawn(move || {
            let _guard = buckets.lock().unwrap();
            panic!("poison the counter map");
        })
        .join();

        assert_eq!(store.count("1.2.3.4", "auth", Duration::from_secs(60)), 1);
    }

    #[tokio::test]
    async fn concurrent_hits_respect_exact_limit() {
        // Issue #482: spawn many tasks hitting the same bucket and verify the exact allowed count.
        let rl = RateLimiter::default();
        let window = Duration::from_secs(60);
        let limit = 10u32;
        let concurrent_requests = 50;

        // Spawn many concurrent tasks all hitting the same bucket
        let handles: Vec<_> = (0..concurrent_requests)
            .map(|_| {
                let rl = rl.clone();
                tokio::spawn(async move {
                    rl.check("concurrent-key", "test", limit, window).await
                })
            })
            .collect();

        let results: Vec<bool> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        // Exactly `limit` requests should succeed
        let allowed = results.iter().filter(|&&success| success).count();
        assert_eq!(
            allowed, limit as usize,
            "exactly {limit} concurrent requests should be allowed"
        );
        
        // The rest should be rejected
        let rejected = results.iter().filter(|&&success| !success).count();
        assert_eq!(
            rejected,
            (concurrent_requests - limit as usize),
            "remaining requests should be rejected"
        );
    }

    #[tokio::test]
    async fn sweep_drops_expired_entries_at_threshold() {
        // Issue #482: fill past SWEEP_THRESHOLD and verify expired entries are dropped.
        let store = MemoryRateLimitStore::default();
        let short_window = Duration::from_millis(10);

        // Fill up to just over the threshold with different keys
        for i in 0..SWEEP_THRESHOLD + 100 {
            store.count(&format!("key-{i}"), "test", short_window);
        }

        // Verify we have many entries
        let before_count = store.buckets.lock().unwrap().len();
        assert!(
            before_count > SWEEP_THRESHOLD,
            "should have filled past threshold"
        );

        // Wait for windows to expire
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Trigger a sweep by adding one more entry (the count method sweeps at threshold)
        store.count("trigger-sweep", "test", Duration::from_secs(60));

        // Verify expired entries were removed
        let after_count = store.buckets.lock().unwrap().len();
        assert!(
            after_count < before_count,
            "sweep should have removed expired entries (before: {before_count}, after: {after_count})"
        );
        assert!(
            after_count <= SWEEP_THRESHOLD + 10,
            "most expired entries should be gone"
        );
    }

    #[tokio::test]
    async fn prune_removes_expired_buckets() {
        let rl = RateLimiter::default();
        let short_window = Duration::from_millis(10);

        // Create several buckets with short windows
        for i in 0..50 {
            assert!(rl.check(&format!("key-{i}"), "test", 1, short_window).await);
        }

        // Wait for expiry
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Prune should remove expired entries
        let removed = rl.prune().await.unwrap();
        assert!(removed > 0, "prune should have removed expired buckets");
    }

    #[test]
    fn client_ip_uses_socket_peer_without_a_trusted_proxy() {
        let empty = HeaderMap::new();
        let peer = "127.0.0.1:5000".parse().ok();
        assert_eq!(client_ip(&empty, peer), "127.0.0.1");
        assert_eq!(client_ip(&empty, None), "unknown");
    }

    // -------------------------------------------------------------------------
    // #481 – table-driven coverage for forwarded-header variants
    // -------------------------------------------------------------------------

    /// Build a HeaderMap with a single header value.
    fn hm(name: &str, value: &str) -> HeaderMap {
        let mut m = HeaderMap::new();
        m.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            axum::http::HeaderValue::from_str(value).unwrap(),
        );
        m
    }

    /// Set TRUSTED_PROXY_CIDRS to a single CIDR for the duration of a closure,
    /// then restore the previous value. Not parallel-safe (env mutation), but
    /// each test pins a distinct CIDR so individual test runs are deterministic.
    fn with_trusted_proxy<F: FnOnce()>(cidr: &str, f: F) {
        std::env::set_var("TRUSTED_PROXY_CIDRS", cidr);
        f();
        std::env::remove_var("TRUSTED_PROXY_CIDRS");
    }

    #[test]
    fn parse_trusted_proxies_skips_invalid_entries() {
        let parsed = parse_trusted_proxies("10.0.0.0/8, not-a-cidr, 2001:db8::/32, 10.0.0.0/99");
        assert_eq!(
            parsed,
            vec![
                ("10.0.0.0".parse().unwrap(), 8),
                ("2001:db8::".parse().unwrap(), 32),
            ]
        );
        // An invalid entry must never widen trust.
        assert!(!parsed.iter().any(|cidr| ip_in_cidr("192.0.2.1".parse().unwrap(), *cidr)));
    }

    #[test]
    fn client_ip_single_hop_xff_from_trusted_proxy() {
        with_trusted_proxy("10.0.0.1/32", || {
            let peer = "10.0.0.1:443".parse().ok();
            let headers = hm("x-forwarded-for", "203.0.113.5");
            assert_eq!(client_ip(&headers, peer), "203.0.113.5");
        });
    }

    #[test]
    fn client_ip_multiple_hops_picks_leftmost_untrusted() {
        // XFF chain: client → proxy1 (untrusted) → proxy2 (trusted)
        // peer is the trusted proxy; the function should walk right-to-left and
        // return the first IP that is not itself a trusted proxy.
        with_trusted_proxy("10.0.0.2/32", || {
            let peer = "10.0.0.2:443".parse().ok();
            // "203.0.113.5, 198.51.100.7" – left is real client, right is intermediate
            let headers = hm("x-forwarded-for", "203.0.113.5, 198.51.100.7");
            assert_eq!(client_ip(&headers, peer), "198.51.100.7");
        });
    }

    #[test]
    fn client_ip_multiple_hops_all_trusted_falls_back_to_peer() {
        // All hops are trusted proxies → fall back to peer IP.
        with_trusted_proxy("10.0.0.0/8", || {
            let peer = "10.1.2.3:443".parse().ok();
            let headers = hm("x-forwarded-for", "10.4.5.6, 10.7.8.9");
            assert_eq!(client_ip(&headers, peer), "10.1.2.3");
        });
    }

    #[test]
    fn client_ip_xff_with_whitespace_around_commas() {
        with_trusted_proxy("10.0.0.1/32", || {
            let peer = "10.0.0.1:443".parse().ok();
            // Typical proxy behaviour: "  1.2.3.4  ,  5.6.7.8  "
            let headers = hm("x-forwarded-for", "  203.0.113.5  ,  198.51.100.9  ");
            // Right-most untrusted after trimming is 198.51.100.9
            assert_eq!(client_ip(&headers, peer), "198.51.100.9");
        });
    }

    #[test]
    fn client_ip_xff_with_ipv6_address() {
        with_trusted_proxy("10.0.0.1/32", || {
            let peer = "10.0.0.1:443".parse().ok();
            let headers = hm("x-forwarded-for", "2001:db8::1");
            assert_eq!(client_ip(&headers, peer), "2001:db8::1");
        });
    }

    #[test]
    fn client_ip_xff_ipv6_multi_hop() {
        with_trusted_proxy("10.0.0.1/32", || {
            let peer = "10.0.0.1:443".parse().ok();
            let headers = hm("x-forwarded-for", "2001:db8::cafe, 2001:db8::dead");
            // right-most untrusted
            assert_eq!(client_ip(&headers, peer), "2001:db8::dead");
        });
    }

    #[test]
    fn client_ip_empty_xff_header_falls_back_to_peer() {
        with_trusted_proxy("10.0.0.1/32", || {
            let peer = "10.0.0.1:443".parse().ok();
            let headers = hm("x-forwarded-for", "");
            // Empty value cannot be parsed as IPs → fall back to peer
            assert_eq!(client_ip(&headers, peer), "10.0.0.1");
        });
    }

    #[test]
    fn client_ip_malformed_xff_falls_back_to_peer() {
        with_trusted_proxy("10.0.0.1/32", || {
            let peer = "10.0.0.1:443".parse().ok();
            // One of the entries is not a valid IP → whole header treated as untrustworthy
            let headers = hm("x-forwarded-for", "203.0.113.5, not-an-ip");
            assert_eq!(client_ip(&headers, peer), "10.0.0.1");
        });
    }

    #[test]
    fn client_ip_no_trusted_proxy_configured_ignores_xff() {
        // TRUSTED_PROXY_CIDRS unset → peer IP is always returned regardless of XFF.
        std::env::remove_var("TRUSTED_PROXY_CIDRS");
        let peer = "198.51.100.1:443".parse().ok();
        let headers = hm("x-forwarded-for", "203.0.113.5");
        assert_eq!(client_ip(&headers, peer), "198.51.100.1");
    }

    #[test]
    fn client_ip_no_peer_returns_unknown() {
        with_trusted_proxy("10.0.0.1/32", || {
            let headers = hm("x-forwarded-for", "203.0.113.5");
            assert_eq!(client_ip(&headers, None), "unknown");
        });
    }

    #[test]
    fn client_ip_cidr_wildcard_0_prefix_trusts_all_peers() {
        // 0.0.0.0/0 trusts every IPv4 peer → XFF is always honoured.
        with_trusted_proxy("0.0.0.0/0", || {
            let peer = "1.2.3.4:80".parse().ok();
            let headers = hm("x-forwarded-for", "203.0.113.99");
            assert_eq!(client_ip(&headers, peer), "203.0.113.99");
        });
    }

    #[test]
    fn cidr_matching_supports_ipv4_and_ipv6() {
        let v4 = parse_cidr("10.0.0.0/8").unwrap();
        let v6 = parse_cidr("2001:db8::/32").unwrap();
        assert!(ip_in_cidr("10.2.3.4".parse().unwrap(), v4));
        assert!(!ip_in_cidr("11.2.3.4".parse().unwrap(), v4));
        assert!(ip_in_cidr("2001:db8::1".parse().unwrap(), v6));
    }
}
