//! Outbound webhooks for octo.
//!
//! Delivers signed JSON events (e.g. `deposit.created`) to a wallet's registered endpoints. Each
//! payload is **HMAC-SHA256 signed** (see [`sign`]) so consumers can authenticate it, retried with
//! backoff on failure, and every attempt is logged to `webhook_deliveries`.
//!
//! SSRF note: endpoint URLs are operator-registered, but [`is_safe_url`] still blocks obvious
//! internal targets (localhost, link-local, private ranges) as defense in depth.
#![forbid(unsafe_code)]

pub mod sign;

use octo_resilience::{CallKind, CircuitBreaker, ResilienceError, Retriable, RetryPolicy};
use octo_store::Store;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;

/// A webhook event to deliver.
pub struct Event {
    /// e.g. `"deposit.created"`.
    pub event_type: String,
    /// The JSON payload (the `data` of the event).
    pub data: serde_json::Value,
}

pub const DEFAULT_DELIVERY_TIMEOUT: Duration = Duration::from_secs(20);

/// Most bytes of an endpoint's response body kept in the delivery log (bounds table growth).
pub const RESPONSE_SNIPPET_MAX_BYTES: usize = 1024;

/// Extra bytes read past the snippet cap so a secret straddling the cut is still redacted.
const REDACTION_SLACK_BYTES: usize = 1024;

/// Default retry policy: 3 attempts, ~1s then ~2s backoff, bounded by the delivery timeout.
fn default_retry_policy() -> RetryPolicy {
    RetryPolicy {
        max_attempts: 3,
        base_delay_ms: 1_000,
        max_delay_ms: 4_000,
        ..RetryPolicy::default()
    }
}

/// What a single HTTP attempt observed — the only response data that is persisted.
#[derive(Debug, Clone, Default)]
struct AttemptOutcome {
    /// HTTP status, or `None` for a connection error / per-request timeout.
    status: Option<u16>,
    /// Redacted, truncated response body.
    body_snippet: Option<String>,
}

impl AttemptOutcome {
    fn is_success(&self) -> bool {
        matches!(self.status, Some(s) if (200..300).contains(&s))
    }
}

// Transport errors and 5xx are transient; any other non-2xx is the endpoint's final answer.
impl Retriable for AttemptOutcome {
    fn is_retriable(&self) -> bool {
        self.status.is_none_or(|s| s >= 500)
    }
}

/// Delivery-log statuses written by the sender.
pub mod status {
    pub const DELIVERED: &str = "delivered";
    /// Never attempted (unsafe URL) or a diagnostic ping that failed.
    pub const FAILED: &str = "failed";
    /// Terminal: retries exhausted or a non-retriable answer (#458).
    pub const DEAD: &str = "dead";
}

/// Event type of the diagnostic ping sent by [`WebhookSender::send_ping`].
pub const PING_EVENT: &str = "ping";

/// Env var holding the dead-delivery streak that auto-disables an endpoint (unset = never).
pub const AUTO_DISABLE_ENV: &str = "OCTO_WEBHOOK_AUTO_DISABLE_AFTER";

/// The final, logged result of sending one event to one endpoint.
#[derive(Debug, Clone)]
pub struct DeliveryResult {
    /// Delivery-log row id; `None` only if writing the log row itself failed.
    pub delivery_id: Option<Uuid>,
    pub status: &'static str,
    pub attempts: i32,
    pub response_code: Option<i32>,
}

impl DeliveryResult {
    pub fn is_delivered(&self) -> bool {
        self.status == status::DELIVERED
    }
}

/// How a send is retried, labelled on failure, and whether it feeds the auto-disable streak.
#[derive(Clone, Copy)]
enum SendKind {
    /// A real event: full retry policy, `dead` on failure, counts toward auto-disable.
    Event,
    /// A diagnostic ping: one attempt, `failed` on failure, never disables the endpoint.
    Ping,
}

/// Sends signed webhooks for a wallet's active endpoints, with retry + delivery logging.
#[derive(Clone)]
pub struct WebhookSender {
    store: Store,
    http: reqwest::Client,
    retry_policy: RetryPolicy,
    delivery_timeout: Duration,
    auto_disable_after: Option<i32>,
}

impl WebhookSender {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            retry_policy: default_retry_policy(),
            delivery_timeout: DEFAULT_DELIVERY_TIMEOUT,
            auto_disable_after: auto_disable_after_from_env(),
        }
    }

    /// Deactivate an endpoint after `n` consecutive dead deliveries (`None` disables the feature).
    pub fn with_auto_disable_after(mut self, n: Option<i32>) -> Self {
        self.auto_disable_after = n.filter(|n| *n > 0);
        self
    }

    /// Set a custom total delivery timeout ceiling per endpoint, across all retries (default 20s).
    pub fn with_delivery_timeout(mut self, timeout: Duration) -> Self {
        self.delivery_timeout = timeout;
        self
    }

    /// Override the retry policy (attempt count and backoff) used for each endpoint.
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }

    /// Deliver `event` to every active endpoint of `wallet_id`. Best-effort per endpoint: a failing
    /// endpoint is logged and does not block the others. Returns how many endpoints accepted.
    pub async fn dispatch(&self, wallet_id: Uuid, event: &Event) -> usize {
        let endpoints = match self.store.active_webhook_endpoints(wallet_id).await {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = ?e, "could not load webhook endpoints");
                return 0;
            }
        };

        // The signed body wraps the event in the standard envelope.
        let body = json!({
            "event": event.event_type,
            "data": event.data,
        });

        let mut delivered = 0;
        for ep in endpoints {
            let result = self
                .send(&ep, &event.event_type, &body, SendKind::Event)
                .await;
            if result.is_delivered() {
                delivered += 1;
            }
        }
        delivered
    }

    /// Send a signed `ping` to one endpoint so its owner can verify their receiver (#456).
    ///
    /// Goes through the same SSRF check, signing and delivery log as real events, but makes a
    /// single attempt and never counts toward auto-disable. Callers enforce ownership.
    pub async fn send_ping(&self, ep: &octo_store::WebhookEndpoint) -> DeliveryResult {
        let body = json!({
            "event": PING_EVENT,
            "data": { "endpoint_id": ep.id, "sent_at": unix_now() },
        });
        self.send(ep, PING_EVENT, &body, SendKind::Ping).await
    }

    /// Re-send a past delivery's event to its endpoint (#457). Callers enforce ownership.
    ///
    /// The original `event` and `data` are reused verbatim; `redelivery_of` and a fresh
    /// `redelivered_at` are added so the body, and therefore the signature, is new.
    pub async fn redeliver(
        &self,
        ep: &octo_store::WebhookEndpoint,
        original: &octo_store::WebhookDelivery,
    ) -> DeliveryResult {
        let body = json!({
            "event": original.event_type,
            "data": original.payload.get("data").cloned().unwrap_or(serde_json::Value::Null),
            "redelivery_of": original.id,
            "redelivered_at": unix_now(),
        });
        self.send(ep, &original.event_type, &body, SendKind::Event)
            .await
    }

    /// SSRF-check, sign and deliver `body` to one endpoint, logging the outcome.
    async fn send(
        &self,
        ep: &octo_store::WebhookEndpoint,
        event_type: &str,
        body: &serde_json::Value,
        kind: SendKind,
    ) -> DeliveryResult {
        if !is_safe_url(&ep.url) {
            tracing::warn!(url = %ep.url, "skipping webhook to unsafe URL");
            let delivery_id = self
                .store
                .log_webhook_delivery(ep.id, event_type, body, status::FAILED, 0, None, None)
                .await
                .ok();
            return DeliveryResult {
                delivery_id,
                status: status::FAILED,
                attempts: 0,
                response_code: None,
            };
        }
        let body_bytes = serde_json::to_vec(body).unwrap_or_default();
        let result = self
            .deliver_with_retry(ep, event_type, body, &body_bytes, kind)
            .await;

        if matches!(kind, SendKind::Event) {
            let dead = !result.is_delivered();
            match self
                .store
                .record_webhook_endpoint_outcome(ep.id, dead, self.auto_disable_after)
                .await
            {
                Ok(true) => tracing::warn!(
                    endpoint_id = %ep.id,
                    threshold = ?self.auto_disable_after,
                    "webhook endpoint auto-disabled after consecutive dead deliveries"
                ),
                Ok(false) => {}
                Err(e) => tracing::warn!(error = ?e, "could not update endpoint delivery streak"),
            }
        }
        result
    }

    /// Deliver to one endpoint via `octo_resilience::execute`, then log the final outcome.
    async fn deliver_with_retry(
        &self,
        ep: &octo_store::WebhookEndpoint,
        event_type: &str,
        body: &serde_json::Value,
        body_bytes: &[u8],
        kind: SendKind,
    ) -> DeliveryResult {
        let (policy, failed_status) = match kind {
            SendKind::Event => (self.retry_policy.clone(), status::DEAD),
            SendKind::Ping => (
                RetryPolicy {
                    max_attempts: 1,
                    ..self.retry_policy.clone()
                },
                status::FAILED,
            ),
        };
        let signature = sign::sign(ep.secret.as_bytes(), body_bytes);
        // Fresh per delivery and never tripping: one endpoint's outage must not gate another's.
        let circuit = CircuitBreaker::new(u32::MAX, Duration::ZERO);
        // Atomic (not Cell) so the dispatch future stays `Send` for callers that spawn it.
        let attempts = AtomicU32::new(0);
        // Last observation, kept so a deadline mid-retry still logs what the endpoint said.
        let last = Mutex::new(AttemptOutcome::default());
        let (attempts_ref, last_ref, signature_ref) = (&attempts, &last, signature.as_str());

        let result = tokio::time::timeout(
            self.delivery_timeout,
            octo_resilience::execute(&circuit, &policy, CallKind::ReadOnly, move || {
                attempts_ref.fetch_add(1, Ordering::Relaxed);
                async move {
                    let outcome = self.attempt_once(ep, signature_ref, body_bytes).await;
                    *last_ref.lock().unwrap() = outcome.clone();
                    if outcome.is_success() {
                        Ok(outcome)
                    } else {
                        Err(outcome)
                    }
                }
            }),
        )
        .await;

        let (final_status, outcome) = match result {
            Ok(Ok(outcome)) => (status::DELIVERED, outcome),
            Ok(Err(ResilienceError::Exhausted(outcome))) => (failed_status, outcome),
            Ok(Err(ResilienceError::Circuit)) => (failed_status, take_last(&last)),
            Err(_) => {
                tracing::warn!(
                    endpoint_id = %ep.id,
                    url = %ep.url,
                    timeout_secs = self.delivery_timeout.as_secs(),
                    "webhook delivery exceeded overall deadline"
                );
                (failed_status, take_last(&last))
            }
        };

        let kind_label = match kind {
            SendKind::Event => "event",
            SendKind::Ping => "ping",
        };
        octo_metrics::WEBHOOK_DELIVERIES.inc(&[kind_label, final_status]);
        let attempts = attempts.load(Ordering::Relaxed).max(1) as i32;
        let response_code = outcome.status.map(i32::from);
        let delivery_id = self
            .store
            .log_webhook_delivery(
                ep.id,
                event_type,
                body,
                final_status,
                attempts,
                response_code,
                outcome.body_snippet.as_deref(),
            )
            .await
            .map_err(|e| tracing::warn!(error = ?e, "could not log webhook delivery"))
            .ok();
        DeliveryResult {
            delivery_id,
            status: final_status,
            attempts,
            response_code,
        }
    }

    /// One signed POST. Reads at most a bounded prefix of the response body.
    async fn attempt_once(
        &self,
        ep: &octo_store::WebhookEndpoint,
        signature: &str,
        body_bytes: &[u8],
    ) -> AttemptOutcome {
        if !is_safe_delivery_url(&ep.url).await {
            tracing::warn!(url = %ep.url, "webhook destination resolved to a non-public address");
            return AttemptOutcome::default();
        }
        let resp = self
            .http
            .post(&ep.url)
            .header("content-type", "application/json")
            .header(sign::SIGNATURE_HEADER, signature)
            .body(body_bytes.to_vec())
            .send()
            .await;
        let Ok(mut resp) = resp else {
            return AttemptOutcome::default();
        };
        let status = resp.status().as_u16();

        // Stream only a bounded prefix so a huge error page can't balloon memory.
        let limit = RESPONSE_SNIPPET_MAX_BYTES + REDACTION_SLACK_BYTES;
        let mut raw = Vec::new();
        while raw.len() < limit {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    let take = chunk.len().min(limit - raw.len());
                    raw.extend_from_slice(&chunk[..take]);
                }
                _ => break,
            }
        }

        AttemptOutcome {
            status: Some(status),
            body_snippet: response_snippet(&raw, &[signature, ep.secret.as_str()]),
        }
    }
}

/// Re-resolve hostnames immediately before each attempt. This closes registration-to-delivery DNS
/// rebinding; production egress policy must constrain the remaining resolver-to-connect window.
async fn is_safe_delivery_url(url: &str) -> bool {
    if !is_safe_url(url) {
        return false;
    }
    if std::env::var("OCTO_ALLOW_LOCAL_WEBHOOKS").as_deref() == Ok("1") {
        return true;
    }
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
        return true;
    }
    let port = parsed.port_or_known_default().unwrap_or(443);
    match tokio::net::lookup_host((host, port)).await {
        Ok(addresses) => {
            let resolved: Vec<_> = addresses.collect();
            !resolved.is_empty()
                && resolved.into_iter().all(|address| match address.ip() {
                    IpAddr::V4(ip) => is_public_ipv4(ip),
                    IpAddr::V6(ip) => is_public_ipv6(ip),
                })
        }
        Err(_) => false,
    }
}

/// Seconds since the Unix epoch, for envelope timestamps.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Read [`AUTO_DISABLE_ENV`]; unset, unparsable or non-positive means auto-disable is off.
fn auto_disable_after_from_env() -> Option<i32> {
    parse_auto_disable_after(std::env::var(AUTO_DISABLE_ENV).ok().as_deref())
}

fn parse_auto_disable_after(raw: Option<&str>) -> Option<i32> {
    raw.and_then(|v| v.trim().parse::<i32>().ok())
        .filter(|n| *n > 0)
}

/// Take the last attempt's outcome, tolerating a poisoned lock (logging must still happen).
fn take_last(last: &Mutex<AttemptOutcome>) -> AttemptOutcome {
    std::mem::take(&mut *last.lock().unwrap_or_else(|e| e.into_inner()))
}

/// Redact `secrets` from a response body and truncate it to [`RESPONSE_SNIPPET_MAX_BYTES`] on a
/// char boundary. An endpoint echoing our headers back must never land the signature in the log.
fn response_snippet(raw: &[u8], secrets: &[&str]) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    let mut text = String::from_utf8_lossy(raw).into_owned();
    for secret in secrets.iter().filter(|s| !s.is_empty()) {
        text = text.replace(secret, "[redacted]");
    }
    let mut cut = text.len().min(RESPONSE_SNIPPET_MAX_BYTES);
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
    Some(text)
}

/// Reject obviously-internal webhook targets (defense-in-depth against SSRF). Only `http`/`https`
/// to non-loopback, non-private hosts are allowed.
///
/// The host is taken from the WHATWG-normalised URL — the same parse `reqwest` connects with — so
/// alternate encodings (`[::ffff:7f00:1]`, `0x7f.1`, `2130706433`, `0`) are classified by the
/// address they actually reach, not by how they were spelled.
///
/// Scope boundary: `is_safe_url` inspects the URL syntactically and validates literal
/// IP addresses and local domain patterns. It deliberately does not perform asynchronous DNS
/// lookups to resolve hostnames to IP addresses; full DNS resolution and rebinding protections
/// are delegated to the HTTP client and egress network policies.
pub fn is_safe_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return false;
    }
    // Dev/test escape hatch: allow loopback/private targets only when explicitly opted in.
    if allow_local_webhooks() {
        return true;
    }
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    // IPv6 hosts come back bracketed; strip before parsing as an address.
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => is_public_ipv4(v4),
        Ok(IpAddr::V6(v6)) => is_public_ipv6(v6),
        Err(_) => is_public_hostname(host),
    }
}

pub fn allow_local_webhooks() -> bool {
    std::env::var("OCTO_ALLOW_LOCAL_WEBHOOKS").as_deref() == Ok("1")
}

/// Hostname blocklist; a trailing root dot (`localhost.`) resolves identically so is ignored.
fn is_public_hostname(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    !(host.is_empty()
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local"))
}

/// IPv4: reject unspecified/"this network" (0/8), loopback, private, link-local (incl. cloud
/// metadata 169.254.169.254), CGNAT (100.64/10), reserved/documentation ranges, broadcast and
/// multicast.
fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    !(a == 0
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && ip.octets()[2] == 0)
        || (a == 192 && b == 0 && ip.octets()[2] == 2)
        || (a == 198 && b == 51 && ip.octets()[2] == 100)
        || (a == 203 && b == 0 && ip.octets()[2] == 113)
        || (a == 198 && (18..=19).contains(&b))
        || a >= 240
        || ip.is_broadcast()
        || ip.is_multicast())
}

/// IPv6: an IPv4-mapped address (`::ffff:a.b.c.d`) is judged by its embedded IPv4 — that's what
/// the socket reaches. Otherwise reject unspecified (`::`), loopback, link-local (fe80::/10),
/// unique-local (fc00::/7) and multicast.
fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_ipv4(v4);
    }
    // Deprecated IPv4-compatible form (`::a.b.c.d`) is judged by its embedded IPv4 too.
    if ip.segments()[..6].iter().all(|s| *s == 0) {
        return ip.to_ipv4().is_some_and(is_public_ipv4);
    }
    let first = ip.segments()[0];
    !(ip.is_unspecified()
        || ip.is_loopback()
        || (first & 0xffc0) == 0xfe80
        || (first & 0xfe00) == 0xfc00
        || ip.is_multicast())
}

#[cfg(test)]
mod tests {
    use super::{
        is_safe_url, parse_auto_disable_after, response_snippet, RESPONSE_SNIPPET_MAX_BYTES,
    };

    #[test]
    fn auto_disable_threshold_parses_only_positive_integers() {
        assert_eq!(parse_auto_disable_after(Some("5")), Some(5));
        assert_eq!(parse_auto_disable_after(Some(" 3 ")), Some(3));
        assert_eq!(parse_auto_disable_after(Some("0")), None);
        assert_eq!(parse_auto_disable_after(Some("-2")), None);
        assert_eq!(parse_auto_disable_after(Some("ten")), None);
        assert_eq!(parse_auto_disable_after(None), None);
    }

    // --- Standard Public URLs ---
    #[test]
    fn test_standard_public_urls() {
        assert!(is_safe_url("https://api.customer.com/webhooks"));
        assert!(is_safe_url("http://example.org:8080/hook"));
        assert!(is_safe_url("http://172.15.0.1/x"));
        assert!(is_safe_url("http://172.32.0.1/x"));
        assert!(is_safe_url("https://93.184.216.34/webhook"));
    }

    #[test]
    fn reserved_ipv4_ranges_are_rejected() {
        for url in [
            "http://192.0.0.1/hook",
            "http://192.0.2.1/hook",
            "http://198.51.100.1/hook",
            "http://203.0.113.1/hook",
            "http://198.18.0.1/hook",
            "http://198.19.255.255/hook",
            "http://240.0.0.1/hook",
            "http://255.255.255.254/hook",
        ] {
            assert!(!is_safe_url(url), "{url} should be rejected");
        }
        assert!(is_safe_url("https://8.8.8.8/hook"));
    }

    // --- IPv4 Literal Forms (Dotted, Decimal, Hex, Octal) ---
    #[test]
    fn test_ipv4_literal_forms() {
        // Standard dotted decimal loopback
        assert!(!is_safe_url("http://127.0.0.1:9000"));
        assert!(!is_safe_url("http://127.0.0.2/hook"));
        assert!(!is_safe_url("http://127.1.2.3/hook"));

        // Private ranges (RFC 1918)
        assert!(!is_safe_url("http://10.0.0.5/x"));
        assert!(!is_safe_url("http://192.168.1.10/x"));
        assert!(!is_safe_url("http://172.16.5.5/x"));
        assert!(!is_safe_url("http://172.31.255.255/x"));

        // Carrier-grade NAT (100.64.0.0/10)
        assert!(!is_safe_url("http://100.64.5.5/x"));
        assert!(!is_safe_url("http://100.127.255.255/x"));

        // Alternative representations (decimal integer, hex, octal)
        assert!(!is_safe_url("http://2130706433/hook"));
        assert!(!is_safe_url("http://0x7f000001/hook"));
        assert!(!is_safe_url("http://0x7f.0.0.1/hook"));
        assert!(!is_safe_url("http://0177.0.0.1/hook"));
    }

    // --- IPv6 Forms (Loopback, Unique Local) ---
    #[test]
    fn test_ipv6_forms() {
        // Loopback
        assert!(!is_safe_url("http://[::1]/hook"));
        assert!(!is_safe_url("http://[0:0:0:0:0:0:0:1]/hook"));

        // Unique local (fc00::/7)
        assert!(!is_safe_url("http://[fc00::1]/hook"));
        assert!(!is_safe_url("http://[fd00::1]/hook"));
        assert!(!is_safe_url("http://[fd12:3456:789a::1]/hook"));
    }

    // --- IPv4-Mapped and IPv4-Compatible IPv6 Forms ---
    #[test]
    fn test_ipv4_mapped_and_compatible_ipv6_forms() {
        // IPv4-mapped with dotted decimal
        assert!(!is_safe_url("http://[::ffff:127.0.0.1]/hook"));
        assert!(!is_safe_url("http://[::ffff:10.0.0.1]/hook"));
        assert!(!is_safe_url("http://[::ffff:192.168.1.1]/hook"));
        assert!(!is_safe_url("http://[::ffff:169.254.169.254]/hook"));

        // IPv4-mapped with hex representation (7f00:1 == 127.0.0.1)
        assert!(!is_safe_url("http://[::ffff:7f00:1]/hook"));

        // IPv4-compatible
        assert!(!is_safe_url("http://[::127.0.0.1]/hook"));
        assert!(!is_safe_url("http://[::10.0.0.1]/hook"));
    }

    // --- Link-Local Addresses (IPv4 and IPv6) ---
    #[test]
    fn test_link_local_addresses() {
        // IPv4 link-local (169.254.0.0/16 including AWS/cloud metadata)
        assert!(!is_safe_url("http://169.254.169.254/latest/meta-data"));
        assert!(!is_safe_url("http://169.254.1.1/x"));

        // IPv6 link-local (fe80::/10)
        assert!(!is_safe_url("http://[fe80::1]/hook"));
        assert!(!is_safe_url("http://[febf::ffff]/hook"));
    }

    // --- Unspecified Addresses (0.0.0.0 and ::) ---
    #[test]
    fn test_unspecified_addresses() {
        // IPv4 0.0.0.0
        assert!(!is_safe_url("http://0.0.0.0/hook"));
        assert!(!is_safe_url("http://0.0.0.0:8080/hook"));
        assert!(!is_safe_url("http://0/hook"));

        // IPv6 ::
        assert!(!is_safe_url("http://[::]/hook"));
        assert!(!is_safe_url("http://[0:0:0:0:0:0:0:0]/hook"));
    }

    // --- Hostnames, Local Domains, and DNS Boundary Scope ---
    #[test]
    fn test_hostnames_and_dns_scope_boundary() {
        // Obvious local hostnames and mDNS domains are blocked syntactically
        assert!(!is_safe_url("http://localhost/hook"));
        assert!(!is_safe_url("http://localhost:3000/hook"));
        assert!(!is_safe_url("http://app.localhost/hook"));
        assert!(!is_safe_url("http://db.internal.local/x"));
        assert!(!is_safe_url("http://service.local/webhook"));

        // Scope boundary: arbitrary hostnames (e.g., custom domains that might resolve
        // to private IPs via DNS) are permitted by syntactic validation; DNS resolution
        // and rebind protection are explicitly the responsibility of the HTTP client.
        assert!(is_safe_url("https://internal-service.example.com/webhook"));
        assert!(is_safe_url("https://webhook.acme-corp.com/events"));
    }

    // --- Invalid and Malformed URLs ---
    #[test]
    fn test_invalid_and_malformed_urls() {
        assert!(!is_safe_url("ftp://example.com"));
        assert!(!is_safe_url("javascript:alert(1)"));
        assert!(!is_safe_url("not-a-url"));
        assert!(!is_safe_url("http:///empty-host"));
        assert!(!is_safe_url("http://[invalid-ipv6]/hook"));
    }

    #[test]
    fn is_safe_url_rejects_ipv4_mapped_ipv6_loopback() {
        assert!(!is_safe_url("http://[::ffff:127.0.0.1]/hook"));
        // The hex spelling reqwest normalises to — previously slipped past the string check.
        assert!(!is_safe_url("http://[::ffff:7f00:1]/hook"));
        assert!(!is_safe_url("http://[::ffff:10.0.0.1]/hook"));
        assert!(!is_safe_url("http://[::ffff:169.254.169.254]/latest/meta-data"));
        assert!(!is_safe_url("http://[::ffff:a9fe:a9fe]/latest/meta-data"));
    }

    #[test]
    fn is_safe_url_rejects_the_unspecified_address() {
        assert!(!is_safe_url("http://0.0.0.0/hook"));
        assert!(!is_safe_url("http://0.0.0.0:8080/hook"));
        assert!(!is_safe_url("http://[::]/hook"));
        assert!(!is_safe_url("http://[::ffff:0.0.0.0]/hook"));
        // Shorthand forms the URL parser expands to 0.0.0.0 / 127.0.0.1.
        assert!(!is_safe_url("http://0/hook"));
        assert!(!is_safe_url("http://2130706433/hook"));
        assert!(!is_safe_url("http://0x7f.1/hook"));
    }

    #[test]
    fn is_safe_url_still_accepts_a_normal_public_https_url() {
        assert!(is_safe_url("https://api.customer.com/webhooks"));
        assert!(is_safe_url("https://8.8.8.8/hook"));
        assert!(is_safe_url("https://[2606:4700:4700::1111]/hook"));
        assert!(is_safe_url("https://[::ffff:8.8.8.8]/hook"));
    }

    #[test]
    fn blocks_trailing_dot_localhost() {
        assert!(!is_safe_url("http://localhost./hook"));
    }

    #[test]
    fn response_snippet_redacts_secrets_and_caps_size() {
        let body = format!("echo sig=abc123 secret=s3cr3t {}", "x".repeat(4096));
        let snippet = response_snippet(body.as_bytes(), &["abc123", "s3cr3t"]).unwrap();
        assert!(!snippet.contains("abc123") && !snippet.contains("s3cr3t"));
        assert!(snippet.len() <= RESPONSE_SNIPPET_MAX_BYTES);
        assert_eq!(response_snippet(b"", &["abc123"]), None);
    }

    #[test]
    fn response_snippet_truncates_on_a_char_boundary() {
        let body = "é".repeat(RESPONSE_SNIPPET_MAX_BYTES);
        let snippet = response_snippet(body.as_bytes(), &[]).unwrap();
        assert!(snippet.len() <= RESPONSE_SNIPPET_MAX_BYTES);
        assert!(snippet.chars().all(|c| c == 'é'));
    }
}
