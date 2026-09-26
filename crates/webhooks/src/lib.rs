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

use octo_store::Store;
use serde_json::json;
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

/// Sends signed webhooks for a wallet's active endpoints, with retry + delivery logging.
#[derive(Clone)]
pub struct WebhookSender {
    store: Store,
    http: reqwest::Client,
    max_attempts: u32,
    delivery_timeout: Duration,
}

impl WebhookSender {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            max_attempts: 3,
            delivery_timeout: DEFAULT_DELIVERY_TIMEOUT,
        }
    }

    /// Set a custom total delivery timeout ceiling per endpoint attempt (default is 20s).
    pub fn with_delivery_timeout(mut self, timeout: Duration) -> Self {
        self.delivery_timeout = timeout;
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
        let body_bytes = serde_json::to_vec(&body).unwrap_or_default();

        let mut delivered = 0;
        for ep in endpoints {
            if !is_safe_url(&ep.url) {
                tracing::warn!(url = %ep.url, "skipping webhook to unsafe URL");
                let _ = self
                    .store
                    .log_webhook_delivery(ep.id, &event.event_type, &body, "failed", 0, None)
                    .await;
                continue;
            }
            if self
                .deliver_with_retry(&ep, &event.event_type, &body, &body_bytes)
                .await
            {
                delivered += 1;
            }
        }
        delivered
    }

    /// Try to deliver to one endpoint, retrying with backoff. Logs the final outcome.
    async fn deliver_with_retry(
        &self,
        ep: &octo_store::WebhookEndpoint,
        event_type: &str,
        body: &serde_json::Value,
        body_bytes: &[u8],
    ) -> bool {
        let signature = sign::sign(ep.secret.as_bytes(), body_bytes);
        let mut last_code: Option<i32> = None;
        let mut attempts_made = 0;

        let res = tokio::time::timeout(self.delivery_timeout, async {
            for attempt in 1..=self.max_attempts {
                attempts_made = attempt;
                let resp = self
                    .http
                    .post(&ep.url)
                    .header("content-type", "application/json")
                    .header(sign::SIGNATURE_HEADER, &signature)
                    .body(body_bytes.to_vec())
                    .send()
                    .await;

                match resp {
                    Ok(r) => {
                        let code = r.status().as_u16() as i32;
                        last_code = Some(code);
                        if r.status().is_success() {
                            return Ok(attempt);
                        }
                    }
                    Err(_) => last_code = None,
                }

                if attempt < self.max_attempts {
                    // Exponential backoff: 1s, 2s, ...
                    tokio::time::sleep(Duration::from_secs(1 << (attempt - 1))).await;
                }
            }
            Err(())
        })
        .await;

        match res {
            Ok(Ok(successful_attempt)) => {
                let _ = self
                    .store
                    .log_webhook_delivery(
                        ep.id,
                        event_type,
                        body,
                        "delivered",
                        successful_attempt as i32,
                        last_code,
                    )
                    .await;
                true
            }
            Ok(Err(())) => {
                let _ = self
                    .store
                    .log_webhook_delivery(
                        ep.id,
                        event_type,
                        body,
                        "failed",
                        self.max_attempts as i32,
                        last_code,
                    )
                    .await;
                false
            }
            Err(_) => {
                tracing::warn!(
                    endpoint_id = %ep.id,
                    url = %ep.url,
                    timeout_secs = self.delivery_timeout.as_secs(),
                    "webhook delivery attempt exceeded overall deadline"
                );
                let attempts = if attempts_made > 0 {
                    attempts_made as i32
                } else {
                    1
                };
                let _ = self
                    .store
                    .log_webhook_delivery(ep.id, event_type, body, "failed", attempts, last_code)
                    .await;
                false
            }
        }
    }
}

/// Reject obviously-internal webhook targets (defense-in-depth against SSRF). Only `http`/`https`
/// to non-loopback, non-private hosts are allowed.
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
    let allow_local = std::env::var("OCTO_ALLOW_LOCAL_WEBHOOKS").as_deref() == Ok("1");
    if allow_local {
        return true;
    }
    // Extract host between scheme and the next delimiter.
    let after_scheme = match lower.split_once("://") {
        Some((_, rest)) => rest,
        None => return false,
    };
    // Extract bracketed IPv6 literal before splitting on port colons.
    let host: &str = if let Some(rest) = after_scheme.strip_prefix('[') {
        match rest.split_once(']') {
            Some((inside, _)) => inside,
            None => return false,
        }
    } else {
        after_scheme
            .split(['/', ':', '?', '#'])
            .next()
            .unwrap_or("")
    };

    if host.is_empty() {
        return false;
    }

    // Block well-known local hostnames and mDNS domains.
    if host == "localhost"
        || host.ends_with(".localhost")
        || host == "local"
        || host.ends_with(".local")
    {
        return false;
    }

    // Check if host is a valid IPv6 literal.
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        return !is_unsafe_ipv6(v6);
    }

    // Check if host matches lenient IPv4 representations.
    if let Some(v4) = parse_ipv4_lenient(host) {
        return !is_unsafe_ipv4(v4);
    }

    true
}

/// Helper to parse IPv4 addresses in dotted-decimal, octal, hex, or raw integer representations.
fn parse_ipv4_lenient(s: &str) -> Option<std::net::Ipv4Addr> {
    // Raw integer IPv4 representation (e.g. 2130706433 or 0).
    if let Ok(num) = s.parse::<u32>() {
        return Some(std::net::Ipv4Addr::from(num));
    }
    // Raw hex integer IPv4 representation (e.g. 0x7f000001).
    if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if let Ok(num) = u32::from_str_radix(hex_str, 16) {
            return Some(std::net::Ipv4Addr::from(num));
        }
    }
    // Dotted 4-octet representation with potential decimal, octal, or hex segments.
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4 {
        let mut octets = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            let val = if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
                u32::from_str_radix(hex, 16).ok()?
            } else if part.len() > 1 && part.starts_with('0') {
                u32::from_str_radix(part, 8).ok()?
            } else {
                part.parse::<u32>().ok()?
            };
            if val > 255 {
                return None;
            }
            octets[i] = val as u8;
        }
        return Some(std::net::Ipv4Addr::from(octets));
    }
    None
}

/// Returns true if an IPv4 address is in a private, loopback, link-local, unspecified, or broadcast range.
fn is_unsafe_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 0.0.0.0/8 (unspecified / this network)
    octets[0] == 0
    // 127.0.0.0/8 (loopback)
    || octets[0] == 127
    // 10.0.0.0/8 (private)
    || octets[0] == 10
    // 172.16.0.0/12 (private: 172.16.x.x - 172.31.x.x)
    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
    // 192.168.0.0/16 (private)
    || (octets[0] == 192 && octets[1] == 168)
    // 169.254.0.0/16 (link-local, cloud metadata)
    || (octets[0] == 169 && octets[1] == 254)
    // 100.64.0.0/10 (carrier-grade NAT)
    || (octets[0] == 100 && (64..=127).contains(&octets[1]))
    // Broadcast 255.255.255.255
    || ip.is_broadcast()
}

/// Returns true if an IPv6 address is in a private, loopback, link-local, unspecified, or mapped unsafe range.
fn is_unsafe_ipv6(ip: std::net::Ipv6Addr) -> bool {
    // Loopback ::1
    if ip.is_loopback() {
        return true;
    }
    // Unspecified ::
    if ip.is_unspecified() {
        return true;
    }
    // IPv4-mapped IPv6 address (e.g. ::ffff:127.0.0.1 or ::ffff:7f00:1)
    if let Some(v4) = ip.to_ipv4_mapped() {
        if is_unsafe_ipv4(v4) {
            return true;
        }
    }
    // IPv4-compatible IPv6 address (deprecated, e.g. ::127.0.0.1)
    if let Some(v4) = ip.to_ipv4() {
        if is_unsafe_ipv4(v4) {
            return true;
        }
    }
    let segs = ip.segments();
    // Link-local: fe80::/10 (fe80..febf)
    if (segs[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // Unique-local: fc00::/7 (fc00..fdff)
    if (segs[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::is_safe_url;

    // --- Standard Public URLs ---
    #[test]
    fn test_standard_public_urls() {
        assert!(is_safe_url("https://api.customer.com/webhooks"));
        assert!(is_safe_url("http://example.org:8080/hook"));
        assert!(is_safe_url("http://172.15.0.1/x"));
        assert!(is_safe_url("http://172.32.0.1/x"));
        assert!(is_safe_url("https://93.184.216.34/webhook"));
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
}
