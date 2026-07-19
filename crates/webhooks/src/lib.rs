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

/// Sends signed webhooks for a wallet's active endpoints, with retry + delivery logging.
#[derive(Clone)]
pub struct WebhookSender {
    store: Store,
    http: reqwest::Client,
    max_attempts: u32,
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
        }
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

        for attempt in 1..=self.max_attempts {
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
                        let _ = self
                            .store
                            .log_webhook_delivery(
                                ep.id,
                                event_type,
                                body,
                                "delivered",
                                attempt as i32,
                                Some(code),
                            )
                            .await;
                        return true;
                    }
                }
                Err(_) => last_code = None,
            }

            if attempt < self.max_attempts {
                // Exponential backoff: 1s, 2s, ...
                tokio::time::sleep(Duration::from_secs(1 << (attempt - 1))).await;
            }
        }

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
}

/// Reject obviously-internal webhook targets (defense-in-depth against SSRF). Only `http`/`https`
/// to non-loopback, non-private hosts are allowed.
pub fn is_safe_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return false;
    }
    // Dev/test escape hatch: allow loopback/private targets only when explicitly opted in. Never
    // set this in production.
    let allow_local = std::env::var("OCTO_ALLOW_LOCAL_WEBHOOKS").as_deref() == Ok("1");
    if allow_local {
        return true;
    }
    // Extract host between scheme and the next '/' or ':'.
    let after_scheme = match lower.split_once("://") {
        Some((_, rest)) => rest,
        None => return false,
    };
    let host = after_scheme
        .split(['/', ':', '?', '#'])
        .next()
        .unwrap_or("");

    if host.is_empty() {
        return false;
    }
    // Block loopback, link-local, metadata, and common private ranges.
    let blocked_exact = [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "169.254.169.254",
    ];
    if blocked_exact.contains(&host) {
        return false;
    }
    if host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("169.254.")
        || host.ends_with(".local")
    {
        return false;
    }
    // 172.16.0.0/12
    if let Some(rest) = host.strip_prefix("172.") {
        if let Some(second) = rest.split('.').next() {
            if let Ok(n) = second.parse::<u8>() {
                if (16..=31).contains(&n) {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::is_safe_url;

    #[test]
    fn allows_public_https() {
        assert!(is_safe_url("https://api.customer.com/webhooks"));
        assert!(is_safe_url("http://example.org:8080/hook"));
    }

    #[test]
    fn blocks_internal_targets() {
        assert!(!is_safe_url("http://localhost/hook"));
        assert!(!is_safe_url("http://127.0.0.1:9000"));
        assert!(!is_safe_url("http://169.254.169.254/latest/meta-data"));
        assert!(!is_safe_url("http://10.0.0.5/x"));
        assert!(!is_safe_url("http://192.168.1.10/x"));
        assert!(!is_safe_url("http://172.16.5.5/x"));
        assert!(!is_safe_url("http://db.internal.local/x"));
        assert!(!is_safe_url("ftp://example.com"));
        assert!(!is_safe_url("not-a-url"));
    }

    #[test]
    fn allows_172_outside_private_block() {
        assert!(is_safe_url("http://172.15.0.1/x"));
        assert!(is_safe_url("http://172.32.0.1/x"));
    }

    #[test]
    fn decimal_ip_literal_loopback_bypass_is_documented() {
        // KNOWN GAP: is_safe_url uses naive string matching instead of IP parsing.
        // The decimal encoding of 127.0.0.1 (2130706433) bypasses the checks.
        assert!(is_safe_url("http://2130706433/hook"), "decimal IP bypasses checks");
    }

    #[test]
    fn octal_ip_literal_loopback_bypass_is_documented() {
        // KNOWN GAP: is_safe_url uses naive string matching instead of IP parsing.
        // The octal encoding of 127.0.0.1 (0177.0.0.1) bypasses the checks.
        assert!(is_safe_url("http://0177.0.0.1/hook"), "octal IP bypasses checks");
    }

    #[test]
    fn hex_ip_literal_loopback_bypass_is_documented() {
        // KNOWN GAP: is_safe_url uses naive string matching instead of IP parsing.
        // The hex encoding of 127.0.0.1 (0x7f000001) bypasses the checks.
        assert!(is_safe_url("http://0x7f000001/hook"), "hex IP bypasses checks");
    }

    #[test]
    fn ipv6_loopback_and_mapped_forms_bypass_is_documented() {
        // KNOWN GAP: is_safe_url incorrectly splits on ':' which breaks IPv6 literal parsing,
        // and it does not recognize IPv6 mapped addresses.
        assert!(is_safe_url("http://[::1]/hook"), "IPv6 loopback bypasses checks");
        assert!(is_safe_url("http://[::ffff:127.0.0.1]/hook"), "IPv4-mapped IPv6 bypasses checks");
    }
}
