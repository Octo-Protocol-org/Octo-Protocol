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
                let attempts = if attempts_made > 0 { attempts_made as i32 } else { 1 };
                let _ = self
                    .store
                    .log_webhook_delivery(
                        ep.id,
                        event_type,
                        body,
                        "failed",
                        attempts,
                        last_code,
                    )
                    .await;
                false
            }
        }
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

    #[tokio::test]
    async fn dispatch_bounds_total_delivery_time_for_a_slow_but_non_erroring_endpoint() {
        use axum::routing::post;
        use axum::Router;
        use octo_store::Store;
        use std::time::{Duration, Instant};
        use uuid::Uuid;

        std::env::set_var("OCTO_ALLOW_LOCAL_WEBHOOKS", "1");

        // Mock endpoint that sleeps 150ms on every attempt and returns 500 (triggering retries).
        let app = Router::new().route(
            "/slow",
            post(|| async {
                tokio::time::sleep(Duration::from_millis(150)).await;
                axum::http::StatusCode::INTERNAL_SERVER_ERROR
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/dummy")
            .unwrap();
        let store = Store::from_pool(pool);
        // Set a short per-endpoint delivery timeout ceiling of 200ms.
        let sender = super::WebhookSender::new(store).with_delivery_timeout(Duration::from_millis(200));

        let ep = octo_store::WebhookEndpoint {
            id: Uuid::new_v4(),
            wallet_id: Uuid::new_v4(),
            url: format!("http://{addr}/slow"),
            secret: "secret".into(),
            active: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let body = serde_json::json!({"event": "test"});
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let start = Instant::now();
        let success = sender
            .deliver_with_retry(&ep, "test", &body, &body_bytes)
            .await;
        let elapsed = start.elapsed();

        assert!(!success, "delivery should fail due to overall timeout");
        assert!(
            elapsed < Duration::from_millis(1000),
            "total time should be bounded by delivery ceiling (< 1s), took {:?}",
            elapsed
        );
        assert!(
            elapsed >= Duration::from_millis(150),
            "total time should run at least one attempt (>= 150ms), took {:?}",
            elapsed
        );
    }
}

