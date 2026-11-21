//! Delivery backends behind [`EmailTransport`]: Resend for production, plus capture, log-only and
//! failing fakes that need no feature flags.

use crate::EmailError;
use octo_resilience::{execute, CallKind, CircuitBreaker, ResilienceError, RetryPolicy};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const RESEND_URL: &str = "https://api.resend.com/emails";
/// Hard cap on one `deliver` call across every attempt and backoff sleep.
const SEND_DEADLINE: Duration = Duration::from_secs(25);

/// One outbound message.
#[derive(Clone)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub html: String,
    /// Plain-text alternative sent as the second multipart part.
    pub text: String,
}

// Manual Debug: the body can carry an OTP, so only routing metadata is ever formatted.
impl std::fmt::Debug for Email {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Email")
            .field("to", &self.to)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

/// Boxed future so the trait stays object-safe without an `async-trait` dependency.
pub type DeliverFuture<'a> = Pin<Box<dyn Future<Output = Result<(), EmailError>> + Send + 'a>>;

/// A backend that can deliver an [`Email`].
pub trait EmailTransport: Send + Sync {
    /// Deliver one message, returning an error the caller can act on if it could not be sent.
    fn deliver<'a>(&'a self, email: &'a Email) -> DeliverFuture<'a>;

    /// Messages retained for inspection; empty for transports that don't keep any.
    fn sent(&self) -> Vec<Email> {
        Vec::new()
    }
}

/// Sends via Resend's HTTP API, retrying transient failures within a bounded deadline.
pub struct ResendTransport {
    api_key: String,
    from_address: String,
    http: reqwest::Client,
    endpoint: String,
    policy: RetryPolicy,
    circuit: CircuitBreaker,
}

impl ResendTransport {
    pub fn new(api_key: String, from_address: String) -> Self {
        Self {
            api_key,
            from_address,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            endpoint: RESEND_URL.to_string(),
            policy: RetryPolicy::default(),
            // High threshold: email outages shouldn't lock out sends for unrelated users for long.
            circuit: CircuitBreaker::new(20, Duration::from_secs(10)),
        }
    }

    /// One POST to Resend, classifying the response as success, transient or permanent.
    async fn post_once(&self, email: &Email) -> Result<(), EmailError> {
        let body = serde_json::json!({
            "from": self.from_address,
            "to": email.to,
            "subject": email.subject,
            "html": email.html,
            "text": email.text,
        });

        let resp = self
            .http
            .post(&self.endpoint)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let detail = resp.text().await.unwrap_or_default();
        tracing::warn!(to = %email.to, subject = %email.subject, %status, detail, "Resend rejected an email send");
        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            Err(EmailError::Unavailable(detail))
        } else {
            Err(EmailError::Rejected(detail))
        }
    }
}

impl EmailTransport for ResendTransport {
    fn deliver<'a>(&'a self, email: &'a Email) -> DeliverFuture<'a> {
        Box::pin(async move {
            let attempts = execute(&self.circuit, &self.policy, CallKind::ReadOnly, || {
                self.post_once(email)
            });
            match tokio::time::timeout(SEND_DEADLINE, attempts).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(ResilienceError::Exhausted(e))) => Err(e),
                Ok(Err(ResilienceError::Circuit)) => {
                    Err(EmailError::Unavailable("circuit breaker open".into()))
                }
                Err(_) => Err(EmailError::DeadlineExceeded),
            }
        })
    }
}

/// Records messages in memory instead of sending them — for tests and local runs.
#[derive(Default)]
pub struct CaptureTransport {
    messages: Mutex<Vec<Email>>,
}

impl EmailTransport for CaptureTransport {
    fn deliver<'a>(&'a self, email: &'a Email) -> DeliverFuture<'a> {
        Box::pin(async move {
            self.messages.lock().unwrap().push(email.clone());
            Ok(())
        })
    }

    fn sent(&self) -> Vec<Email> {
        self.messages.lock().unwrap().clone()
    }
}

/// Logs recipient and subject only (never the body, which may hold an OTP) and drops the message.
pub struct LogOnlyTransport;

impl EmailTransport for LogOnlyTransport {
    fn deliver<'a>(&'a self, email: &'a Email) -> DeliverFuture<'a> {
        Box::pin(async move {
            tracing::info!(to = %email.to, subject = %email.subject, "email not sent (log-only transport)");
            Ok(())
        })
    }
}

/// Always rejects — simulates a provider refusal (e.g. unverified domain) for rollback tests.
pub struct FailingTransport;

impl EmailTransport for FailingTransport {
    fn deliver<'a>(&'a self, _email: &'a Email) -> DeliverFuture<'a> {
        Box::pin(async { Err(EmailError::Rejected("simulated failure".into())) })
    }
}

/// Shared handle type used by [`crate::EmailSender`].
pub type SharedTransport = Arc<dyn EmailTransport>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Serve `statuses` in order, one per connection, counting the requests received.
    async fn mock_resend(statuses: Vec<u16>) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/emails", listener.local_addr().unwrap());
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let n = counter.fetch_add(1, Ordering::SeqCst);
                let status = statuses.get(n).copied().unwrap_or(500);
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let resp = format!("HTTP/1.1 {status} X\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}");
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        (url, hits)
    }

    fn msg() -> Email {
        Email { to: "u@x.test".into(), subject: "s".into(), html: "<p>h</p>".into(), text: "h".into() }
    }

    fn fast_sender(endpoint: String) -> ResendTransport {
        let mut s = ResendTransport::new("k".into(), "a@b.test".into());
        s.endpoint = endpoint;
        s.policy = RetryPolicy {
            base_delay_ms: 1,
            max_delay_ms: 5,
            ..Default::default()
        };
        s
    }

    #[tokio::test]
    async fn send_retries_transient_failures_until_success() {
        let (url, hits) = mock_resend(vec![503, 429, 200]).await;
        fast_sender(url).deliver(&msg()).await.unwrap();
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn send_never_retries_a_4xx_validation_failure() {
        let (url, hits) = mock_resend(vec![422, 200]).await;
        let err = fast_sender(url).deliver(&msg()).await.unwrap_err();
        assert!(matches!(err, EmailError::Rejected(_)));
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn send_gives_up_after_max_attempts_on_persistent_5xx() {
        let (url, hits) = mock_resend(vec![500, 500, 500, 200]).await;
        let err = fast_sender(url).deliver(&msg()).await.unwrap_err();
        assert!(matches!(err, EmailError::Unavailable(_)));
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 3);
    }
}
