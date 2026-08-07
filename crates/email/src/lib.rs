//! Transactional email via Resend, plus OTP generation and hashing.
#![forbid(unsafe_code)]

mod error;
pub mod templates;

pub use error::EmailError;

use rand::Rng;
use sha2::{Digest, Sha256};
use std::time::Duration;

#[cfg(feature = "test-fixtures")]
use std::sync::{Arc, Mutex};

const RESEND_URL: &str = "https://api.resend.com/emails";

/// A captured OTP, recorded instead of actually emailed when using [`EmailSender::new_captured`].
#[cfg(feature = "test-fixtures")]
#[derive(Debug, Clone)]
pub struct CapturedOtp {
    pub to: String,
    pub code: String,
}

/// Sends transactional email via Resend's HTTP API.
#[derive(Clone)]
pub struct EmailSender {
    api_key: String,
    from_address: String,
    http: reqwest::Client,
    #[cfg(feature = "test-fixtures")]
    captured: Option<Arc<Mutex<Vec<CapturedOtp>>>>,
    #[cfg(feature = "test-fixtures")]
    always_fail: bool,
}

impl EmailSender {
    pub fn new(api_key: String, from_address: String) -> Self {
        Self {
            api_key,
            from_address,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            #[cfg(feature = "test-fixtures")]
            captured: None,
            #[cfg(feature = "test-fixtures")]
            always_fail: false,
        }
    }

    /// A sender that records OTP codes in memory instead of calling Resend — lets integration
    /// tests complete the signup/withdrawal OTP flow without a real inbox.
    #[cfg(feature = "test-fixtures")]
    pub fn new_captured() -> Self {
        Self {
            captured: Some(Arc::new(Mutex::new(Vec::new()))),
            ..Self::new(String::new(), "test@octo.test".to_string())
        }
    }

    /// A sender that always fails to send — simulates a Resend rejection (e.g. unverified
    /// domain), so callers can test their rollback/error-handling behavior.
    #[cfg(feature = "test-fixtures")]
    pub fn new_failing() -> Self {
        Self {
            always_fail: true,
            ..Self::new(String::new(), "test@octo.test".to_string())
        }
    }

    /// The most recently captured OTP for `to`, if any. Test-fixtures only.
    #[cfg(feature = "test-fixtures")]
    pub fn last_otp_for(&self, to: &str) -> Option<String> {
        let captured = self.captured.as_ref()?.lock().ok()?;
        captured
            .iter()
            .rev()
            .find(|c| c.to == to)
            .map(|c| c.code.clone())
    }

    /// Send an OTP email. In captured mode, records `code` instead of calling Resend.
    pub async fn send_otp(&self, to: &str, purpose: &str, code: &str) -> Result<(), EmailError> {
        #[cfg(feature = "test-fixtures")]
        if self.always_fail {
            return Err(EmailError::Rejected("simulated failure".into()));
        }
        #[cfg(feature = "test-fixtures")]
        if let Some(captured) = &self.captured {
            captured.lock().unwrap().push(CapturedOtp {
                to: to.to_string(),
                code: code.to_string(),
            });
            return Ok(());
        }
        let html = templates::otp_email(code, purpose);
        self.send(to, "Your Octo verification code", &html).await
    }

    /// Send one HTML email. Logs and propagates failure — callers on a critical path (e.g. an
    /// OTP the user has no other way to receive) need to know sending failed, not just log it.
    pub async fn send(&self, to: &str, subject: &str, html: &str) -> Result<(), EmailError> {
        let body = serde_json::json!({
            "from": self.from_address,
            "to": to,
            "subject": subject,
            "html": html,
        });

        let resp = self
            .http
            .post(RESEND_URL)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await?;

        if resp.status().is_success() {
            return Ok(());
        }
        let detail = resp.text().await.unwrap_or_default();
        tracing::warn!(to, subject, detail, "Resend rejected an email send");
        Err(EmailError::Rejected(detail))
    }
}

/// A fresh 6-digit numeric OTP, zero-padded (e.g. "042817").
pub fn generate_otp() -> String {
    let n: u32 = rand::rngs::OsRng.gen_range(0..1_000_000);
    format!("{n:06}")
}

/// SHA-256 hex digest of an OTP — stored instead of the raw code, same principle as password
/// hashing elsewhere in this codebase.
pub fn hash_otp(code: &str) -> String {
    let digest = Sha256::digest(code.as_bytes());
    hex::encode(digest)
}
