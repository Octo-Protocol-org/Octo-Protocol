//! Transactional email behind a pluggable transport, plus OTP generation and hashing.
#![forbid(unsafe_code)]

mod error;
pub mod templates;
mod transport;

pub use error::EmailError;
pub use transport::{
    CaptureTransport, DeliverFuture, Email, EmailTransport, FailingTransport, LogOnlyTransport,
    ResendTransport, SharedTransport,
};

use rand::Rng;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Sends transactional email through whichever [`EmailTransport`] it was built with.
#[derive(Clone)]
pub struct EmailSender {
    transport: SharedTransport,
}

impl EmailSender {
    /// A sender backed by Resend.
    pub fn new(api_key: String, from_address: String) -> Self {
        Self::with_transport(Arc::new(ResendTransport::new(api_key, from_address)))
    }

    pub fn with_transport(transport: SharedTransport) -> Self {
        Self { transport }
    }

    /// A sender that records messages in memory — lets integration tests complete the
    /// signup/withdrawal OTP flow without a real inbox.
    pub fn new_captured() -> Self {
        Self::with_transport(Arc::new(CaptureTransport::default()))
    }

    /// A sender that only logs recipient and subject — for local runs without a provider.
    pub fn new_log_only() -> Self {
        Self::with_transport(Arc::new(LogOnlyTransport))
    }

    /// A sender that always fails — simulates a provider rejection so callers can test their
    /// rollback/error-handling behavior.
    pub fn new_failing() -> Self {
        Self::with_transport(Arc::new(FailingTransport))
    }

    /// The most recently captured OTP for `to`, if the transport retains messages.
    pub fn last_otp_for(&self, to: &str) -> Option<String> {
        self.transport
            .sent()
            .iter()
            .rev()
            .filter(|m| m.to == to)
            .find_map(|m| templates::extract_otp(&m.html))
    }

    /// Send an OTP email.
    pub async fn send_otp(&self, to: &str, purpose: &str, code: &str) -> Result<(), EmailError> {
        let body = templates::otp_email(code, purpose);
        self.send(to, "Your Octo verification code", &body).await
    }

    /// Send one multipart (HTML + plain-text) email. Propagates failure — callers on a critical
    /// path (e.g. an OTP the user has no other way to receive) need to know sending failed.
    pub async fn send(
        &self,
        to: &str,
        subject: &str,
        body: &templates::Body,
    ) -> Result<(), EmailError> {
        let email = Email {
            to: to.to_string(),
            subject: subject.to_string(),
            html: body.html.clone(),
            text: body.text.clone(),
        };
        self.transport.deliver(&email).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // Gross-bug smoke test: asserts digit distribution across 100k samples is roughly uniform (not a crypto audit).
    #[test]
    fn generate_otp_produces_a_roughly_uniform_distribution_of_digits_across_a_large_sample() {
        const SAMPLES: usize = 100_000;
        let mut digit_counts = [[0usize; 10]; 6];

        for _ in 0..SAMPLES {
            let otp = generate_otp();
            assert_eq!(otp.len(), 6, "OTP must always be exactly 6 characters");
            assert!(otp.chars().all(|c| c.is_ascii_digit()), "OTP must only contain digits");

            for (pos, ch) in otp.chars().enumerate() {
                let d = ch.to_digit(10).expect("valid digit") as usize;
                digit_counts[pos][d] += 1;
            }
        }

        // Each digit at each position has expected frequency 10,000; assert within 8,000..=12,000.
        for pos in 0..6 {
            for digit in 0..10 {
                let count = digit_counts[pos][digit];
                assert!(
                    (8_000..=12_000).contains(&count),
                    "digit {digit} at position {pos} occurred {count} times (expected ~10,000)"
                );
            }
        }
    }

    // Gross-bug smoke test: duplicate rate across 100k draws in 1M space matches birthday-paradox expectation.
    #[test]
    fn generate_otp_duplicate_rate_across_a_large_sample_is_consistent_with_true_uniform_randomness() {
        const SAMPLES: usize = 100_000;
        let mut seen = HashSet::with_capacity(SAMPLES);

        for _ in 0..SAMPLES {
            seen.insert(generate_otp());
        }

        // For 100,000 draws from 1,000,000 bins, expected unique is ~95,163 (assert within 92,000..=98,000).
        let unique_count = seen.len();
        assert!(
            (92_000..=98_000).contains(&unique_count),
            "expected ~95,163 unique codes, got {unique_count}"
        );
    }
}
