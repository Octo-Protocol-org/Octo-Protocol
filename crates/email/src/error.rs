use octo_resilience::Retriable;
use thiserror::Error;

/// Errors from sending an email via Resend.
#[derive(Debug, Error)]
pub enum EmailError {
    #[error("request to Resend failed")]
    Request(#[from] reqwest::Error),
    /// A 4xx validation/auth failure — resending the same payload cannot succeed.
    #[error("Resend rejected the request: {0}")]
    Rejected(String),
    /// A 429/5xx response — Resend is overloaded or down, so a later attempt may succeed.
    #[error("Resend is temporarily unavailable: {0}")]
    Unavailable(String),
    /// The overall send deadline (all attempts plus backoff) elapsed.
    #[error("email send exceeded its overall deadline")]
    DeadlineExceeded,
}

impl Retriable for EmailError {
    fn is_retriable(&self) -> bool {
        match self {
            Self::Request(e) => e.is_timeout() || e.is_connect(),
            Self::Unavailable(_) => true,
            Self::Rejected(_) | Self::DeadlineExceeded => false,
        }
    }
}
