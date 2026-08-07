use thiserror::Error;

/// Errors from sending an email via Resend.
#[derive(Debug, Error)]
pub enum EmailError {
    #[error("request to Resend failed")]
    Request(#[from] reqwest::Error),
    #[error("Resend rejected the request: {0}")]
    Rejected(String),
}
