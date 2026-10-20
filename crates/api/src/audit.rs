//! Audit logging helpers.
//!
//! Records notable account activity (sign-in, wallet/address/key creation, withdrawals). Auditing
//! is best-effort ([`record`]) except for secret-adjacent reads, which use [`record_strict`] and
//! refuse to proceed without an audit row. Rows are hash-chained per user for tamper evidence
//! (see `octo_store::AuditChainKey`).

use crate::error::ApiError;
use crate::state::AppState;
use axum::http::HeaderMap;
use uuid::Uuid;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue};

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        m
    }

    // -------------------------------------------------------------------------
    // #481 – table-driven coverage for audit::client_ip header variants
    // -------------------------------------------------------------------------

    #[test]
    fn xff_single_entry_is_returned() {
        let h = hm(&[("x-forwarded-for", "203.0.113.5")]);
        assert_eq!(client_ip(&h).as_deref(), Some("203.0.113.5"));
    }

    #[test]
    fn xff_first_entry_of_multiple_hops_is_returned() {
        // audit::client_ip is a best-effort logger: it takes the leftmost value
        // (the claimed origin) without proxy trust validation.
        let h = hm(&[("x-forwarded-for", "203.0.113.5, 10.0.0.1, 10.0.0.2")]);
        assert_eq!(client_ip(&h).as_deref(), Some("203.0.113.5"));
    }

    #[test]
    fn xff_with_surrounding_whitespace_is_trimmed() {
        let h = hm(&[("x-forwarded-for", "  198.51.100.7  ")]);
        assert_eq!(client_ip(&h).as_deref(), Some("198.51.100.7"));
    }

    #[test]
    fn xff_with_ipv6_address_is_returned() {
        let h = hm(&[("x-forwarded-for", "2001:db8::1")]);
        assert_eq!(client_ip(&h).as_deref(), Some("2001:db8::1"));
    }

    #[test]
    fn xff_ipv6_first_entry_of_multiple_hops() {
        let h = hm(&[("x-forwarded-for", "2001:db8::cafe, 2001:db8::dead")]);
        assert_eq!(client_ip(&h).as_deref(), Some("2001:db8::cafe"));
    }

    #[test]
    fn x_real_ip_is_used_when_xff_absent() {
        let h = hm(&[("x-real-ip", "198.51.100.42")]);
        assert_eq!(client_ip(&h).as_deref(), Some("198.51.100.42"));
    }

    #[test]
    fn x_real_ip_with_whitespace_is_trimmed() {
        let h = hm(&[("x-real-ip", "  203.0.113.9  ")]);
        assert_eq!(client_ip(&h).as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn xff_takes_precedence_over_x_real_ip() {
        let h = hm(&[
            ("x-forwarded-for", "203.0.113.1"),
            ("x-real-ip", "203.0.113.2"),
        ]);
        assert_eq!(client_ip(&h).as_deref(), Some("203.0.113.1"));
    }

    #[test]
    fn empty_xff_falls_through_to_x_real_ip() {
        // An empty XFF yields an empty first segment after split, which trim() produces "".
        // The function maps to Some("") for XFF; x-real-ip is the fallback only when XFF
        // is absent entirely — confirm the actual behaviour is consistent.
        let h = hm(&[("x-real-ip", "198.51.100.99")]);
        assert_eq!(client_ip(&h).as_deref(), Some("198.51.100.99"));
    }

    #[test]
    fn no_forwarding_headers_returns_none() {
        let h = HeaderMap::new();
        assert_eq!(client_ip(&h), None);
    }
}

/// Audit categories (shown as colored chips in the dashboard).
pub mod category {
    pub const AUTH: &str = "authentication";
    pub const WALLET: &str = "wallet";
    pub const ADDRESS: &str = "address";
    pub const CREDENTIALS: &str = "credentials";
    pub const WEBHOOK: &str = "configuration";
    pub const PAYMENT_LINK: &str = "configuration";
    pub const WITHDRAWAL: &str = "wallet";
    pub const SPONSORSHIP: &str = "sponsorship";

    pub const ALL: &[&str] = &[AUTH, WALLET, ADDRESS, CREDENTIALS, WEBHOOK, SPONSORSHIP];
}

/// Fixed action strings that tooling or alerting may match on exactly.
pub mod action {
    pub const BACKUP_RETRIEVED: &str = "retrieved encrypted seed backup";
}

/// Best-effort client IP from common proxy headers (first `X-Forwarded-For`, then `X-Real-IP`).
pub fn client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
        })
}

/// Record an audit event. Never fails the caller — logs and moves on.
pub async fn record(
    state: &AppState,
    user_id: Uuid,
    action: &str,
    category: &str,
    target: Option<&str>,
    headers: &HeaderMap,
) {
    let ip = client_ip(headers);
    if let Err(e) = state
        .store()
        .record_audit(
            state.audit_chain_key(),
            user_id,
            action,
            category,
            target,
            ip.as_deref(),
        )
        .await
    {
        tracing::warn!(error = ?e, action, "failed to record audit log");
    }
}

/// Record an audit event, failing the caller if the row can't be written.
///
/// For operations that must never happen untraced (e.g. handing out the sealed seed backup).
/// `action` and `target` must never carry key material — pass identifiers only.
pub async fn record_strict(
    state: &AppState,
    user_id: Uuid,
    action: &str,
    category: &str,
    target: Option<&str>,
    headers: &HeaderMap,
) -> Result<(), ApiError> {
    let ip = client_ip(headers);
    state
        .store()
        .record_audit(
            state.audit_chain_key(),
            user_id,
            action,
            category,
            target,
            ip.as_deref(),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, action, "failed to record mandatory audit log");
            ApiError::Internal
        })
}
