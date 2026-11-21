//! Shared validation for caller-supplied free text (labels, descriptions, references).
//!
//! These strings are echoed back in the dashboard, audit log and webhooks, so they are bounded in
//! length and stripped of anything that could forge log lines or visually spoof another value.

use crate::error::ApiError;

/// Max characters in a wallet label.
pub const WALLET_LABEL_MAX: usize = 64;
/// Max characters in a wallet description.
pub const WALLET_DESCRIPTION_MAX: usize = 500;
/// Max characters in an address `customer_ref`.
pub const CUSTOMER_REF_MAX: usize = 128;
/// Max characters in an allowlist entry label.
pub const WHITELIST_LABEL_MAX: usize = 64;

/// True for invisible or direction-changing characters that can make one string render as another.
fn is_spoofing_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
}

/// Trim `value`; empty becomes `None`, oversized or control/spoofing characters are a 400.
pub fn clean_text(field: &str, value: &str, max_chars: usize) -> Result<Option<String>, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.chars().count() > max_chars {
        return Err(ApiError::BadRequest(format!(
            "{field} must be at most {max_chars} characters"
        )));
    }
    if trimmed.chars().any(|c| c.is_control() || is_spoofing_char(c)) {
        return Err(ApiError::BadRequest(format!(
            "{field} must not contain control or invisible formatting characters"
        )));
    }
    Ok(Some(trimmed.to_string()))
}

/// [`clean_text`] over an optional value.
pub fn clean_optional(
    field: &str,
    value: Option<&str>,
    max_chars: usize,
) -> Result<Option<String>, ApiError> {
    value.map_or(Ok(None), |v| clean_text(field, v, max_chars))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_and_empties_to_none() {
        assert_eq!(clean_text("label", "  Treasury  ", 64).unwrap().as_deref(), Some("Treasury"));
        assert_eq!(clean_text("label", "   ", 64).unwrap(), None);
    }

    #[test]
    fn rejects_oversized_by_characters_not_bytes() {
        assert!(clean_text("label", &"é".repeat(64), 64).is_ok());
        assert!(clean_text("label", &"a".repeat(65), 64).is_err());
    }

    #[test]
    fn rejects_control_and_spoofing_characters() {
        for bad in [
            "a\nb",
            "a\u{0}b",
            "a\tb",
            "a\u{1b}[31mb",
            "a\u{202E}b",
            "a\u{200B}b",
            "\u{FEFF}a",
            "a\u{00AD}b",
            "a\u{061C}b",
            "a\u{180E}b",
            "a\u{2028}b",
            "a\u{2029}b",
        ] {
            assert!(clean_text("label", bad, 64).is_err(), "{bad:?} must be rejected");
        }
    }
}
