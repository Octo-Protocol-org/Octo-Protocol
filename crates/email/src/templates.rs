//! Email HTML templates. Keep in sync with Octo-frontend's `src/emails/` — that's the
//! hand-maintained source; this is the copy actually sent.
//!
//! Images are real HTTPS URLs, not inline data: URIs — Gmail and most clients strip inline
//! data:image/svg+xml (and often data: images generally), so anything shown here has to be
//! fetchable. The logo lives on Cloudinary; the small icon set is served from octohq.org/email/
//! (Octo-frontend's public/email/).
//!
//! ## Escaping convention
//!
//! Every value that originates outside this server — user input (email address, labels), a
//! user-signed transaction (asset code, destination), or a Horizon response (tx hash, error
//! detail) — MUST go through [`html_escape`] before it is interpolated into HTML. Only values
//! the server generates itself (the numeric OTP, the formatted amount, fixed copy) skip it.

/// A rendered message: the styled HTML part and its plain-text alternative.
#[derive(Debug, Clone)]
pub struct Body {
    pub html: String,
    pub text: String,
}

const BURGUNDY: &str = "#7b1733";
const BURGUNDY_BRIGHT: &str = "#b81f4d";
const INK: &str = "#0a0506";

const LOGO_URL: &str =
    "https://res.cloudinary.com/h9jpvcxe/image/upload/v1786115234/octopus_burgundy_black_bg_wrx0sf.png";
const ICON_BASE: &str = "https://octohq.org/email";

/// A purpose icon shown above the body copy: a colored circle badge with a glyph.
enum Icon {
    Key,
    Wave,
    Check,
    Warn,
}

fn icon_url(icon: Icon) -> &'static str {
    match icon {
        Icon::Key => "icon-key.png",
        Icon::Wave => "icon-wave.png",
        Icon::Check => "icon-check.png",
        Icon::Warn => "icon-warn.png",
    }
}

/// A social icon link: white glyph on a filled burgundy circle, matching the button's brand color.
fn social_icon(icon: &str, href: &str, label: &str) -> String {
    format!(
        "<a href=\"{href}\" style=\"display:inline-block;margin:0 6px;text-decoration:none;\" aria-label=\"{label}\"><img src=\"{ICON_BASE}/social-{icon}.png\" width=\"32\" height=\"32\" alt=\"{label}\" style=\"display:block;border:0;\"/></a>"
    )
}

fn socials() -> String {
    [
        social_icon("x", "https://x.com/Octo_Hq", "X (Twitter)"),
        social_icon("instagram", "https://instagram.com/OctoHQ", "Instagram"),
        social_icon(
            "linkedin",
            "https://linkedin.com/company/OctoHQ",
            "LinkedIn",
        ),
        social_icon("github", "https://github.com/Octo-Protocol-org", "GitHub"),
        social_icon("telegram", "https://t.me/OctoHQ", "Telegram"),
    ]
    .join("")
}

/// Escape `&`, `<`, `>`, `"` and `'` so an untrusted value renders as text in HTML body and
/// attribute contexts, never as markup.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Make an untrusted value safe for the plain-text part: control characters (CR/LF included)
/// become spaces so a value can't forge extra lines. No HTML escaping — text/plain isn't markup.
fn text_clean(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

fn text_shell(lines: &[String]) -> String {
    format!(
        "Octo\n\n{}\n\n--\nOcto · Stellar-native wallet infrastructure\n",
        lines.join("\n")
    )
}

fn shell(body: &str, icon: Icon) -> String {
    let icon_url = format!("{ICON_BASE}/{}", icon_url(icon));
    let socials = socials();
    let year = chrono::Utc::now().format("%Y");
    format!(
        "<div style=\"font-family:-apple-system,Helvetica,Arial,sans-serif;background:#f5f5f5;padding:32px 0;\">\
<div style=\"max-width:480px;margin:0 auto;background:#fff;border-radius:16px;overflow:hidden;border:1px solid #eee;\">\
<div style=\"text-align:center;padding:28px 32px 20px;\">\
<img src=\"{LOGO_URL}\" width=\"40\" height=\"40\" alt=\"Octo\" style=\"display:inline-block;border-radius:10px;\"/>\
<div style=\"margin-top:10px;font-size:16px;font-weight:700;color:{INK};letter-spacing:-0.02em;\">Octo</div>\
</div>\
<div style=\"height:1px;background:#eee;\"></div>\
<div style=\"padding:32px;color:#222;font-size:14px;line-height:1.6;text-align:center;\">\
<div style=\"text-align:center;margin-bottom:20px;\"><img src=\"{icon_url}\" width=\"40\" height=\"40\" alt=\"\" style=\"display:inline-block;\"/></div>\
{body}\
</div>\
<div style=\"background:{BURGUNDY};padding:22px 32px;text-align:center;\">\
{socials}\
<p style=\"margin:14px 0 0;color:rgba(255,255,255,0.7);font-size:11px;\">© {year} Octo · Stellar-native wallet infrastructure</p>\
</div>\
</div>\
</div>"
    )
}

/// One-time code email, shared by signup verification and withdrawal confirmation.
pub fn otp_email(code: &str, purpose: &str) -> Body {
    let action = match purpose {
        "withdrawal" => "confirm a withdrawal",
        "password_reset" => "reset your password",
        "email_change" => "confirm your new email address",
        "account_export" => "export your account data",
        "account_delete" => "permanently delete your account",
        _ => "verify your email",
    };
    let html = shell(
        &format!(
            "<p style=\"margin:0 0 4px;font-size:18px;font-weight:700;color:#111;\">Your verification code</p>\
<p style=\"margin:0 0 20px;color:#666;\">Use this code to {action}.</p>\
<div style=\"display:inline-block;background:{BURGUNDY_BRIGHT};border-radius:10px;padding:14px 28px;\">\
<span style=\"font-size:30px;font-weight:700;letter-spacing:6px;color:#fff;\">{code}</span>\
</div>\
<p style=\"margin:20px 0 0;color:#999;font-size:12px;\">This code expires in 10 minutes. If you didn't request it, you can ignore this email.</p>"
        ),
        Icon::Key,
    );
    let text = text_shell(&[
        format!("Your verification code: {code}"),
        format!("Use this code to {action}."),
        "This code expires in 10 minutes. If you didn't request it, you can ignore this email."
            .to_string(),
    ]);
    Body { html, text }
}

/// The OTP inside an [`otp_email`] body, for test transports that capture rendered messages.
pub fn extract_otp(html: &str) -> Option<String> {
    let marker = "letter-spacing:6px;color:#fff;\">";
    let start = html.find(marker)? + marker.len();
    let code = html.get(start..start + 6)?;
    code.bytes().all(|b| b.is_ascii_digit()).then(|| code.to_string())
}

/// Escape untrusted text for interpolation into HTML (emails are only loosely validated).
fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Sent to the OLD address after an email change, so a hijacked change is noticed.
pub fn email_changed_email(new_email: &str) -> Body {
    let raw = text_clean(new_email);
    let new_email = escape_html(new_email);
    let html = shell(
        &format!(
            "<p style=\"margin:0 0 4px;font-size:18px;font-weight:700;color:#111;\">Your login email was changed</p>\
<p style=\"margin:0;color:#666;\">This account's email is now {new_email}. If this wasn't you, reset your password right away.</p>"
        ),
        Icon::Warn,
    );
    let text = text_shell(&[
        "Your login email was changed".to_string(),
        format!("This account's email is now {raw}. If this wasn't you, reset your password right away."),
    ]);
    Body { html, text }
}

/// Sent to the former address once an account deletion completes, so an unwanted one is noticed.
pub fn account_deleted_email() -> String {
    shell(
        "<p style=\"margin:0 0 4px;font-size:18px;font-weight:700;color:#111;\">Your Octo account was deleted</p>\
<p style=\"margin:0;color:#666;\">Your profile, sessions and API keys have been removed. If this wasn't you, contact support immediately.</p>",
        Icon::Warn,
    )
}

/// Sent once, right after signup verification succeeds.
pub fn welcome_email(email: &str) -> Body {
    let raw = text_clean(email);
    // The address is user-supplied at signup; RFC 5322 local parts may legally contain `<"'&`.
    let email = html_escape(email);
    let html = shell(
        &format!(
            "<p style=\"margin:0 0 4px;font-size:18px;font-weight:700;color:#111;\">Welcome to Octo 🎉</p>\
<p style=\"margin:0 0 20px;color:#666;\">{email} is verified and ready to go.</p>\
<a href=\"https://octohq.org/dashboard\" style=\"display:inline-block;background:{BURGUNDY_BRIGHT};border-radius:10px;padding:12px 28px;color:#fff;font-weight:600;text-decoration:none;font-size:14px;\">Go to dashboard</a>"
        ),
        Icon::Wave,
    );
    let text = text_shell(&[
        "Welcome to Octo".to_string(),
        format!("{raw} is verified and ready to go."),
        "Go to dashboard: https://octohq.org/dashboard".to_string(),
    ]);
    Body { html, text }
}

/// Sent after a withdrawal successfully relays to Horizon.
pub fn withdrawal_success_email(
    amount: &str,
    asset: &str,
    destination: &str,
    tx_hash: &str,
) -> Body {
    let (raw_asset, raw_destination, raw_hash) = (
        text_clean(asset),
        text_clean(destination),
        text_clean(tx_hash),
    );
    // Asset and destination come from the user-signed XDR, the hash from Horizon's response.
    let (asset, destination, tx_hash) = (
        html_escape(asset),
        html_escape(destination),
        html_escape(tx_hash),
    );
    let html = shell(
        &format!(
            "<p style=\"margin:0 0 4px;font-size:18px;font-weight:700;color:#111;\">Withdrawal confirmed</p>\
<p style=\"margin:0 0 20px;color:#666;\">Your withdrawal has been confirmed on-chain.</p>\
<div style=\"text-align:left;background:#fafafa;border-radius:10px;padding:16px 20px;font-size:13px;\">\
<p style=\"margin:0 0 8px;\"><strong>Amount:</strong> {amount} {asset}</p>\
<p style=\"margin:0 0 8px;word-break:break-all;\"><strong>Destination:</strong> {destination}</p>\
<p style=\"margin:0;word-break:break-all;\"><strong>Transaction:</strong> {tx_hash}</p>\
</div>"
        ),
        Icon::Check,
    );
    let text = text_shell(&[
        "Withdrawal confirmed".to_string(),
        "Your withdrawal has been confirmed on-chain.".to_string(),
        format!("Amount: {amount} {raw_asset}"),
        format!("Destination: {raw_destination}"),
        format!("Transaction: {raw_hash}"),
    ]);
    Body { html, text }
}

/// Sent when a withdrawal was attempted but did not complete (wrong OTP, or Horizon rejected it).
pub fn withdrawal_failed_email(
    amount: &str,
    asset: &str,
    destination: &str,
    reason: &str,
) -> Body {
    let (raw_asset, raw_destination, raw_reason) = (
        text_clean(asset),
        text_clean(destination),
        text_clean(reason),
    );
    // Asset and destination come from the user-signed XDR, the reason may echo Horizon's detail.
    let (asset, destination, reason) = (
        html_escape(asset),
        html_escape(destination),
        html_escape(reason),
    );
    let html = shell(
        &format!(
            "<p style=\"margin:0 0 4px;font-size:18px;font-weight:700;color:#111;\">Withdrawal attempt failed</p>\
<p style=\"margin:0 0 20px;color:#666;\">A withdrawal attempt on your account did not complete.</p>\
<div style=\"text-align:left;background:#fafafa;border-radius:10px;padding:16px 20px;font-size:13px;\">\
<p style=\"margin:0 0 8px;\"><strong>Amount:</strong> {amount} {asset}</p>\
<p style=\"margin:0 0 8px;word-break:break-all;\"><strong>Destination:</strong> {destination}</p>\
<p style=\"margin:0;\"><strong>Reason:</strong> {reason}</p>\
</div>\
<p style=\"margin:20px 0 0;color:#999;font-size:12px;\">If this wasn't you, secure your account and contact support.</p>"
        ),
        Icon::Warn,
    );
    let text = text_shell(&[
        "Withdrawal attempt failed".to_string(),
        "A withdrawal attempt on your account did not complete.".to_string(),
        format!("Amount: {amount} {raw_asset}"),
        format!("Destination: {raw_destination}"),
        format!("Reason: {raw_reason}"),
        "If this wasn't you, secure your account and contact support.".to_string(),
    ]);
    Body { html, text }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_otp_round_trips_the_rendered_otp_email() {
        assert_eq!(extract_otp(&otp_email("042817", "signup").html).as_deref(), Some("042817"));
        assert_eq!(extract_otp(&welcome_email("a@b.test").html), None);
    }

    const HOSTILE: &str = "<b>\"x\"&'</b>\r\nInjected: yes";

    #[test]
    fn every_template_has_a_text_part_without_markup() {
        let bodies = [
            otp_email("123456", "signup"),
            email_changed_email("a@b.test"),
            welcome_email("a@b.test"),
            withdrawal_success_email("1.0", "USDC", "GDEST", "abc"),
            withdrawal_failed_email("1.0", "USDC", "GDEST", "nope"),
        ];
        for b in bodies {
            assert!(!b.html.is_empty());
            assert!(b.text.contains("Octo") && !b.text.contains("<div"));
        }
    }

    #[test]
    fn html_part_escapes_untrusted_values_and_text_part_strips_line_breaks() {
        let welcome = welcome_email(HOSTILE);
        assert!(!welcome.html.contains("<b>"));
        assert!(!welcome.text.contains('\r') && !welcome.text.contains("\nInjected"));
        let changed = email_changed_email(HOSTILE);
        assert!(!changed.html.contains("<b>"));
        assert!(!changed.text.contains("\nInjected"));
        let ok = withdrawal_success_email("1.0", HOSTILE, HOSTILE, HOSTILE);
        assert!(!ok.html.contains("<b>"));
        assert!(!ok.text.contains("\nInjected"));
        let failed = withdrawal_failed_email("1.0", HOSTILE, HOSTILE, HOSTILE);
        assert!(!failed.html.contains("<b>"));
        assert!(!failed.text.contains("\nInjected"));
    }

    #[test]
    fn text_part_keeps_values_unescaped() {
        let b = welcome_email("o'brien&co@b.test");
        assert!(b.text.contains("o'brien&co@b.test"));
        assert!(b.html.contains("o&#x27;brien&amp;co@b.test"));
    }

    // -------------------------------------------------------------------------
    // #486 – template rendering and HTML-escaping suite
    // -------------------------------------------------------------------------

    // --- html_escape unit tests ---

    #[test]
    fn html_escape_encodes_all_five_special_chars() {
        assert_eq!(html_escape("&"), "&amp;");
        assert_eq!(html_escape("<"), "&lt;");
        assert_eq!(html_escape(">"), "&gt;");
        assert_eq!(html_escape("\""), "&quot;");
        assert_eq!(html_escape("'"), "&#x27;");
    }

    #[test]
    fn html_escape_leaves_safe_chars_unchanged() {
        let safe = "hello world 123 !@#$%^*()-_=+[]{}|;:,.?/`~";
        assert_eq!(html_escape(safe), safe);
    }

    #[test]
    fn html_escape_handles_empty_string() {
        assert_eq!(html_escape(""), "");
    }

    #[test]
    fn html_escape_handles_string_with_all_special_chars_mixed() {
        let input = "<script>alert('xss' & \"injection\")</script>";
        let escaped = html_escape(input);
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert!(!escaped.contains('\''));
        assert!(!escaped.contains('"'));
        assert!(!escaped.contains('&'));
        // Round-trip: escaped must not contain any raw injection characters
        assert!(escaped.contains("&lt;") && escaped.contains("&gt;"));
        assert!(escaped.contains("&#x27;") && escaped.contains("&quot;"));
        assert!(escaped.contains("&amp;"));
    }

    #[test]
    fn html_escape_handles_multibyte_unicode_without_corruption() {
        let input = "こんにちは <world> & \"友\"";
        let escaped = html_escape(input);
        // Unicode chars pass through; only the ASCII specials are substituted.
        assert!(escaped.contains("こんにちは"));
        assert!(escaped.contains("友"));
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
    }

    // --- otp_email ---

    #[test]
    fn otp_email_contains_the_code_verbatim_in_html() {
        let b = otp_email("987654", "signup");
        assert!(b.html.contains("987654"));
        assert!(b.text.contains("987654"));
    }

    #[test]
    fn otp_email_renders_all_recognised_purposes() {
        let purposes = [
            ("withdrawal", "confirm a withdrawal"),
            ("password_reset", "reset your password"),
            ("email_change", "confirm your new email address"),
            ("account_export", "export your account data"),
            ("account_delete", "permanently delete your account"),
            ("signup", "verify your email"),
            ("unknown_purpose", "verify your email"),
        ];
        for (purpose, expected_action) in purposes {
            let b = otp_email("000000", purpose);
            assert!(
                b.html.contains(expected_action),
                "purpose={purpose}: HTML missing expected action text"
            );
            assert!(
                b.text.contains(expected_action),
                "purpose={purpose}: plain text missing expected action text"
            );
        }
    }

    #[test]
    fn otp_email_html_does_not_escape_the_numeric_code() {
        // The OTP is server-generated digits; no escaping should alter it.
        let b = otp_email("123456", "signup");
        assert!(b.html.contains("123456"), "code must appear unmodified in HTML");
    }

    // --- welcome_email ---

    #[test]
    fn welcome_email_escapes_special_chars_in_address() {
        let hostile_addr = "<script>alert(1)</script>@example.com";
        let b = welcome_email(hostile_addr);
        assert!(!b.html.contains("<script>"), "raw <script> must not appear in HTML");
        assert!(b.html.contains("&lt;script&gt;"), "address must be HTML-escaped");
        // Plain-text part: no HTML escaping, but control chars stripped
        assert!(b.text.contains("<script>alert(1)</script>@example.com") || b.text.contains("<script>"),
            "text part should contain the raw address (no HTML escaping)");
    }

    #[test]
    fn welcome_email_escapes_ampersand_in_address() {
        let b = welcome_email("user+tag&test@example.com");
        assert!(b.html.contains("user+tag&amp;test@example.com"));
        assert!(b.text.contains("user+tag&test@example.com"));
    }

    #[test]
    fn welcome_email_strips_newline_injection_in_text_part() {
        let b = welcome_email("user@example.com\nX-Header: injected");
        assert!(!b.text.contains("\nX-Header"), "newline injection must be stripped from text");
    }

    // --- email_changed_email ---

    #[test]
    fn email_changed_escapes_html_in_new_address() {
        let b = email_changed_email("<b>attacker</b>@evil.com");
        assert!(!b.html.contains("<b>"), "raw tags must not appear in HTML");
        assert!(b.html.contains("&lt;b&gt;"), "tags must be HTML-escaped");
    }

    #[test]
    fn email_changed_strips_carriage_return_in_text() {
        let b = email_changed_email("user@example.com\r\nBcc: attacker@evil.com");
        assert!(!b.text.contains('\r'), "CR must be stripped from text part");
    }

    #[test]
    fn email_changed_text_part_mentions_the_new_address() {
        let b = email_changed_email("new@example.com");
        assert!(b.text.contains("new@example.com"));
    }

    // --- withdrawal_success_email ---

    #[test]
    fn withdrawal_success_escapes_hostile_asset_destination_and_hash() {
        let b = withdrawal_success_email("10.00", "<XSS>", "dest&<>", "hash\"val");
        assert!(!b.html.contains("<XSS>"), "raw tag in asset must be escaped");
        assert!(b.html.contains("&lt;XSS&gt;"));
        assert!(!b.html.contains("dest&<>"));
        assert!(b.html.contains("dest&amp;&lt;&gt;"));
        assert!(!b.html.contains("hash\"val"));
        assert!(b.html.contains("hash&quot;val"));
    }

    #[test]
    fn withdrawal_success_text_part_contains_raw_values_without_html_entities() {
        let b = withdrawal_success_email("5.00", "USDC", "GDEST1234", "txhash");
        assert!(b.text.contains("USDC"));
        assert!(b.text.contains("GDEST1234"));
        assert!(b.text.contains("txhash"));
        assert!(!b.text.contains("&amp;"), "text part must not contain HTML entities");
    }

    #[test]
    fn withdrawal_success_text_strips_newline_injection_in_all_fields() {
        let b = withdrawal_success_email(
            "1.00",
            "USDC\nX-Extra: hdr",
            "GDEST\rinjected",
            "hash\ninjected",
        );
        assert!(!b.text.contains("X-Extra"), "newline injection in asset must be stripped");
        assert!(!b.text.contains('\r'), "CR in destination must be stripped");
        assert!(!b.text.contains("hash\ninjected"), "newline in hash must be stripped");
    }

    // --- withdrawal_failed_email ---

    #[test]
    fn withdrawal_failed_escapes_hostile_reason() {
        let b = withdrawal_failed_email("1.00", "USDC", "GDEST", "<script>alert('fail')</script>");
        assert!(!b.html.contains("<script>"), "raw script tag in reason must be escaped");
        assert!(b.html.contains("&lt;script&gt;"));
    }

    #[test]
    fn withdrawal_failed_text_contains_reason_without_html_escaping() {
        let b = withdrawal_failed_email("1.00", "USDC", "GDEST", "op_bad_auth & timeout");
        assert!(b.text.contains("op_bad_auth & timeout"));
        assert!(!b.text.contains("&amp;"), "text must not HTML-escape the reason");
    }

    // --- account_deleted_email ---

    #[test]
    fn account_deleted_email_returns_non_empty_html() {
        let html = account_deleted_email();
        assert!(!html.is_empty());
        assert!(html.contains("deleted"), "should mention deletion");
    }

    // --- Cross-template: all HTML outputs must close every opened tag ---

    #[test]
    fn all_templates_produce_html_containing_div_and_closing_div() {
        let bodies = [
            otp_email("000000", "signup").html,
            email_changed_email("a@b.test").html,
            welcome_email("user@example.com").html,
            withdrawal_success_email("1.0", "XLM", "GDEST", "abc123").html,
            withdrawal_failed_email("1.0", "XLM", "GDEST", "error").html,
            account_deleted_email(),
        ];
        for html in &bodies {
            let opens = html.matches("<div").count();
            let closes = html.matches("</div>").count();
            assert_eq!(opens, closes, "unbalanced <div> tags in template output");
        }
    }

    // --- extract_otp ---

    #[test]
    fn extract_otp_returns_none_for_empty_string() {
        assert_eq!(extract_otp(""), None);
    }

    #[test]
    fn extract_otp_returns_none_when_marker_absent() {
        assert_eq!(extract_otp("<html>no otp here</html>"), None);
    }

    #[test]
    fn extract_otp_returns_none_when_code_is_not_all_digits() {
        // Forge a marker but with a non-digit payload
        let fake = format!("{}abcdef", "letter-spacing:6px;color:#fff;\">");
        assert_eq!(extract_otp(&fake), None);
    }
}
