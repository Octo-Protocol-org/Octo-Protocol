//! Email HTML templates. Keep in sync with Octo-frontend's `src/emails/` — that's the
//! hand-maintained source; this is the copy actually sent.

use base64::Engine;

const BURGUNDY: &str = "#7b1733";
const BURGUNDY_BRIGHT: &str = "#b81f4d";
const INK: &str = "#0a0506";

/// Octo's octopus mark, resolved to static colors (no CSS vars — email clients won't resolve them).
fn logo_svg() -> String {
    format!(
        "<svg width=\"40\" height=\"40\" viewBox=\"0 0 512 512\" xmlns=\"http://www.w3.org/2000/svg\">\
<rect width=\"512\" height=\"512\" rx=\"112\" fill=\"{INK}\"/>\
<g stroke=\"{BURGUNDY_BRIGHT}\" stroke-width=\"34\" stroke-linecap=\"round\" stroke-linejoin=\"round\" fill=\"none\">\
<path d=\"M196 286 a92 92 0 1 1 104 -18 c14 26 12 52 -10 74\"/>\
<path d=\"M150 268 c-30 -2 -52 18 -52 44 c0 20 16 34 34 34 c14 0 24 -10 24 -22 c0 -10 -8 -16 -16 -16 c-7 0 -12 5 -12 11\"/>\
<path d=\"M210 300 c-18 18 -26 40 -22 60 c3 16 16 26 30 24 c12 -2 19 -12 17 -23 c-2 -9 -10 -13 -17 -11\"/>\
<path d=\"M268 312 c10 22 8 46 -6 62 c-11 12 -26 13 -36 4 c-9 -8 -9 -20 -1 -27 c7 -6 16 -5 20 1\"/>\
<path d=\"M306 296 c28 6 50 28 50 54 c0 20 -16 34 -34 34 c-14 0 -24 -10 -24 -22 c0 -10 8 -16 16 -16 c7 0 12 5 12 11\"/>\
</g>\
</svg>"
    )
}

fn svg_data_uri(svg: &str) -> String {
    format!(
        "data:image/svg+xml;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(svg)
    )
}

/// A social icon: white glyph on a filled burgundy circle, matching the button's brand color.
fn social_icon(path: &str, href: &str, label: &str) -> String {
    let svg = format!(
        "<svg width=\"32\" height=\"32\" viewBox=\"0 0 32 32\" xmlns=\"http://www.w3.org/2000/svg\">\
<circle cx=\"16\" cy=\"16\" r=\"16\" fill=\"{BURGUNDY}\"/>\
<g transform=\"translate(8,8)\" fill=\"#fff\">{path}</g>\
</svg>"
    );
    let uri = svg_data_uri(&svg);
    format!(
        "<a href=\"{href}\" style=\"display:inline-block;margin:0 6px;text-decoration:none;\" aria-label=\"{label}\"><img src=\"{uri}\" width=\"32\" height=\"32\" alt=\"{label}\" style=\"display:block;border:0;\"/></a>"
    )
}

fn socials() -> String {
    [
        social_icon(
            "<path d=\"M15.3 2.68 9.66 9.15 14.86 16h-2.11l-3.5-4.36L5.15 16H3l6-6.85L3.1 2.68h2.17l3.13 4 3.7-4Z\"/>",
            "https://x.com/Octo_Hq",
            "X (Twitter)",
        ),
        social_icon(
            "<rect width=\"13.5\" height=\"13.5\" x=\"1\" y=\"1\" rx=\"3.5\" fill=\"none\" stroke=\"#fff\" stroke-width=\"1.4\"/><circle cx=\"7.75\" cy=\"7.75\" r=\"3.4\" fill=\"none\" stroke=\"#fff\" stroke-width=\"1.4\"/><circle cx=\"12\" cy=\"4\" r=\"0.8\"/>",
            "https://instagram.com/OctoHQ",
            "Instagram",
        ),
        social_icon(
            "<rect x=\"1\" y=\"1\" width=\"14\" height=\"14\" rx=\"3.5\" fill=\"none\" stroke=\"#fff\" stroke-width=\"1.4\"/><path d=\"M4 6.2v6M4 4.5v.01M7 9v3.2M7 9c0-.8.6-1.4 1.4-1.4S9.8 8.2 9.8 9v3.2M12.5 9v3.2\" stroke=\"#fff\" stroke-width=\"1.4\" stroke-linecap=\"round\" fill=\"none\"/>",
            "https://linkedin.com/company/OctoHQ",
            "LinkedIn",
        ),
        social_icon(
            "<path d=\"M8 .8C3.75.8.3 4.26.3 8.53c0 3.4 2.2 6.3 5.25 7.32.38.07.52-.17.52-.37 0-.19-.01-.68-.01-1.32-2.13.46-2.58-1.03-2.58-1.03-.35-.9-.85-1.13-.85-1.13-.7-.48.05-.47.05-.47.77.05 1.17.79 1.17.79.68 1.18 1.79.84 2.23.64.07-.5.27-.84.49-1.03-1.7-.2-3.48-.86-3.48-3.84 0-.85.3-1.54.78-2.08-.08-.2-.34-.99.07-2.06 0 0 .64-.2 2.08.8a7.15 7.15 0 0 1 3.79 0c1.45-1 2.08-.8 2.08-.8.41 1.07.15 1.86.08 2.06.48.54.77 1.23.77 2.08 0 2.99-1.79 3.64-3.49 3.83.27.24.52.71.52 1.44 0 1.04-.01 1.87-.01 2.13 0 .21.14.45.53.37A7.86 7.86 0 0 0 15.7 8.53C15.7 4.26 12.25.8 8 .8Z\"/>",
            "https://github.com/Octo-Protocol-org",
            "GitHub",
        ),
        social_icon(
            "<path d=\"M15.7 2.35a.8.8 0 0 0-.86-.16L1.2 7.7c-.34.14-.55.46-.53.82.03.36.29.65.65.71l2.33.39 1.95 2.66c.16.22.44.32.7.24.26-.07.45-.29.52-.58l.75-3.08 3.25 2.56c.11.09.25.14.39.14a.79.79 0 0 0 .78-.63l1.59-7.64c.06-.24 0-.5-.14-.7ZM6.93 9.36l-.49 1.81-1.41-1.92 1.9.11Z\"/>",
            "https://t.me/OctoHQ",
            "Telegram",
        ),
    ]
    .join("")
}

/// A purpose icon shown above the body copy: a colored circle badge with a glyph.
enum Icon {
    Key,
    Wave,
    Check,
    Warn,
}

fn icon_svg(icon: Icon) -> String {
    let inner = match icon {
        Icon::Key => format!(
            "<circle cx=\"20\" cy=\"20\" r=\"20\" fill=\"#fff2f5\"/><g transform=\"translate(9,9)\" fill=\"none\" stroke=\"{BURGUNDY_BRIGHT}\" stroke-width=\"1.8\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><circle cx=\"7.5\" cy=\"7.5\" r=\"4.5\"/><path d=\"M11 11l9 9M17 17l2.5-2.5M20 20l2-2\"/></g>"
        ),
        Icon::Wave => format!(
            "<circle cx=\"20\" cy=\"20\" r=\"20\" fill=\"#fff2f5\"/><path d=\"M12 21c1.5-3 3-4.5 5-4.5s3.5 1.5 5 1.5 3.5-1.5 5-4.5\" transform=\"translate(0,1)\" fill=\"none\" stroke=\"{BURGUNDY_BRIGHT}\" stroke-width=\"1.8\" stroke-linecap=\"round\"/><circle cx=\"20\" cy=\"14\" r=\"2.6\" fill=\"{BURGUNDY_BRIGHT}\"/>"
        ),
        Icon::Check => "<circle cx=\"20\" cy=\"20\" r=\"20\" fill=\"#f0fdf4\"/><path d=\"M13 20.5l4.5 4.5L27.5 15\" fill=\"none\" stroke=\"#16a34a\" stroke-width=\"2.4\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>".to_string(),
        Icon::Warn => "<circle cx=\"20\" cy=\"20\" r=\"20\" fill=\"#fff7ed\"/><path d=\"M20 12l9 15H11l9-15Z\" fill=\"none\" stroke=\"#d97706\" stroke-width=\"2\" stroke-linejoin=\"round\"/><path d=\"M20 19v3.5\" stroke=\"#d97706\" stroke-width=\"2\" stroke-linecap=\"round\"/><circle cx=\"20\" cy=\"25.5\" r=\"1.1\" fill=\"#d97706\"/>".to_string(),
    };
    svg_data_uri(&format!(
        "<svg width=\"40\" height=\"40\" viewBox=\"0 0 40 40\" xmlns=\"http://www.w3.org/2000/svg\">{inner}</svg>"
    ))
}

fn shell(body: &str, icon: Icon) -> String {
    let logo_uri = svg_data_uri(&logo_svg());
    let icon_uri = icon_svg(icon);
    let socials = socials();
    let year = chrono::Utc::now().format("%Y");
    format!(
        "<div style=\"font-family:-apple-system,Helvetica,Arial,sans-serif;background:#f5f5f5;padding:32px 0;\">\
<div style=\"max-width:480px;margin:0 auto;background:#fff;border-radius:16px;overflow:hidden;border:1px solid #eee;\">\
<div style=\"text-align:center;padding:28px 32px 20px;\">\
<img src=\"{logo_uri}\" width=\"40\" height=\"40\" alt=\"Octo\" style=\"display:inline-block;border-radius:10px;\"/>\
<div style=\"margin-top:10px;font-size:16px;font-weight:700;color:{INK};letter-spacing:-0.02em;\">Octo</div>\
</div>\
<div style=\"height:1px;background:#eee;\"></div>\
<div style=\"padding:32px;color:#222;font-size:14px;line-height:1.6;text-align:center;\">\
<div style=\"text-align:center;margin-bottom:20px;\"><img src=\"{icon_uri}\" width=\"40\" height=\"40\" alt=\"\" style=\"display:inline-block;\"/></div>\
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
pub fn otp_email(code: &str, purpose: &str) -> String {
    let action = match purpose {
        "withdrawal" => "confirm a withdrawal",
        _ => "verify your email",
    };
    shell(
        &format!(
            "<p style=\"margin:0 0 4px;font-size:18px;font-weight:700;color:#111;\">Your verification code</p>\
<p style=\"margin:0 0 20px;color:#666;\">Use this code to {action}.</p>\
<div style=\"display:inline-block;background:{BURGUNDY_BRIGHT};border-radius:10px;padding:14px 28px;\">\
<span style=\"font-size:30px;font-weight:700;letter-spacing:6px;color:#fff;\">{code}</span>\
</div>\
<p style=\"margin:20px 0 0;color:#999;font-size:12px;\">This code expires in 10 minutes. If you didn't request it, you can ignore this email.</p>"
        ),
        Icon::Key,
    )
}

/// Sent once, right after signup verification succeeds.
pub fn welcome_email(email: &str) -> String {
    shell(
        &format!(
            "<p style=\"margin:0 0 4px;font-size:18px;font-weight:700;color:#111;\">Welcome to Octo 🎉</p>\
<p style=\"margin:0 0 20px;color:#666;\">{email} is verified and ready to go.</p>\
<a href=\"https://app.octo.dev/dashboard\" style=\"display:inline-block;background:{BURGUNDY_BRIGHT};border-radius:10px;padding:12px 28px;color:#fff;font-weight:600;text-decoration:none;font-size:14px;\">Go to dashboard</a>"
        ),
        Icon::Wave,
    )
}

/// Sent after a withdrawal successfully relays to Horizon.
pub fn withdrawal_success_email(
    amount: &str,
    asset: &str,
    destination: &str,
    tx_hash: &str,
) -> String {
    shell(
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
    )
}

/// Sent when a withdrawal was attempted but did not complete (wrong OTP, or Horizon rejected it).
pub fn withdrawal_failed_email(
    amount: &str,
    asset: &str,
    destination: &str,
    reason: &str,
) -> String {
    shell(
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
    )
}
