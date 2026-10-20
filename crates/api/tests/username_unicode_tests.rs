//! Tests for username impersonation via Unicode normalization, confusables, and zero-width
//! characters (#493). These tests guard against homoglyph attacks and ensure that usernames
//! that look identical to humans are rejected at signup and update time.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use octo_api::{build_router, AppState};
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use std::sync::Once;
use tower::ServiceExt;

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

async fn test_state() -> Option<AppState> {
    let url = database_url()?;
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    Some(
        AppState::new(
            store,
            [42u8; 32],
            StellarNetwork::Testnet,
            "https://horizon-testnet.stellar.org".into(),
            None,
            octo_email::EmailSender::new_captured(),
        )
        .with_jwt_secret(b"test-jwt-secret-at-least-16-bytes".to_vec()),
    )
}

fn unique_email() -> String {
    format!("user-{}@octo.test", uuid::Uuid::new_v4().simple())
}

async fn signup_user(app: &axum::Router, state: &AppState) -> String {
    common::signup_and_verify(app, state, &unique_email()).await
}

fn patch_username(token: &str, username: &str) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri("/v1/auth/me")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(Body::from(format!(r#"{{"username":"{}"}}"#, username)))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Unicode confusables / homoglyphs
// ---------------------------------------------------------------------------

/// Latin 'a' vs Cyrillic 'а' (U+0061 vs U+0430) — visually identical but different codepoints.
/// The current ASCII-only validation should reject Cyrillic, but this test documents the
/// expectation that Unicode lookalikes are blocked.
#[tokio::test]
async fn cyrillic_lookalikes_are_rejected() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = signup_user(&app, &state).await;

    // Latin "alice"
    let resp1 = app
        .clone()
        .oneshot(patch_username(&token, "alice"))
        .await
        .unwrap();
    assert_eq!(
        resp1.status(),
        StatusCode::OK,
        "Latin 'alice' should be accepted"
    );

    // Cyrillic "аlice" (first char is Cyrillic 'а' U+0430, rest Latin)
    // Current implementation rejects this because it's not ASCII, which is correct.
    let token2 = signup_user(&app, &state).await;
    let resp2 = app
        .clone()
        .oneshot(patch_username(&token2, "аlice"))
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::BAD_REQUEST,
        "Cyrillic lookalike should be rejected"
    );
}

/// Greek 'ο' (omicron U+03BF) looks like Latin 'o' (U+006F).
#[tokio::test]
async fn greek_omicron_lookalike_rejected() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = signup_user(&app, &state).await;

    // "bobcat" with Greek omicron: "bοbcat"
    let resp = app
        .oneshot(patch_username(&token, "bοbcat"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "Greek omicron lookalike should be rejected (non-ASCII)"
    );
}

// ---------------------------------------------------------------------------
// Zero-width and invisible characters
// ---------------------------------------------------------------------------

/// Zero-width space (U+200B) is invisible but distinct.
/// "alice" + ZWS looks like "alice" but would bypass uniqueness checks if not normalized.
#[tokio::test]
async fn zero_width_space_rejected() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = signup_user(&app, &state).await;

    // Zero-width space (U+200B) embedded in username
    let username_with_zws = "ali\u{200B}ce";
    let resp = app
        .oneshot(patch_username(&token, username_with_zws))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "Username with zero-width space should be rejected"
    );
}

/// Zero-width joiner (U+200D) is used in emoji but is invisible alone.
#[tokio::test]
async fn zero_width_joiner_rejected() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = signup_user(&app, &state).await;

    let username_with_zwj = "bob\u{200D}cat";
    let resp = app
        .oneshot(patch_username(&token, username_with_zwj))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "Username with zero-width joiner should be rejected"
    );
}

/// Zero-width non-joiner (U+200C)
#[tokio::test]
async fn zero_width_non_joiner_rejected() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = signup_user(&app, &state).await;

    let username_with_zwnj = "user\u{200C}name";
    let resp = app
        .oneshot(patch_username(&token, username_with_zwnj))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "Username with zero-width non-joiner should be rejected"
    );
}

// ---------------------------------------------------------------------------
// Mixed-case and case folding
// ---------------------------------------------------------------------------

/// Case folding: "Alice" and "alice" should be treated as the same username.
/// The database has a case-insensitive unique index (`users_username_unique_idx`),
/// so attempting to register both should fail with a conflict.
#[tokio::test]
async fn mixed_case_usernames_conflict() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());

    // First user claims "alice"
    let token1 = signup_user(&app, &state).await;
    let resp1 = app
        .clone()
        .oneshot(patch_username(&token1, "alice"))
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::OK, "First user gets 'alice'");

    // Second user tries "Alice" (different case) — should conflict
    let token2 = signup_user(&app, &state).await;
    let resp2 = app
        .clone()
        .oneshot(patch_username(&token2, "Alice"))
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::BAD_REQUEST,
        "Mixed-case variant should conflict"
    );

    // Third user tries "ALICE" — should also conflict
    let token3 = signup_user(&app, &state).await;
    let resp3 = app
        .oneshot(patch_username(&token3, "ALICE"))
        .await
        .unwrap();
    assert_eq!(
        resp3.status(),
        StatusCode::BAD_REQUEST,
        "Uppercase variant should conflict"
    );
}

/// Case should be preserved for display but ignored for uniqueness.
#[tokio::test]
async fn case_is_preserved_for_display() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = signup_user(&app, &state).await;

    // Set username with mixed case
    let resp = app
        .clone()
        .oneshot(patch_username(&token, "AliceSmith"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Fetch /me and verify the case is preserved
    let me_resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/me")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(me_resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(me_resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        json["data"]["username"].as_str().unwrap(),
        "AliceSmith",
        "Username case should be preserved"
    );
}

// ---------------------------------------------------------------------------
// Unicode normalization (NFC vs NFD)
// ---------------------------------------------------------------------------

/// "é" can be represented as NFC (U+00E9) or NFD (U+0065 U+0301).
/// These should be considered equivalent for uniqueness, but the current ASCII-only
/// validation rejects both forms. This test documents the expected behavior if Unicode
/// usernames are ever allowed.
#[tokio::test]
async fn unicode_normalization_forms_rejected_by_ascii_only_policy() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());

    // NFC form: "café" (U+00E9)
    let token1 = signup_user(&app, &state).await;
    let resp1 = app
        .clone()
        .oneshot(patch_username(&token1, "café"))
        .await
        .unwrap();
    assert_eq!(
        resp1.status(),
        StatusCode::BAD_REQUEST,
        "Non-ASCII 'café' (NFC) should be rejected by current ASCII-only policy"
    );

    // NFD form: "café" (e + combining acute U+0301)
    let token2 = signup_user(&app, &state).await;
    let nfd_cafe = "cafe\u{0301}"; // e + combining acute accent
    let resp2 = app
        .oneshot(patch_username(&token2, nfd_cafe))
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::BAD_REQUEST,
        "Non-ASCII 'café' (NFD) should be rejected by current ASCII-only policy"
    );
}

// ---------------------------------------------------------------------------
// Emoji and special characters
// ---------------------------------------------------------------------------

/// Emoji are rejected by the ASCII-only policy.
#[tokio::test]
async fn emoji_in_username_rejected() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = signup_user(&app, &state).await;

    let resp = app
        .oneshot(patch_username(&token, "alice😀"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "Emoji should be rejected"
    );
}

/// Right-to-left override (U+202E) can reverse text display direction.
#[tokio::test]
async fn rtl_override_rejected() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = signup_user(&app, &state).await;

    // "alice" + RTL override
    let username_with_rtl = "alice\u{202E}";
    let resp = app
        .oneshot(patch_username(&token, username_with_rtl))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "Username with RTL override should be rejected"
    );
}

// ---------------------------------------------------------------------------
// Whitespace and trimming
// ---------------------------------------------------------------------------

/// Leading/trailing whitespace should be trimmed, but internal spaces are not allowed.
#[tokio::test]
async fn leading_and_trailing_whitespace_trimmed() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = signup_user(&app, &state).await;

    // " alice " should be trimmed to "alice"
    let resp = app
        .clone()
        .oneshot(patch_username(&token, "  alice  "))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Leading/trailing spaces should be trimmed and accepted"
    );

    // Verify it was stored as "alice" (trimmed)
    let me_resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/me")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(me_resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        json["data"]["username"].as_str().unwrap(),
        "alice",
        "Username should be trimmed"
    );
}

/// Internal spaces are not allowed per the ASCII alphanumeric + underscore/hyphen rule.
#[tokio::test]
async fn internal_spaces_rejected() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = signup_user(&app, &state).await;

    let resp = app
        .oneshot(patch_username(&token, "alice smith"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "Internal spaces should be rejected"
    );
}

// ---------------------------------------------------------------------------
// Boundary cases
// ---------------------------------------------------------------------------

/// Minimum length: 3 characters
#[tokio::test]
async fn username_minimum_length_enforced() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());
    let token = signup_user(&app, &state).await;

    // 2 chars — too short
    let resp = app
        .clone()
        .oneshot(patch_username(&token, "ab"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "2-char username should be rejected"
    );

    // 3 chars — minimum valid
    let token2 = signup_user(&app, &state).await;
    let resp2 = app
        .oneshot(patch_username(&token2, "abc"))
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::OK,
        "3-char username should be accepted"
    );
}

/// Maximum length: 20 characters
#[tokio::test]
async fn username_maximum_length_enforced() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());

    // 20 chars — maximum valid
    let token1 = signup_user(&app, &state).await;
    let resp1 = app
        .clone()
        .oneshot(patch_username(&token1, "a12345678901234567890".chars().take(20).collect::<String>().as_str()))
        .await
        .unwrap();
    assert_eq!(
        resp1.status(),
        StatusCode::OK,
        "20-char username should be accepted"
    );

    // 21 chars — too long
    let token2 = signup_user(&app, &state).await;
    let resp2 = app
        .oneshot(patch_username(&token2, "a123456789012345678901"))
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::BAD_REQUEST,
        "21-char username should be rejected"
    );
}

// ---------------------------------------------------------------------------
// Reserved usernames (case-insensitive)
// ---------------------------------------------------------------------------

/// Reserved names like "admin", "root", "support" are blocked case-insensitively.
#[tokio::test]
async fn reserved_usernames_blocked_case_insensitively() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());

    let reserved = ["admin", "Admin", "ADMIN", "root", "Root", "support", "SUPPORT"];
    for name in reserved.iter() {
        let token = signup_user(&app, &state).await;
        let resp = app
            .clone()
            .oneshot(patch_username(&token, name))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "Reserved username '{}' should be rejected",
            name
        );
    }
}

/// Non-reserved names that are similar to reserved ones should be accepted.
#[tokio::test]
async fn non_reserved_similar_names_accepted() {
    let Some(state) = test_state().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };
    let app = build_router(state.clone());

    // "admin1", "root_user", "my_support" are not reserved
    let valid = ["admin1", "root_user", "my_support"];
    for name in valid.iter() {
        let token = signup_user(&app, &state).await;
        let resp = app
            .clone()
            .oneshot(patch_username(&token, name))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Non-reserved username '{}' should be accepted",
            name
        );
    }
}
