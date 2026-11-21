//! HMAC-SHA256 signing of webhook payloads.
//!
//! Each delivery is signed with the endpoint's secret over the exact bytes of the JSON body. The
//! signature is sent in the `X-Octo-Signature` header as lowercase hex. Consumers recompute the
//! HMAC over the received body and compare in constant time to authenticate the webhook.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// The HTTP header carrying the signature.
pub const SIGNATURE_HEADER: &str = "X-Octo-Signature";

/// Compute the lowercase-hex HMAC-SHA256 of `body` under `secret`.
pub fn sign(secret: &[u8], body: &[u8]) -> String {
    // `new_from_slice` accepts any key length and never errors for HMAC.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// Verify a hex signature against `body` using a constant-time comparison.
///
/// This must never be reimplemented as a variable-time `==` comparison of decoded bytes (or of
/// the hex strings themselves). `secret` is a shared HMAC key: a byte-at-a-time early-exit
/// comparison leaks timing information that lets an attacker recover it one byte at a time over
/// repeated requests. `mac.verify_slice` (via the `subtle` crate through `hmac`/`crypto-mac`) is
/// constant-time and must remain the comparison primitive here.
pub fn verify(secret: &[u8], body: &[u8], signature_hex: &str) -> bool {
    let Ok(sig) = hex::decode(signature_hex) else {
        return false;
    };
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    mac.verify_slice(&sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_roundtrips() {
        let secret = b"shh-secret";
        let body = br#"{"event":"deposit.created","amount":"5"}"#;
        let sig = sign(secret, body);
        assert!(verify(secret, body, &sig));
    }

    #[test]
    fn tampered_body_fails_verification() {
        let secret = b"shh-secret";
        let sig = sign(secret, b"original");
        assert!(!verify(secret, b"tampered", &sig));
    }

    #[test]
    fn wrong_secret_fails_verification() {
        let sig = sign(b"key-a", b"body");
        assert!(!verify(b"key-b", b"body", &sig));
    }

    #[test]
    fn garbage_signature_is_rejected() {
        assert!(!verify(b"k", b"body", "not-hex"));
        assert!(!verify(b"k", b"body", "00"));
    }

    /// Regression guard: `verify` must reject a near-miss signature that differs from the correct
    /// one by only a single byte. This is a correctness check, not a timing measurement — the
    /// durable guard against a *timing* regression is the doc-comment on `verify` plus the fact
    /// that this crate never hand-rolls a byte comparison over the decoded signature. If a future
    /// refactor replaces `mac.verify_slice` with a variable-time `==`, this test still passes
    /// (the comparison would still be correct, just no longer constant-time), so it does not
    /// substitute for keeping the doc-comment enforced in review.
    #[test]
    fn verify_rejects_signatures_differing_only_in_last_byte() {
        let secret = b"shh-secret";
        let body = b"payload";
        let sig = sign(secret, body);

        let mut bytes = hex::decode(&sig).expect("valid hex");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        let tampered = hex::encode(bytes);

        assert_ne!(tampered, sig);
        assert!(!verify(secret, body, &tampered));
    }

    #[test]
    fn verify_rejects_signatures_differing_only_in_first_byte() {
        let secret = b"shh-secret";
        let body = b"payload";
        let sig = sign(secret, body);

        let mut bytes = hex::decode(&sig).expect("valid hex");
        bytes[0] ^= 0xFF;
        let tampered = hex::encode(bytes);

        assert_ne!(tampered, sig);
        assert!(!verify(secret, body, &tampered));
    }

    // -------------------------------------------------------------------------
    // #483 – known-answer vectors (published in docs/webhook-consumer-guide.md)
    //
    // These are fixed (secret, body, expected-signature) triples computed once
    // and then frozen. Any change to the signing algorithm must update both this
    // table AND the matching table in docs/webhook-consumer-guide.md so
    // consumers in other languages can validate their implementations.
    //
    // To add a vector: compute `HMAC-SHA256(secret, body)` externally, append a
    // row here, then update the docs table.
    // -------------------------------------------------------------------------

    /// A single published test vector.
    struct KnownVector {
        secret: &'static [u8],
        body: &'static [u8],
        /// Lowercase hex HMAC-SHA256 digest.
        expected_sig: &'static str,
    }

    /// The canonical set of known-answer vectors, mirrored in the consumer guide.
    fn known_answer_vectors() -> Vec<KnownVector> {
        vec![
            // Vector 1: typical payment.succeeded event, primary test secret.
            KnownVector {
                secret: b"whsec_test_secret",
                body: b"{\"event\":\"payment.succeeded\",\"id\":\"evt_1\"}",
                expected_sig: "2a3a35ef554472881c09967f5ad8429a017035c566d73dd13e71e4d3bd78a698",
            },
            // Vector 2: payment.failed event, same secret — different body, different digest.
            KnownVector {
                secret: b"whsec_test_secret",
                body: b"{\"event\":\"payment.failed\",\"id\":\"evt_2\"}",
                expected_sig: "edf20815fbdb56bcf9bd038f7bfc66008038dbef972baf427227e8d807724db7",
            },
            // Vector 3: same body as vector 1, different secret — shows key sensitivity.
            KnownVector {
                secret: b"whsec_other_secret",
                body: b"{\"event\":\"payment.succeeded\",\"id\":\"evt_1\"}",
                expected_sig: "e625b85145a931ddd0665dd0140748cf48aec259ed5ee9e0390f1cb656680a3d",
            },
            // Vector 4: empty body — edge-case every consumer must handle.
            KnownVector {
                secret: b"whsec_test_secret",
                body: b"",
                expected_sig: "c6c175a074d482e2b94a0f8c5619f3abd861a511ec3ea7603b906811fd3d9d30",
            },
            // Vector 5: binary-safe — body contains a NUL byte and high-byte chars.
            KnownVector {
                secret: b"whsec_test_secret",
                body: b"\x00\xff\xfe",
                expected_sig: "9f76343e2836c6dec88455d5ad6ef7dd615a7553e7c0142c5a8240754eb965ba",
            },
        ]
    }

    #[test]
    fn known_answer_vectors_sign_produces_expected_signatures() {
        for (i, v) in known_answer_vectors().iter().enumerate() {
            let got = sign(v.secret, v.body);
            assert_eq!(
                got, v.expected_sig,
                "vector {i}: sign() mismatch — algorithm or encoding changed"
            );
        }
    }

    #[test]
    fn known_answer_vectors_verify_accepts_expected_signatures() {
        for (i, v) in known_answer_vectors().iter().enumerate() {
            assert!(
                verify(v.secret, v.body, v.expected_sig),
                "vector {i}: verify() rejected a correct known-answer signature"
            );
        }
    }

    #[test]
    fn known_answer_vectors_verify_rejects_wrong_secret() {
        for (i, v) in known_answer_vectors().iter().enumerate() {
            assert!(
                !verify(b"wrong_secret", v.body, v.expected_sig),
                "vector {i}: verify() accepted a signature under a different secret"
            );
        }
    }

    #[test]
    fn known_answer_vectors_verify_rejects_wrong_body() {
        for (i, v) in known_answer_vectors().iter().enumerate() {
            assert!(
                !verify(v.secret, b"tampered body", v.expected_sig),
                "vector {i}: verify() accepted a signature over a different body"
            );
        }
    }

    #[test]
    fn known_answer_signatures_are_exactly_64_hex_chars() {
        // HMAC-SHA256 is always 32 bytes → 64 lowercase hex characters.
        for (i, v) in known_answer_vectors().iter().enumerate() {
            assert_eq!(
                v.expected_sig.len(),
                64,
                "vector {i}: expected_sig is not 64 hex chars"
            );
            assert!(
                v.expected_sig.chars().all(|c| c.is_ascii_hexdigit()),
                "vector {i}: expected_sig contains non-hex characters"
            );
        }
    }

    #[test]
    fn sign_output_is_always_64_lowercase_hex_chars() {
        // Regression: sign() must never emit uppercase or a wrong-length digest.
        let long_key = vec![b'k'; 1024];
        let cases: &[(&[u8], &[u8])] = &[
            (b"key", b"body"),
            (b"", b""),
            (&long_key, b"x"),
        ];
        for (secret, body) in cases {
            let sig = sign(secret, body);
            assert_eq!(sig.len(), 64, "sign() produced wrong-length hex");
            assert!(
                sig.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
                "sign() produced non-lowercase hex"
            );
        }
    }
}
