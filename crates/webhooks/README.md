# octo-webhooks

HMAC-SHA256 signed outbound webhooks with retry + `webhook_deliveries` log. Echoes address
`metadata` so customer backends can reconcile. Implemented in Step 9.

## Signing contract (for consumers)

- **Header:** every delivery carries the signature in the `X-Octo-Signature` header.
- **Algorithm:** HMAC-SHA256 computed over the **exact raw request body** (the bytes as sent,
  before any parsing or re-serialization).
- **Encoding:** the signature is lowercase hex.
- **Verification:** compare the computed signature against the header value using a
  **constant-time comparison** to avoid timing side channels. Do not use `==` on strings in
  security-sensitive paths.

For language samples (Node, Python, Go, Rust) and guidance on retries, ordering, and
idempotent handling, see [`docs/webhook-consumer-guide.md`](../../docs/webhook-consumer-guide.md).

## Test vectors

The test vectors in [`src/sign.rs`](src/sign.rs) are the **published vectors**. The consumer
samples in the guide are validated against these vectors, so they can be used to confirm a
correct implementation in any language.