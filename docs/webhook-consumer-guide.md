# Webhook Consumer Guide

This guide explains how to receive and verify Octo webhooks, and how to handle them safely in production.

Octo signs every webhook delivery with HMAC-SHA256 over the exact raw request body. You **must** verify the signature before trusting the payload, and you **must** compare signatures in constant time to avoid timing attacks.

Related documentation:

- [API reference](./api.md)
- [Webhooks crate README](../crates/webhooks/README.md)

---

## 1. Signing scheme

Each delivery includes an `X-Octo-Signature` header containing a lowercase-hex HMAC-SHA256 digest of the request body.

| Property | Value |
| --- | --- |
| Algorithm | HMAC-SHA256 |
| Key | Your webhook signing secret (shared secret, per endpoint) |
| Message | The **exact raw request body bytes**, unmodified |
| Output encoding | Lowercase hexadecimal (64 characters) |
| Header | `X-Octo-Signature` |

### Critical rules

1. **Sign the raw bytes.** Do not parse the JSON and re-serialize it before verifying. Whitespace, key ordering, and number formatting all change the bytes and therefore the signature. Read the raw body exactly as received.
2. **Compare in constant time.** A naive `==` comparison leaks timing information that can allow an attacker to forge signatures byte by byte. Use the constant-time comparison primitive provided by your language/runtime.
3. **Reject on mismatch.** If the signature is missing or does not match, respond with `401` and do not process the payload.
4. **Keep the secret secret.** Store the signing secret in a secrets manager or environment variable; never commit it to source control.

### Verification algorithm

```
expected = lowercase_hex( HMAC_SHA256(secret, raw_body_bytes) )
received = X-Octo-Signature header value
if constant_time_equals(expected, received):
    accept
else:
    reject with 401
```

---

## 2. Published test vectors

The table below contains fixed `(secret, body, signature)` triples. The **exact same values** are
frozen in the test suite at
[`crates/webhooks/src/sign.rs`](../crates/webhooks/src/sign.rs) (`known_answer_vectors`).
Use them to validate any new consumer implementation before wiring it into production.

| # | Secret | Body (UTF-8) | Expected `X-Octo-Signature` |
| --- | --- | --- | --- |
| 1 | `whsec_test_secret` | `{"event":"payment.succeeded","id":"evt_1"}` | `2a3a35ef554472881c09967f5ad8429a017035c566d73dd13e71e4d3bd78a698` |
| 2 | `whsec_test_secret` | `{"event":"payment.failed","id":"evt_2"}` | `edf20815fbdb56bcf9bd038f7bfc66008038dbef972baf427227e8d807724db7` |
| 3 | `whsec_other_secret` | `{"event":"payment.succeeded","id":"evt_1"}` | `e625b85145a931ddd0665dd0140748cf48aec259ed5ee9e0390f1cb656680a3d` |
| 4 | `whsec_test_secret` | _(empty string)_ | `c6c175a074d482e2b94a0f8c5619f3abd861a511ec3ea7603b906811fd3d9d30` |
| 5 | `whsec_test_secret` | `\x00\xff\xfe` (3 raw bytes) | `9f76343e2836c6dec88455d5ad6ef7dd615a7553e7c0142c5a8240754eb965ba` |

**What each vector tests:**

- **1–2** — normal event payloads; same secret, different body → different digest.
- **3** — same body as vector 1 but different secret → different digest (key sensitivity).
- **4** — empty body; every consumer must handle a zero-length message correctly.
- **5** — raw binary body; confirms byte-level, not string-level, hashing.

> **Keeping vectors in sync:** if the signing algorithm ever changes (e.g., algorithm upgrade),
> recompute every row in this table and update `known_answer_vectors()` in `sign.rs` in the same
> commit. A consumer that passes the old vectors but fails the new ones is broken.

### Quick self-check

Before wiring a sample into your service, run it against vector 1:

```bash
node verify.js 'whsec_test_secret' '{"event":"payment.succeeded","id":"evt_1"}' '2a3a35ef554472881c09967f5ad8429a017035c566d73dd13e71e4d3bd78a698'
# prints: OK
```

---

## 3. Verification samples

Each sample reads the raw request body, recomputes the HMAC-SHA256, and compares in constant time. All samples are runnable and pass against the published vectors.

### Node.js

Uses `crypto.timingSafeEqual`. Note that `timingSafeEqual` throws if the buffers differ in length, so check lengths first (length is not secret).

```js
// verify.js
const crypto = require('crypto');

/**
 * Verify an Octo webhook signature.
 * @param {string} secret   - webhook signing secret
 * @param {Buffer} rawBody  - exact raw request body bytes
 * @param {string} received - value of the X-Octo-Signature header
 * @returns {boolean}
 */
function verifySignature(secret, rawBody, received) {
  if (typeof received !== 'string') return false;

  const expected = crypto
    .createHmac('sha256', secret)
    .update(rawBody)
    .digest('hex'); // lowercase hex

  const expectedBuf = Buffer.from(expected, 'utf8');
  const receivedBuf = Buffer.from(received, 'utf8');

  // timingSafeEqual requires equal lengths; length is not secret.
  if (expectedBuf.length !== receivedBuf.length) return false;

  return crypto.timingSafeEqual(expectedBuf, receivedBuf);
}

module.exports = { verifySignature };

// --- CLI self-check against published vectors ---
if (require.main === module) {
  const [secret, body, sig] = process.argv.slice(2);
  const ok = verifySignature(secret, Buffer.from(body, 'utf8'), sig);
  console.log(ok ? 'OK' : 'MISMATCH');
  process.exit(ok ? 0 : 1);
}
```

Express example (must capture the raw body):

```js
const express = require('express');
const { verifySignature } = require('./verify');

const app = express();

// Capture raw bytes; do NOT use express.json() before verification.
app.post(
  '/webhooks/octo',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const sig = req.get('X-Octo-Signature');
    if (!verifySignature(process.env.OCTO_WEBHOOK_SECRET, req.body, sig)) {
      return res.status(401).send('invalid signature');
    }
    const event = JSON.parse(req.body.toString('utf8'));
    // ... enqueue for idempotent processing ...
    res.status(200).send('ok');
  }
);
```

### Python

Uses `hmac.compare_digest` for constant-time comparison.

```python
# verify.py
import hmac
import hashlib
import sys


def verify_signature(secret: str, raw_body: bytes, received: str) -> bool:
    """Verify an Octo webhook signature in constant time."""
    if not isinstance(received, str):
        return False
    expected = hmac.new(
        secret.encode("utf-8"), raw_body, hashlib.sha256
    ).hexdigest()  # lowercase hex
    # compare_digest is constant-time for equal-length inputs.
    return hmac.compare_digest(expected, received)


if __name__ == "__main__":
    secret, body, sig = sys.argv[1], sys.argv[2], sys.argv[3]
    ok = verify_signature(secret, body.encode("utf-8"), sig)
    print("OK" if ok else "MISMATCH")
    sys.exit(0 if ok else 1)
```

Flask example (read raw body before parsing):

```python
import os
from flask import Flask, request, abort
from verify import verify_signature

app = Flask(__name__)


@app.post("/webhooks/octo")
def octo_webhook():
    raw = request.get_data()  # exact raw bytes
    sig = request.headers.get("X-Octo-Signature", "")
    if not verify_signature(os.environ["OCTO_WEBHOOK_SECRET"], raw, sig):
        abort(401)
    event = request.get_json(force=True)
    # ... enqueue for idempotent processing ...
    return "ok", 200
```

### Go

Uses `hmac.Equal` for constant-time comparison.

```go
// verify.go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

// VerifySignature reports whether received matches the HMAC-SHA256 of body.
func VerifySignature(secret string, body []byte, received string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil)) // lowercase hex

	// hmac.Equal is constant-time.
	return hmac.Equal([]byte(expected), []byte(received))
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: verify <secret> <body> <signature>")
		os.Exit(2)
	}
	ok := VerifySignature(os.Args[1], []byte(os.Args[2]), os.Args[3])
	if ok {
		fmt.Println("OK")
	} else {
		fmt.Println("MISMATCH")
		os.Exit(1)
	}
}
```

`net/http` handler example (read raw body):

```go
func webhookHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	sig := r.Header.Get("X-Octo-Signature")
	if !VerifySignature(os.Getenv("OCTO_WEBHOOK_SECRET"), body, sig) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	// ... enqueue for idempotent processing ...
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}
```

### Rust

Uses `hmac` to compute the digest and `subtle::ConstantTimeEq` to compare. (The `hmac` crate's `verify_slice` also performs a constant-time comparison and is a valid alternative.)

```rust
// src/main.rs
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Verify an Octo webhook signature in constant time.
pub fn verify_signature(secret: &str, body: &[u8], received: &str) -> bool {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts keys of any size");
    mac.update(body);
    let expected = hex::encode(mac.finalize().into_bytes()); // lowercase hex

    // Constant-time comparison; lengths must match for ct_eq on slices.
    let a = expected.as_bytes();
    let b = received.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: verify <secret> <body> <signature>");
        std::process::exit(2);
    }
    let ok = verify_signature(&args[1], args[2].as_bytes(), &args[3]);
    if ok {
        println!("OK");
    } else {
        println!("MISMATCH");
        std::process::exit(1);
    }
}
```

`Cargo.toml`:

```toml
[dependencies]
hmac = "0.12"
sha2 = "0.10"
subtle = "2"
hex = "0.4"
```

Alternative using `verify_slice`:

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn verify_signature(secret: &str, body: &[u8], received: &str) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body);
    let received_bytes = match hex::decode(received) {
        Ok(b) => b,
        Err(_) => return false,
    };
    // verify_slice performs a constant-time comparison internally.
    mac.verify_slice(&received_bytes).is_ok()
}
```

---

## 4. Retries

Octo delivers webhooks with **at-least-once** semantics. A delivery may be retried if:

- your endpoint does not respond within the timeout,
- your endpoint returns a non-2xx status,
- a network error occurs between Octo and your endpoint.

Guidelines:

1. **Respond `2xx` quickly.** Acknowledge receipt as soon as you have verified the signature and durably enqueued the event. Do heavy work asynchronously. Slow handlers trigger retries and duplicate deliveries.
2. **Expect duplicates.** The same event may be delivered more than once. Never assume a single delivery.
3. **Deduplicate by delivery/event id.** Each delivery carries a unique delivery id and references a stable event id. Use these to detect and drop duplicates (see [Idempotent handling](#6-idempotent-handling)).
4. **Return `401` only for signature failures.** For transient internal errors, return `5xx` so Octo retries; for permanent, unprocessable payloads, return `4xx` (other than `401`) to stop retries.

---

## 5. Ordering

**Events may arrive out of order.** Retries, parallel delivery, and network variance mean you cannot rely on arrival order to reflect the true order of events.

Guidelines:

1. **Do not assume arrival order.** Two events for the same resource may be delivered in either order.
2. **Use timestamps/sequence fields.** Each event carries a creation timestamp and, where applicable, a monotonic sequence number. Use these to determine the true order.
3. **Apply last-writer-wins with care.** When reconciling state, compare the event's timestamp/sequence against the version you have stored, and ignore events that are older than what you have already applied.
4. **Fetch current state when in doubt.** If ordering matters and you receive an event that appears stale, re-fetch the resource from the API (see [API reference](./api.md)) rather than trusting the event payload alone.

Example reconciliation:

```python
def apply_event(store, event):
    current = store.get(event["resource_id"])
    if current and event["sequence"] <= current["sequence"]:
        return  # stale or duplicate; ignore
    store.put(event["resource_id"], {
        "sequence": event["sequence"],
        "state": event["data"],
    })
```

---

## 6. Idempotent handling

Because delivery is at-least-once and ordering is not guaranteed, **every handler must be idempotent**: processing the same event twice must produce the same result as processing it once.

Guidelines:

1. **Persist processed ids.** Before (or atomically with) applying an event's effects, record its delivery/event id in a durable store. If the id is already present, skip processing and return `2xx`.
2. **Make side effects idempotent.** Use idempotency keys for downstream calls (e.g., payments, emails) so retries do not double-charge or double-send.
3. **Use atomic check-and-set.** Guard the "have I seen this id?" check and the state update with a transaction or conditional write to avoid races between concurrent deliveries.
4. **Store ids with a TTL.** Retain processed ids long enough to cover the maximum retry window; a TTL-based store (e.g., Redis with expiry) works well.

Example dedupe:

```python
def handle(event, store):
    key = f"processed:{event['id']}"
    # Atomic set-if-absent; returns False if already present.
    if not store.set_if_absent(key, "1", ttl_seconds=7 * 24 * 3600):
        return  # already processed
    apply_event(store, event)
```

---

## 7. Checklist

- [ ] Read the **raw** request body bytes before any JSON parsing.
- [ ] Recompute HMAC-SHA256 with your signing secret.
- [ ] Compare with `X-Octo-Signature` using a **constant-time** function.
- [ ] Reject mismatches with `401`.
- [ ] Respond `2xx` quickly; enqueue work asynchronously.
- [ ] Deduplicate by delivery/event id.
- [ ] Do not rely on arrival order; use timestamps/sequence fields.
- [ ] Make all handlers and side effects idempotent.
- [ ] Verify your implementation against the [published test vectors](#2-published-test-vectors).

---

See also:

- [API reference](./api.md)
- [Webhooks crate README](../crates/webhooks/README.md)
- Signature implementation and tests: [`crates/webhooks/src/sign.rs`](../crates/webhooks/src/sign.rs)