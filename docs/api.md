# API reference

The machine-readable contract is **[openapi.yaml](openapi.yaml)**, and it is enforced: the
`drift_tests` integration test validates live responses against that spec, so the two cannot
silently diverge. This page is the human-readable tour.

All responses use a consistent envelope — **including errors**, where `data` is `null` and a
stable machine-readable `code` is added (see [Error codes](#error-codes)):

```json
{ "statusCode": 200, "message": "OK", "data": { } }
{ "statusCode": 409, "code": "conflict", "message": "payment link is cancelled and cannot be reactivated", "data": null }
```

## Authentication

Two credential types, with deliberately different power:

| Credential | Header | Can do |
|---|---|---|
| **Dashboard JWT** | `Authorization: Bearer <token>` | Everything: create wallets, provision a gas tank, read the key backup |
| **Wallet API key** | `Authorization: Bearer <key>` | Per-wallet operations only. **Cannot** provision a gas tank or read a backup |

Neither can move funds — see below. Tokens carry a unique `jti` and the id of their login
session (`sid`); `logout` and `refresh` both deny-list the presented token, and every
authenticated request checks the deny-list, the session, and the user's session epoch.

- `POST /v1/auth/signup` — create an account, returns a JWT.
- `POST /v1/auth/login` — returns a JWT.
- `POST /v1/auth/refresh` — issue a new token **and revoke the presented one**.
- `POST /v1/auth/logout` — revoke the presented token and its session (repeating it is a
  harmless `200`).
- `GET  /v1/auth/me` — the current user.
- `GET  /v1/auth/sessions` — the caller's live sessions: `id`, `created_at`, `last_seen_at`
  (updated at most once a minute), `expires_at`, `user_agent_hash` (SHA-256 hex of the sign-in
  User-Agent) and `current`.
- `DELETE /v1/auth/sessions/:id` — revoke one session; its token is rejected on its next request.
  `404` if the id is unknown, already revoked, or another user's.
- `POST /v1/auth/sessions/revoke-others` — revoke every other session, including tokens issued
  before session tracking. Returns `{ token, revoked }`: the presented token is invalidated too,
  so switch to the returned one.

Session endpoints require a dashboard JWT (API keys get `401`).

### Account export and deletion

Both flows require a dashboard JWT **plus** the current password **plus** an emailed one-time
code. Export and delete codes are separate purposes, so one can never be redeemed for the other.
All four calls share a cap of 5 per user per hour (`429` beyond that).

- `POST /v1/auth/account/export/request-otp` — body `{ "password" }`; emails a code.
- `POST /v1/auth/account/export` — body `{ "password", "code" }`; returns the caller's profile,
  wallets, addresses, transactions, withdrawals, sponsored transactions, API keys (prefix and
  scopes only), webhook endpoints (no secret), allowlist, payment links and payments, sessions
  and audit log. **No secrets**: password hash, sealed seeds, the encrypted backup blob, webhook
  secrets and API key hashes are never included. Each section holds at most `section_limit`
  rows; cut-off sections are named in `truncated`. Every export writes an audit row, and the
  request fails rather than export untraced.
- `POST /v1/auth/account/delete/request-otp` — body `{ "password" }`; emails a code, or `409`
  if any wallet still holds funds.
- `POST /v1/auth/account/delete` — body `{ "password", "code" }`; deletes the account.

**Deletion is refused (`409`) while any wallet's Stellar account or gas tank holds a non-zero
balance** — withdraw or merge them first. If Horizon can't confirm the balances the request
fails closed with `503`. On success the user row becomes a tombstone (email, username and
password hash scrubbed), every session and API key is revoked, wallets are archived with their
label, description and backup removed, webhooks and payment links are retired, payer details
are erased, and the audit trail is kept but anonymised (see [audit-log.md](audit-log.md)).
Transactions and withdrawals are retained as financial records.

## Custody model — read this before the wallet endpoints

octo is **non-custodial**. The wallet's private key is generated and held **client-side**; the
server stores only the public account and an opaque, client-encrypted backup blob it cannot
decrypt. Consequently:

- There is **no endpoint that signs a payment for you.** You build and sign locally, then relay.
- `POST /v1/wallets/:id/withdraw` and `POST /v1/wallets/:id/trustlines` are **`410 Gone`
  tombstones**. They exist only to give integrators a clear error pointing at `submit-signed`.

## Wallets

- `POST /v1/wallets` — register a wallet from a **client-generated** keypair.
  Body: `{ "public_key": "G...", "encrypted_backup"?: string, "label"?: string,
  "description"?: string }`. `public_key` is required; a body without it is `400`.
  Returns `201` with `{ id, network, address, custody, funded }`.
  **Never returns a mnemonic** — the client generated it and the server never saw it.
- `GET  /v1/wallets` — list your wallets (paginated).
- `GET  /v1/wallets/{id}` — wallet details.
- `PATCH /v1/wallets/{id}` — rename or annotate a wallet. Body: `{ "label"?: string|null,
  "description"?: string|null }` — omit a field to keep it, `null` or `""` to clear it. `label` ≤ 64
  characters, `description` ≤ 500; control and invisible formatting characters are `400`. Owner
  login or a `write`-scoped API key; archived wallets are `403`. Audit-logged.
- `GET  /v1/wallets/{id}/balances` — live on-chain balances.
- `GET  /v1/wallets/{id}/transactions` — deposits + outbound transfers (paginated). Optional
  filters compose with each other and with `?before=` keyset pagination:
  `direction` (`deposit`|`withdrawal`), `status` (`pending`|`confirmed`|`failed`), `asset`
  (`native`/`XLM`, a code such as `USDC` for any issuer, or `CODE:ISSUER`), `from` (inclusive)
  and `to` (exclusive) as RFC 3339 timestamps or `YYYY-MM-DD` (midnight UTC). Any invalid value,
  or `from` not earlier than `to`, is `400`. A `before` cursor from another wallet yields an empty
  page.
- `GET  /v1/wallets/{id}/transactions.csv` — the same history as an accounting CSV download
  (`text/csv`, `Content-Disposition: attachment`, `Cache-Control: no-store`). Same auth and the
  same filters as the JSON endpoint, but no pagination: rows stream newest first in batches of
  500, so memory is bounded however long the history is. Columns: `id, created_at, direction,
  status, asset_code, asset_issuer, amount_stroops, source_account, destination_account,
  stellar_tx_hash, operation_index, ledger, memo_id, address_id, reference`. Text cells starting
  with `=`, `+`, `-`, `@`, tab or CR are prefixed with `'` so spreadsheets never evaluate them.
  If the database fails mid-export the connection is aborted rather than ending cleanly, so a
  partial file is never mistaken for a complete one.
- `PATCH /v1/wallets/{id}/ingest/pause` / `PATCH /v1/wallets/{id}/ingest/resume` — stop or
  restart deposit polling for one wallet. **Dashboard JWT only**, owner-only, audit-logged.
  The ingest cursor is kept while paused, so resume continues from where polling stopped with no
  gap; a pause takes effect from the supervisor's next tick. Wallet views expose
  `ingest_paused` and `ingest_paused_at`.
- `GET  /v1/wallets/{id}/backup` — the opaque client-encrypted backup blob, for new-device
  recovery. **Dashboard JWT only.** Useless without the user's password. Rate-limited to 5
  requests per hour per user (`429` beyond that); every successful read writes an audit row, and
  the request fails with `500` rather than return the blob if that row can't be written.

## Moving funds (the non-custodial path)

1. `GET  /v1/wallets/{id}/signing-info` — returns the account `sequence`, network passphrase,
   selected per-operation `base_fee_stroops`, and absolute Unix `max_time`. The fee is selected
   from the configured Horizon `/fee_stats` percentile and never exceeds the configured ceiling;
   when fee stats are unavailable it falls back to the Stellar base fee.
2. Build and **sign locally**, including a time bound whose `max_time` is the returned value. The
   envelope will then expire after the configured short window rather than remaining submit-able
   indefinitely.
3. `POST /v1/wallets/{id}/submit-signed` — body `{ "transaction_xdr": "<base64>" }`.
   The server validates (v1 envelope, at least one signature, source account == this wallet,
   operation-type allowlist) and relays it **unmodified**. On failure it returns Horizon's
   result codes (`tx_bad_seq`, `op_no_trust`, …) so you can correct and re-sign.

### Withdrawal estimate

`GET /v1/wallets/{id}/withdraw/estimate` — preview a withdrawal's fee and minimum-balance impact
before building it. Query: `asset_code` + `asset_issuer` (omit both for XLM), optional
`amount_stroops`, optional `operations` (1–100, default 1). Returns:

| Field | Meaning |
|---|---|
| `base_fee_stroops` | Network minimum per operation (Horizon `last_ledger_base_fee`) |
| `recommended_fee_stroops` | Per-op bid: `max(base_fee, fee_charged.p90)` |
| `estimated_fee_stroops` | `recommended_fee_stroops × operations` — the tx `fee` to build with |
| `base_reserve_stroops`, `min_reserve_stroops` | `base_reserve × (2 + subentries + sponsoring − sponsored)` |
| `native_balance_stroops`, `asset_balance_stroops` | Current balances (`asset_balance` only for credit assets) |
| `fee_covered` | Native balance above the reserve covers the fee |
| `max_withdrawable_stroops` | Most of the asset that can leave after fee and reserve |
| `sufficient` | Only when `amount_stroops` is given: fee covered and amount ≤ max |

The reserve figures come from the same `AccountInfo` read and `BASE_RESERVE_STROOPS` constant the
withdrawal pre-flight uses. Fee stats are cached in-process for 10 seconds (`FEE_STATS_TTL`) and
shared by all requests; a failed fetch is never cached. The estimate ignores selling liabilities
from open offers (the relay's op allowlist doesn't create them). Unfunded wallet or missing
trustline → `400`.
`POST /v1/wallets/{id}/trustlines` and public payment-link signing info return the same fee and
`max_time` guidance. The server defaults to a five-minute lifetime, fee percentile 50, and a
10,000-stroop per-operation ceiling. Configure these with `STELLAR_TX_MAX_AGE_SECS`
(1–86400), `STELLAR_FEE_PERCENTILE` (10, 20, 30, 40, 50, 60, 70, 80, 90, 95, or 99), and
`STELLAR_FEE_CEILING_STROOPS` (at least 100).

## Addresses

- `POST /v1/wallets/{id}/addresses` — generate a dedicated customer address.
  Body: `{ "customer_ref"?: string, "metadata"?: object }`. Returns `muxed_address` (`M...`)
  **and** the `{ base_address, memo_id }` fallback. `customer_ref` (≤ 128 characters, trimmed, no
  control characters) is unique per wallet: reusing one on the same wallet is `409`.
- `POST /v1/wallets/{id}/addresses/batch` — allocate many addresses at once. Body:
  `{ "addresses": [{ "customer_ref"?: string, "metadata"?: object }, ...] }`, 1–100 entries.
  All-or-nothing: if any entry fails (a bad or duplicate `customer_ref` → `400`/`409`) no address
  is created. Each batch gets a contiguous, collision-free block of muxed ids even under
  concurrent batches. Returns `201` with `{ data: [address, ...] }` in request order.
- `GET  /v1/wallets/{id}/addresses` — list addresses (paginated). `?customer_ref=` returns just
  the address with that reference (an empty list if none).

## Allowlist

- `POST /v1/wallets/{id}/allowlist` — allowlist a destination address. Body:
  `{ "address": "G...", "label"?: string }`. `label` is trimmed, limited to 64 characters, and
  must not contain control or invisible formatting characters; otherwise `400`. The cleaned
  label is returned in the response.

## Gas sponsorship

Lets you pay your users' Stellar fees. The **gas tank** is a separate, server-held account that
carries fee float only — the one server-held key in the system, bounded by your gas budget.

- `POST /v1/wallets/{id}/gas-tank` — provision the gas tank. **Dashboard JWT only** (an API key
  gets `401`). Idempotent: a second call returns the existing tank.
- `GET  /v1/wallets/{id}/sponsorship` / `PUT` — read/update `enabled`, the per-transaction fee
  cap, the daily budget, and `allowed_operations`. `allowed_operations` narrows the global
  sponsorship allowlist (`Payment`, `PathPaymentStrictSend`, `PathPaymentStrictReceive`) for this
  wallet: send a non-empty subset to restrict, `null` to inherit the global list, or omit it to
  keep the current setting. Anything outside the global list is `400`. The response also reports
  `effective_allowed_operations`.
- `POST /v1/wallets/{id}/sponsor` rejects (`400 op_not_allowed`) any operation outside the
  wallet's effective allowlist before anything is signed.
- `POST /v1/wallets/{id}/sponsor` — fee-bump a user's **already-signed** inner transaction.
  The gas tank signs only the outer fee-bump envelope; the inner transaction is passed through
  untouched. Over budget → `429`; duplicate inner tx → `409`.
- `POST /v1/wallets/{id}/sponsor/validate` — dry run of `/sponsor` with the same body. It runs
  the **same validation code** (enabled flag, per-tx cap, op allowlist, self-sponsorship,
  custody, on-chain sequence) plus read-only dedup and daily-budget projections, then returns
  `200` with `{ verdict: "accepted" | "rejected", reason, rejection_status, rejection_code,
  projected_fee_stroops, inner_tx_hash, budget_remaining_stroops }`. `rejection_status`,
  `rejection_code` and `reason` are the status, error `code` and message `/sponsor` would answer
  with. Nothing is signed, reserved,
  submitted, audited or sent as a webhook. Auth failures and upstream errors (`5xx`) still answer
  as errors. A dry run is advisory: concurrent sponsorships can still exhaust the budget before
  the real call.
- `GET  /v1/wallets/{id}/sponsored-transactions` — sponsorship history (paginated, filterable
  by status).

## Webhooks

- `POST   /v1/wallets/{id}/webhooks` — register an endpoint (URL + generated secret).
- `GET    /v1/wallets/{id}/webhooks` — list active endpoints.
- `DELETE /v1/wallets/{id}/webhooks/{endpoint_id}` — deactivate (soft delete, so the delivery
  history survives as an audit trail).
- `GET    /v1/wallets/{id}/webhooks/{endpoint_id}/deliveries` — delivery history (`?limit=`,
  default 50, max 200; `?status=pending|delivered|failed|dead` to filter, e.g. the dead-letter
  queue).
- `POST   /v1/wallets/{id}/webhooks/{endpoint_id}/test` — send a signed `ping` event and return
  the result (one attempt, recorded in history, 5/min per endpoint).
- `POST   /v1/wallets/{id}/webhooks/{endpoint_id}/deliveries/{delivery_id}/redeliver` — re-send
  a past event with its original `data` plus `redelivery_of`/`redelivered_at` (active endpoints
  only, 10/min per endpoint, audit-logged).

Deliveries are signed `HMAC-SHA256` over the raw body. Endpoint URLs are SSRF-screened:
loopback, private and link-local targets are rejected, IPv4 and bracketed IPv6 alike.

### Verifying webhook signatures

Every delivery carries an `X-Octo-Signature` header. Its value is the lowercase hex
`HMAC-SHA256` of the **raw request body bytes**, keyed with the endpoint's secret (the one
returned when the endpoint was registered). Compute the digest over the bytes exactly as
received — do not parse and re-serialize the JSON first, since any whitespace or key-order
change breaks the match.

Compare the computed digest with the header using a **constant-time** comparison (e.g.
`crypto.timingSafeEqual` in Node, `hmac.compare_digest` in Python, `hmac.Equal` in Go,
`subtle::ConstantTimeEq` in Rust). A plain `==` leaks timing information and must not be used.
Reject the delivery with a non-2xx status when the signature is missing or does not match.

For complete, runnable samples in Node, Python, Go and Rust — plus guidance on retries,
out-of-order delivery and idempotent handling — see
**[webhook-consumer-guide.md](webhook-consumer-guide.md)**.

A delivery whose retries are exhausted ends in the terminal `dead` status. Set
`OCTO_WEBHOOK_AUTO_DISABLE_AFTER=N` to deactivate an endpoint after `N` consecutive dead
deliveries (its `auto_disabled_at` is then set); unset means never.

## Payment links

- `POST   /v1/wallets/{id}/payment-links` — create a link. Optional `expires_at` (RFC 3339, in
  the future, at most 365 days away) time-boxes it.
- `POST   /v1/wallets/{id}/payment-links` accepts an optional `Idempotency-Key` header (1-255
  visible ASCII characters, scoped to the wallet):
  - A retry with the same key and the **byte-identical** body returns the original `201`
    response with `Idempotent-Replayed: true` and creates nothing new.
  - The same key with a different body is `409`. So is a retry while the first request is
    still running.
  - A request that fails (e.g. `400`) frees its key, so a corrected retry can reuse it.
  - Keys expire **24 hours** after first use (`IDEMPOTENCY_KEY_TTL_SECS`), after which the key
    starts fresh.
- `PATCH  /v1/wallets/{id}/payment-links/{link_id}` — edit `description`, `redirect_url` and
  `amount_usdc_stroops` (omit to keep, `null` to clear). Allowed only while no payment is
  pending or has landed; otherwise `409`. Requires the `write` scope. Edits are audit-logged.
- `POST   /v1/wallets/{id}/payment-links/{link_id}/cancel` — permanently close a link
  (idempotent, `write` scope, audit-logged). Its pending payments become `cancelled` and each
  fires a `payment_link.cancelled` webhook. A cancelled link can't be re-activated (`PUT` → `409`).

Every link view carries `status`: `active`, `inactive` (paused via `PUT`), `expired` (at or past
`expires_at`) or `cancelled`. Expired and cancelled are terminal.

On the public pay routes a paused link is `404`. An expired or cancelled link is still readable
at `GET /v1/pay/{slug}` with its `status` and `deposit_address: null`; creating an intent,
fetching signing info or relaying a payment answers `410`. `submit-signed` for a `payment_id`
that is no longer `pending` answers `409`. Polling a pending payment on a closed link reports
the link's `expired`/`cancelled` status straight away.

### Late payments

A deposit is matched to a payment only if, when ingest records it, the payment is still
`pending` **and** the link is neither cancelled nor at/past `expires_at`. Anything later is a
*late deposit*:

- The funds are already in the merchant's wallet (Octo is non-custodial and cannot bounce them).
  The deposit is recorded and `deposit.created` fires as for any deposit; its address `metadata`
  carries `payment_link_slug` for reconciliation.
- The payment is **not** confirmed, no `payment_link.paid` / `payment_link.mismatched` fires,
  and it does not count towards `collected_usdc_stroops`.
- Refunding or honouring a late deposit is the merchant's decision.

Pending payments on an expired link are flipped to `expired` by the ingest sweep (firing
`payment_link.expired`), alongside the existing one-hour intent deadline.

## API keys

All three require a **dashboard JWT** and wallet ownership — an API key can never manage keys,
so it cannot escalate or revoke itself.

- `POST   /v1/wallets/{id}/api-key` — generate/regenerate (the plaintext key is shown **once**;
  only a SHA-256 hash is stored). Optional `expires_in_days` must be between **1 and 365**
  inclusive; any other value is rejected with `400` (`bad_request`, message
  `expires_in_days must be between 1 and 365`) instead of being silently clamped.
- `GET    /v1/wallets/{id}/api-key` — metadata (prefix, created_at) — never the key itself.
- `DELETE /v1/wallets/{id}/api-key` — revoke.

## Audit logs

- `GET /v1/audit-logs` — your account's activity, filterable by `category` and a free-text
  `search` (trimmed, at most 100 characters; longer is `400`). Returns at most
  `AUDIT_LIST_LIMIT` (200) rows, newest first.

## Uploads

- `GET /v1/uploads/signature` — a short-lived signed upload signature for the configured
  Cloudinary account. When the server has no Cloudinary settings the endpoint answers `503`
  (`service_unavailable`); the client did nothing wrong.

## Conventions

- **Pagination:** list endpoints take `?limit=` (default 50, max 200) and `?before=<uuid>` for
  keyset pagination. They return `{ "data": [...], "next_cursor": <uuid|null> }` — note this
  sits *inside* the response envelope, so the full shape is
  `{ statusCode, message, data: { data: [...], next_cursor } }`.
- **Amounts** are integer **stroops** (1 XLM = 10,000,000) end-to-end — never floats.
- **Errors** map to `400` (validation), `401`, `403`, `404`, `409` (conflict), `410` (removed
  custodial endpoints), `413` (body over 64 KiB), `429` (budget exceeded). There is no `422`.
  Branch on `code`, never on `message`.

## Error codes

Every error response — from a handler, an extractor rejection (bad JSON, bad path/query
parameter), an unknown route, a wrong method, or the body-size limit — carries `code`. Codes are
a stable contract: they are never renamed or reused, and a new one is only ever added. `message`
is human-readable and may change at any time. The catalogue lives in `ERROR_CODES`
(`crates/api/src/error.rs`), mirrors `ErrorResponse.code` in `openapi.yaml`, and is pinned by a
snapshot test (`crates/api/tests/snapshots/error_codes.snap`).

| Code | Status | Meaning |
|---|---|---|
| `bad_request` | 400 | The request was malformed or failed validation. |
| `stale_sequence` | 400 | The transaction's sequence number is stale; refresh signing info and rebuild. |
| `unauthorized` | 401 | Missing, invalid or revoked credentials. |
| `forbidden` | 403 | Authenticated, but the server refuses this action for this resource. |
| `not_found` | 404 | The resource or route does not exist, or is not visible to this caller. |
| `method_not_allowed` | 405 | The route exists but not for this HTTP method. |
| `already_exists` | 409 | A resource with this identity already exists (duplicate). |
| `conflict` | 409 | The resource's current state does not allow this change. |
| `gone` | 410 | The endpoint or resource has been permanently removed or closed. |
| `payload_too_large` | 413 | The request body exceeds the 64 KiB limit. |
| `unsupported_media_type` | 415 | The request body has an unsupported Content-Type. |
| `too_many_requests` | 429 | A rate limit or budget would be exceeded. |
| `internal_error` | 500 | An internal error occurred; details are logged, never returned. |
| `service_unavailable` | 503 | A server-side capability is not configured or temporarily unavailable. |
| `upstream_timeout` | 504 | An upstream dependency (e.g. Horizon) did not answer in time. |

See also [errors.md](errors.md) for the per-code remedies.

## Rate Limits

The API enforces fixed-window rate limiting on unauthenticated and authentication endpoints to protect against brute-force and resource-exhaustion attacks. When a rate limit is exceeded, the server responds with HTTP `429 Too Many Requests` and a `Retry-After: <seconds>` header carrying the remaining seconds in the current window (a positive integer). Honour it: wait at least that long before retrying, then fall back to an exponential delay of your own (see [errors.md](errors.md)).

Counters are shared across replicas through Postgres by default (`RATE_LIMIT_BACKEND=postgres`), so limits hold regardless of how many instances run and survive restarts; see `docs/ha-topology.md`. Per-IP keys use the first `X-Forwarded-For` hop only when it parses as an IP address.

| Endpoint | Method | Key Scope | Limit | Window | Code Constant |
|---|---|---|---|---|---|
| `/v1/auth/signup` | POST | Per-IP | 10 req | 60s (1m) | `AUTH_RATE_LIMIT` / `AUTH_RATE_WINDOW` |
| `/v1/auth/verify-email` | POST | Per-IP | 10 req | 60s (1m) | `AUTH_RATE_LIMIT` / `AUTH_RATE_WINDOW` |
| `/v1/auth/login` | POST | Per-IP | 10 req | 60s (1m) | `AUTH_RATE_LIMIT` / `AUTH_RATE_WINDOW` |
| `/v1/auth/refresh` | POST | Per-IP | 10 req | 60s (1m) | `AUTH_RATE_LIMIT` / `AUTH_RATE_WINDOW` |
| `/v1/auth/resend-otp` | POST | Per-IP | 10 req | 60s (1m) | `AUTH_RATE_LIMIT` / `AUTH_RATE_WINDOW` |
| `/v1/auth/resend-otp` | POST | Per-User (`otp:{user_id}`) | 3 req | 3600s (1h) | `OTP_RESEND_USER_LIMIT` / `OTP_RESEND_USER_WINDOW` |
| `/v1/auth/resend-otp` | POST | Per-IP | 10 req | 3600s (1h) | `OTP_RESEND_IP_LIMIT` / `OTP_RESEND_IP_WINDOW` |
| `/v1/pay/:slug` | GET | Per-IP | 60 req | 60s (1m) | `PAY_READ_LIMIT` / `PAY_READ_WINDOW` |
| `/v1/pay/:slug/intent` | POST | Per-IP | 5 req | 60s (1m) | `PAY_INTENT_LIMIT` / `PAY_INTENT_WINDOW` |
| `/v1/pay/:slug/payments/:payment_id` | GET | Per-IP | 60 req | 60s (1m) | `PAY_STATUS_LIMIT` / `PAY_STATUS_WINDOW` |
| `/v1/pay/:slug/signing-info` | GET | Per-IP | 60 req | 60s (1m) | `PAY_SIGNING_INFO_LIMIT` / `PAY_SIGNING_INFO_WINDOW` |
| `/v1/pay/:slug/submit-signed` | POST | Per-IP | 20 req | 60s (1m) | `PAY_SUBMIT_LIMIT` / `PAY_SUBMIT_WINDOW` |
| `/v1/wallets/:id/transactions.csv` | GET | Per-Wallet (`csv_export:{wallet_id}`) | 10 req | 60s (1m) | `CSV_EXPORT_LIMIT` / `CSV_EXPORT_WINDOW` |

> [!NOTE]
> **Process Note:** Any new rate limit added to the API must update this table and reference named constants in `crates/api/src/rate_limit.rs` within the same pull request.
