# API reference

The machine-readable contract is **[openapi.yaml](openapi.yaml)**, and it is enforced: the
`drift_tests` integration test validates live responses against that spec, so the two cannot
silently diverge. This page is the human-readable tour.

All responses use a consistent envelope — **including errors**, where `data` is `null`:

```json
{ "statusCode": 200, "message": "OK", "data": { } }
```

## Authentication

Two credential types, with deliberately different power:

| Credential | Header | Can do |
|---|---|---|
| **Dashboard JWT** | `Authorization: Bearer <token>` | Everything: create wallets, provision a gas tank, read the key backup |
| **Wallet API key** | `Authorization: Bearer <key>` | Per-wallet operations only. **Cannot** provision a gas tank or read a backup |

Neither can move funds — see below. Tokens carry a unique `jti`; `logout` and `refresh` both
deny-list the presented token, and every authenticated request checks that deny-list.

- `POST /v1/auth/signup` — create an account, returns a JWT.
- `POST /v1/auth/login` — returns a JWT.
- `POST /v1/auth/refresh` — issue a new token **and revoke the presented one**.
- `POST /v1/auth/logout` — revoke the presented token (a second logout is `401`, not `200`).
- `POST /v1/auth/change-password` — `{current_password, new_password}`; re-verifies the current
  password, revokes **every** session issued before the change (per-user `session_epoch`), and
  returns a fresh token. Login-JWT only (not API keys); rate-limited per IP and per user.
- `GET  /v1/auth/me` — the current user.
- `POST /v1/auth/request-password-reset` — `{email}`; emails a 10-minute OTP if a verified account
  exists. Always returns the same `200` either way (no account enumeration).
- `POST /v1/auth/confirm-password-reset` — `{email, code, new_password}`; sets the password and
  **revokes every existing session**. Any failure is `400 invalid or expired code`.
- `POST /v1/auth/change-email` — `{new_email, password}` (login required): verifies the current
  password and emails an OTP to the **new** address. Nothing changes yet.
- `POST /v1/auth/change-email/confirm` — `{new_email, code}` (login required): applies the change
  once the new address's OTP is confirmed, and notifies the old address.

## Custody model — read this before the wallet endpoints

octo is **non-custodial**. The wallet's private key is generated and held **client-side**; the
server stores only the public account and an opaque, client-encrypted backup blob it cannot
decrypt. Consequently:

- There is **no endpoint that signs a payment for you.** You build and sign locally, then relay.
- `POST /v1/wallets/:id/withdraw` is a **`410 Gone` tombstone** pointing integrators at
  `submit-signed`.
- `POST /v1/wallets/:id/trustlines` takes `{asset_code, asset_issuer, limit_stroops?}`, validates
  them, and returns ChangeTrust signing info (`account`, `sequence`, `network_passphrase`,
  `base_fee_stroops`, `limit_stroops`, `submit_url`). The server never signs it — the client builds
  and signs the ChangeTrust locally and relays it via `submit-signed`.

## Wallets

- `POST /v1/wallets` — register a wallet from a **client-generated** keypair.
  Body: `{ "public_key": "G...", "encrypted_backup"?: string, "label"?: string,
  "description"?: string }`. `public_key` is required; a body without it is `400`.
  Returns `201` with `{ id, network, address, custody, funded }`.
  **Never returns a mnemonic** — the client generated it and the server never saw it.
- `GET  /v1/wallets` — list your wallets (paginated).
- `GET  /v1/wallets/{id}` — wallet details.
- `GET  /v1/wallets/{id}/balances` — live on-chain balances. Fetched synchronously from
  Horizon under a **10 s** route timeout (independent of per-attempt retries); if Horizon is
  slower than that, the request ends with `504` in the standard envelope — safe to retry.
- `GET  /v1/wallets/{id}/transactions` — deposits + outbound transfers (paginated, optional `?direction=deposit|withdrawal`).
- `GET  /v1/wallets/{id}/backup` — the opaque client-encrypted backup blob, for new-device
  recovery. **Dashboard JWT only.** Useless without the user's password.

## Moving funds (the non-custodial path)

1. `GET  /v1/wallets/{id}/signing-info` — returns the account `sequence`, the network
   passphrase, and the base fee, so you can build a transaction without talking to Horizon.
2. Build and **sign locally**.
3. `POST /v1/wallets/{id}/submit-signed` — body `{ "transaction_xdr": "<base64>" }`.
   The server validates (v1 envelope, at least one signature, source account == this wallet,
   operation-type allowlist) and relays it **unmodified**. On failure it returns Horizon's
   result codes (`tx_bad_seq`, `op_no_trust`, …) so you can correct and re-sign.

## Addresses

- `POST /v1/wallets/{id}/addresses` — generate a dedicated customer address.
  Returns `muxed_address` (`M...`) **and** the `{ base_address, memo_id }` fallback.
- `GET  /v1/wallets/{id}/addresses` — list addresses (paginated).

## Gas sponsorship

Lets you pay your users' Stellar fees. The **gas tank** is a separate, server-held account that
carries fee float only — the one server-held key in the system, bounded by your gas budget.

- `POST /v1/wallets/{id}/gas-tank` — provision the gas tank. **Dashboard JWT only** (an API key
  gets `401`). Idempotent: a second call returns the existing tank.
- `GET  /v1/wallets/{id}/gas-tank` — the tank's public account (`gas_tank_address`), whether it is
  `provisioned`, and today's `spent_today_stroops` against `daily_budget_stroops`. A wallet with
  no tank returns `200` with `provisioned: false`. Never includes the sealed seed.
- `GET  /v1/wallets/{id}/sponsorship` / `PUT` — read/update `enabled`, the per-transaction fee
  cap, and the daily budget.
  - `daily_budget_stroops`: `null`/omitted = **unlimited**; `0` = sponsorship **fully disabled**
    for the day (every sponsor request gets `429`); negative → `400`.
  - `per_tx_fee_cap_stroops`: `null`/omitted = no per-transaction cap; negative → `400`.
  - When both are set, `per_tx_fee_cap_stroops` must be `<=` `daily_budget_stroops`, otherwise
    `400` naming both values. Either field may be left unset independently.
- `POST /v1/wallets/{id}/sponsor` — fee-bump a user's **already-signed** inner transaction.
  The gas tank signs only the outer fee-bump envelope; the inner transaction is passed through
  untouched. Over budget → `429`; duplicate inner tx → `409`.
- `GET  /v1/wallets/{id}/sponsored-transactions` — sponsorship history (paginated, filterable
  by status).

## Webhooks

- `POST   /v1/wallets/{id}/webhooks` — register an endpoint (URL + generated secret).
- `GET    /v1/wallets/{id}/webhooks` — list active endpoints.
- `DELETE /v1/wallets/{id}/webhooks/{endpoint_id}` — deactivate (soft delete, so the delivery
  history survives as an audit trail).
- `GET    /v1/wallets/{id}/webhooks/{endpoint_id}/deliveries` — delivery history (`?limit=`,
  default 50, max 200). Each row carries `response_code` (HTTP status of the last attempt, `null` on
  a connection error/timeout) and `response_body_snippet` (first ≤ 1 KiB of the response body, with
  the signature and secret redacted). Transport errors and 5xx are retried with backoff (3 attempts,
  20 s ceiling); other non-2xx responses are not retried.

Deliveries are signed `HMAC-SHA256` over the raw body. Endpoint URLs are SSRF-screened:
loopback, private and link-local targets are rejected, IPv4 and bracketed IPv6 alike —
including IPv4-mapped IPv6 (`[::ffff:127.0.0.1]`) and the unspecified address (`0.0.0.0`, `[::]`).

## API keys

All three require a **dashboard JWT** and wallet ownership — an API key can never manage keys,
so it cannot escalate or revoke itself.

- `POST   /v1/wallets/{id}/api-key` — generate (the plaintext key is shown **once**; only a
  SHA-256 hash is stored). The first key needs no body. Once a key exists, rotating it requires
  `{"confirm": true}` — otherwise `409` ("an API key already exists; pass confirm=true to rotate
  it"). Rotation immediately invalidates the previous key.
- `GET    /v1/wallets/{id}/api-key` — metadata (prefix, created_at) — never the key itself.
- `DELETE /v1/wallets/{id}/api-key` — revoke.

## Payment link checkout flow

A payment link is a shareable, USDC-only checkout page. The merchant creates it once (authenticated);
every payer step after that is **public — no credential** — and keyed by the link's `slug`. Public
routes are rate-limited per client IP (per minute): read 60, **intent 5**, signing-info 60,
submit 20, status 60. Over the limit → `429`.

Merchant, once (dashboard JWT or wallet API key; `$TOKEN` as in the README):

```bash
curl -s -X POST localhost:8080/v1/wallets/<WALLET_ID>/payment-links \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"name":"Order #1042","amount_usdc_stroops":50000000}' | jq   # omit the amount for a flexible link
# -> data.slug (e.g. "3f9c1a7d2e"), data.url (hosted checkout page)
```

Payer, from there (`$SLUG` is `data.slug`; a fixed-amount link ignores any amount the payer sends,
a flexible link requires `amount_usdc_stroops > 0`):

```bash
# 1. Fetch the link: what is being paid and where. 404 if the slug is unknown or the link is inactive.
curl -s localhost:8080/v1/pay/$SLUG | jq
# -> { name, description, image_url, redirect_url, amount_usdc_stroops, deposit_address, asset_code: "USDC" }

# 2. Create a payment intent. Each intent gets its OWN muxed deposit address, so a deposit maps to
#    exactly one payment. payer_name / payer_email are optional.
curl -s -X POST localhost:8080/v1/pay/$SLUG/intent \
  -H 'content-type: application/json' -d '{"payer_name":"Ada","payer_email":"ada@example.com"}' | jq
# -> 201 { payment_id, deposit_address, amount_usdc_stroops }   (keep payment_id)

# 3. Get what you need to build the transaction. `account` is the PAYER's own G... account, so the
#    returned sequence is the payer's. Omit it and the merchant wallet's account is used.
#    A payer account that does not exist on the network yet (unfunded) returns 404.
curl -s "localhost:8080/v1/pay/$SLUG/signing-info?account=<PAYER_G_ADDRESS>" | jq
# -> { account, sequence, network_passphrase, base_fee_stroops }

# 4. Build and SIGN LOCALLY (e.g. in Freighter): exactly one USDC Payment to the intent's
#    deposit_address, nothing else. Then relay it, passing the payment_id from step 2.
curl -s -X POST localhost:8080/v1/pay/$SLUG/submit-signed \
  -H 'content-type: application/json' \
  -d '{"transaction_xdr":"<BASE64_SIGNED_XDR>","payment_id":"<PAYMENT_ID>"}' | jq
# -> 201 { status: "confirmed" | "failed", stellar_tx_hash, detail }

# 5. Poll until the deposit is matched (the pay page polls about every 3s).
curl -s localhost:8080/v1/pay/$SLUG/payments/<PAYMENT_ID> | jq
# -> { status, transaction_id, expected_usdc_stroops, received_usdc_stroops }
```

Things an integrator should know:

- **`submit-signed` returns `201` even when `status` is `"failed"`** — check `status` and `detail`
  (a Horizon result code such as `op_underfunded`), not just the HTTP code. `400` means the
  transaction was rejected before relay: not a v1 envelope, unsigned, or not exactly one USDC
  `Payment` to this intent's `deposit_address`.
- **The relay is deliberately narrow**: it never signs and cannot spend anything except that one
  payment. Without `payment_id` it falls back to the link's own address (legacy clients).
- **Status** is one of `pending`, `confirmed`, `expired`, `underpaid`, `overpaid`. `received_usdc_stroops`
  is `null` until a deposit is matched; `expected_usdc_stroops` is always present so a client can
  show "you sent X, expected Y". A `confirmed` status comes from the ingest worker seeing the
  deposit, not from the submit response.
- **Payer PII is write-only.** `payer_name` and `payer_email` are stored for the merchant but no
  public route returns them, and none of the public responses above carries merchant-internal
  fields (wallet id, link id, collected totals). If a public response ever gains or loses a field,
  update the shapes shown here.
- Amounts are integer stroops: `50000000` = 5 USDC.

Merchant-side management (list/get/deactivate links and list a link's payments) lives under
`/v1/wallets/{id}/payment-links` — see [openapi.yaml](openapi.yaml).

## Audit logs

- `GET /v1/audit-logs` — your account's activity, filterable by `category` and a free-text
  `search`. Valid categories: `authentication`, `wallet`, `address`, `credentials`, `configuration`, `sponsorship`. The category set and every event that emits one is catalogued in
  [audit-log.md](audit-log.md).

## Conventions

- **Pagination:** list endpoints take `?limit=` (default 50, max 200) and `?before=<uuid>` for
  keyset pagination. They return `{ "data": [...], "next_cursor": <uuid|null> }` — note this
  sits *inside* the response envelope, so the full shape is
  `{ statusCode, message, data: { data: [...], next_cursor } }`.
- **Amounts** are integer **stroops** (1 XLM = 10,000,000) end-to-end — never floats.
- **Errors** map to `400` (validation), `401`, `403`, `404`, `409` (conflict), `410` (removed
  custodial endpoints), `413` (body over 64 KiB), `429` (budget exceeded), `504` (upstream
  Horizon exceeded a route timeout). There is no `422`.
