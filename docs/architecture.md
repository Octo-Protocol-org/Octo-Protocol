# Architecture

octo is a Cargo workspace. The guiding rule: **secret material is confined to one crate**
(`wallet-core`), decrypted only in-memory at signing time, and zeroized immediately after.

## Crates

```
crates/
  crypto/       AES-256-GCM seal/open of a gas-tank seed (random nonce + salt). No Stellar knowledge.
  wallet-core/  The only code that touches secret keys (server-side: gas tank only):
                  - SEP-0005 (SLIP-0010 ed25519) derivation: m/44'/148'/<index>'
                  - muxed address (M...) encode/decode
                  - build + sign fee-bump envelopes, then zeroize
  chain/        Chain-agnostic boundary: the ChainAdapter trait, CAIP-2 ChainId, and a capability
                model. Stellar is the first adapter — a thin forwarding layer over wallet-core.
                See "The ChainAdapter boundary" below.
  resilience/   Retry with backoff + circuit breaker for outbound Horizon calls.
  store/        Postgres models + migrations (sqlx).
  webhooks/     HMAC-SHA256 signed outbound webhooks with retry + delivery log.
  ingest/       Horizon payment streaming + durable cursor → deposit detection & attribution.
  api/          axum REST API (wallets, addresses, submit-signed, sponsorship, webhooks).
bin/
  server/       Composes api + ingest into one process (splittable later to scale).
  migrate-keys/ Offline backfill that re-seals gas-tank seeds under a new master key
                (zero-downtime rotation; skips client-custody rows, which hold no seed).
```

## Request flows

### Create master wallet (non-custodial)
The **client** generates the BIP39 mnemonic and derives the base keypair (`m/44'/148'/0'`) in the
browser/SDK. It sends `api` only the public account (`G...`), plus an optional `encrypted_backup`
blob it encrypted under the user's password. `store` persists the public key, the opaque blob and
`custody = 'client'` — **no seed, no mnemonic, ever.** On testnet, friendbot funds the account so
it exists on-chain.

### Generate a customer address
`api` atomically increments the wallet's id counter → `wallet-core` encodes a muxed `M...` from
the base `G...` + id → `store` saves the row. **No on-chain operation.** The response also returns
the `G...` + numeric-memo fallback for senders that don't support muxed.

### Detect a deposit
`ingest` streams the master account's payments from Horizon (with a persisted cursor). Each
payment is attributed to a customer by its **muxed id** or **memo id**, recorded as a `deposit`
transaction, and a signed webhook fires.

For the full contract around cursor resume, dedup, reorg handling, and the quarantine path
see [`docs/ingest-integration.md`](ingest-integration.md).

### Move funds out (client-signed)
The client fetches `GET /signing-info` (sequence, network passphrase, base fee), builds and
**signs the transaction locally**, then relays it via `POST /submit-signed`. `api` validates the
envelope and submits it to Horizon **unmodified** → record + webhook on confirmation. Horizon's
result codes are passed back so the client can correct and re-sign.

The custodial `POST /withdraw` and `POST /trustlines` endpoints are `410 Gone` tombstones.

## Signing safety

The user's key is never on the server, so there is no server-side signing path for user funds —
and therefore no signing oracle to abuse. What `api` does on the submit path is *validate*:

1. Envelope is a v1 `Tx` (not a fee-bump wrapper smuggled in).
2. At least one signature is present.
3. The source account **is this wallet**.
4. Every operation is on the allowlist (payment / path-payment / change-trust).
5. Submit verbatim — the server never re-signs or alters the transaction.

### The one server-held key: the gas tank
Fee sponsorship still needs a server signature, so a wallet may provision a **gas tank**: a
separate account holding fee float only. Its seed is the only plaintext key material on the
server, and it is confined to one crate:

1. Retrieve the encrypted gas-tank seed from `store`.
2. `crypto::open` decrypts in-memory (AES-256-GCM; tag verifies integrity, network bound as AAD).
3. `wallet-core` derives the private key via SEP-0005.
4. Sign **only the outer fee-bump envelope** — the user's inner transaction is untouched.
5. `zeroize` the seed and key buffers.

Keys are never written to disk or logs and are never persisted in derived form. Worst-case
exposure of this key is the gas budget — never customer balances.

## The ChainAdapter boundary

octo started Stellar-only, which let chain-specific concepts leak directly to callers:
`crates/api/src/state.rs` imports `StellarNetwork`, `crates/ingest/src/lib.rs` calls
`decode_muxed`, and route handlers reason about XDR. That's fine for one chain; it does not scale
to a second one (see `docs/ethereum-expansion-issues.md`) without a `match` on chain kind spreading
into every call site. `octo-chain` is the fix: a `ChainAdapter` trait that `octo-api` and
`octo-ingest` are meant to depend on instead of any one chain's crate or wire format.

**What belongs in an adapter:**
- Chain identity (`ChainId`, CAIP-2 — see AD-1 in `docs/ethereum-expansion-issues.md`) and what
  the chain can do (`ChainCapabilities`: memos, muxed addresses, reorgs, native decimals).
- Address grammar: validating a string is a well-formed address, and normalizing the different
  valid forms of "the same" address to one canonical form.
- Shaping a customer deposit address for that chain (`DepositAddress`): a single muxed-style
  address for chains that support it, or the seam where a chain without that capability must
  instead derive a distinct on-chain address per customer.
- Translating a chain-native failure/result code into a sentence a merchant dashboard can show.
- Calling out to that chain's own signing/derivation crate (for Stellar, `octo-wallet-core`) to do
  the above — never reimplementing chain logic that already exists elsewhere.

**What belongs in business logic (`octo-api`, `octo-ingest`), not an adapter:**
- What to *do* with a validated address or a derived deposit address: allocating a customer id,
  persisting a row, firing a webhook, deciding when a deposit is safe to credit. None of that
  varies by chain in a way the adapter needs to know about.
- Anything involving Octo's own store, webhooks, or email — an adapter never touches `octo-store`
  directly.

**What must never be in `octo-chain`:** raw key material, or a dependency on `octo-crypto`. An
adapter holds secrets the same way business logic would — by delegating to a chain's own signing
crate — never by embedding key handling in this crate. `octo-chain` defines shapes; adapters
supply behaviour.

The trait is a small required core plus a capability description
(`fn capabilities(&self) -> ChainCapabilities`), not the union of every field Stellar and EVM need
— Stellar has muxed addresses and no reorgs, EVM has reorgs and no memos, and a trait that unions
both would rot as more chains are added. It is `Send + Sync + 'static` and object-safe
(`Arc<dyn ChainAdapter>`), since `AppState` is cloned across every Axum handler and
`octo-ingest`'s supervisor spawns one task per wallet. A `ChainRegistry` maps each configured
`ChainId` to its adapter, returning `ChainError::UnsupportedChain` rather than panicking on an
unconfigured chain.

`crates/chain/src/conformance.rs` is a reusable test harness (`chain_conformance_suite`) that
checks an adapter behaves consistently with its own declared capabilities — deterministic
derivation, idempotent normalization, no panics on garbage input. Every adapter, including the
future EVM one, is expected to pass it.

This issue lands the trait and the Stellar adapter only, as a pure refactor — `octo-api` and
`octo-ingest` still call `octo-wallet-core` directly today. Wiring `AppState` and the ingest
supervisor through a `ChainRegistry` is follow-up work once a second adapter exists to prove the
boundary is right, not something to guess at with only one chain implemented.
