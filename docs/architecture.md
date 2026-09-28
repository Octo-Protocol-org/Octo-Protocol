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

The custodial `POST /withdraw` endpoint is a `410 Gone` tombstone. `POST /trustlines` validates the
asset and returns ChangeTrust signing info (sequence, passphrase, fee, limit); the client signs
locally and relays via `submit-signed`.

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

### Entropy source (load-bearing)
Every server-generated mnemonic comes from `WalletSeed::generate` (`wallet-core/src/derive.rs`),
which fills 128 bits of entropy from `rand::rngs::OsRng` (the OS CSPRNG, `getrandom(2)`) and
calls `Mnemonic::from_entropy`. It deliberately bypasses tiny-bip39's `Mnemonic::new`, whose
`thread_rng()` source depends on a default crate feature and a `rand` implementation detail.
`crypto::seal` uses the same `OsRng` for nonces and salts. Any bump of `tiny-bip39` or `rand`
must re-confirm this path stays OS-backed.

## Wallet Foreign Key Constraints

Wallets are intended to be permanent master records. To prevent accidental cascading deletions or silent orphaned records, all tables referencing `wallets(id)` enforce `ON DELETE RESTRICT`:

| Table | Column | Initial Migration Constraint | Intended & Enforced Constraint |
| --- | --- | --- | --- |
| `addresses` | `wallet_id` | `ON DELETE CASCADE` (0001) | `ON DELETE RESTRICT` (0021) |
| `transactions` | `wallet_id` | `ON DELETE CASCADE` (0001) | `ON DELETE RESTRICT` (0021) |
| `withdrawals` | `wallet_id` | `ON DELETE CASCADE` (0001) | `ON DELETE RESTRICT` (0021) |
| `webhook_endpoints` | `wallet_id` | `ON DELETE CASCADE` (0001) | `ON DELETE RESTRICT` (0021) |
| `ingest_cursor` | `wallet_id` | `ON DELETE CASCADE` (0001) | `ON DELETE RESTRICT` (0021) |
| `api_keys` | `wallet_id` | `ON DELETE CASCADE` (0005) | `ON DELETE RESTRICT` (0021) |
| `gas_sponsorship_configs` | `wallet_id` | `ON DELETE CASCADE` (0007) | `ON DELETE RESTRICT` (0021) |
| `sponsored_transactions` | `wallet_id` | `ON DELETE CASCADE` (0007) | `ON DELETE RESTRICT` (0021) |
| `withdrawal_allowlist_configs` | `wallet_id` | `ON DELETE CASCADE` (0013) | `ON DELETE RESTRICT` (0021) |
| `whitelisted_addresses` | `wallet_id` | `ON DELETE CASCADE` (0013) | `ON DELETE RESTRICT` (0021) |
| `payment_links` | `wallet_id` | `ON DELETE CASCADE` (0014) | `ON DELETE RESTRICT` (0021) |
