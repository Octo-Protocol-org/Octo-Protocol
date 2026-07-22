# Architecture

octo is a Cargo workspace. The guiding rule: **secret material is confined to one crate**
(`wallet-core`), decrypted only in-memory at signing time, and zeroized immediately after.

## Crates

```
crates/
  crypto/       AES-256-GCM seal/open of the HD seed (random nonce + salt). No Stellar knowledge.
  wallet-core/  The only code that touches secret keys:
                  - SEP-0005 (SLIP-0010 ed25519) derivation: m/44'/148'/<index>'
                  - muxed address (M...) encode/decode
                  - build + sign Stellar transactions, then zeroize
  store/        Postgres models + migrations (sqlx).
  webhooks/     HMAC-SHA256 signed outbound webhooks with retry + delivery log.
  ingest/       Horizon payment streaming + durable cursor → deposit detection & attribution.
  api/          axum REST API (wallets, addresses, withdrawals, transactions, webhooks).
bin/
  server/       Composes api + ingest into one process (splittable later to scale).
```

## Request flows

### Create master wallet
`api` → generate BIP39 mnemonic → `wallet-core` derives the base keypair (`m/44'/148'/0'`) →
`crypto` seals the seed (AES-256-GCM, random nonce+salt) → `store` persists ciphertext + `G...`.
On testnet, friendbot funds the account so it exists on-chain.

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

### Withdraw
`api` → `wallet-core` decrypts the seed in-memory, derives the key, signs a payment op, **zeroizes**
→ submit via Horizon → record + webhook on confirmation.

## Signing safety

1. Retrieve encrypted seed from `store`.
2. `crypto::open` decrypts in-memory (AES-256-GCM; tag verifies integrity).
3. `wallet-core` derives the private key via SEP-0005.
4. Sign the transaction.
5. `zeroize` the seed and key buffers.

Keys are never written to disk or logs and are never persisted in derived form.
