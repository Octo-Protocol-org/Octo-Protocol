# Architecture

octo is a Cargo workspace. The guiding rule: **secret material is confined to one crate**
(`wallet-core`), decrypted only in-memory at signing time, and zeroized immediately after.

## Crates

```
crates/
  crypto/       AES-256-GCM seal/open of a gas-tank seed (random nonce + salt). No Stellar knowledge.
  wallet-core/  The only code that touches Stellar secret keys (server-side: gas tank only):
                  - SEP-0005 (SLIP-0010 ed25519) derivation: m/44'/148'/<index>'
                  - muxed address (M...) encode/decode
                  - build + sign fee-bump envelopes, then zeroize
  evm-core/     The EVM counterpart of wallet-core — secp256k1 keys for EIP-155 chains:
                  - BIP-44 derivation: m/44'/60'/0'/0/<index> (note: non-hardened tail, unlike
                    wallet-core's all-hardened path — see the ADR below and the crate's own
                    module docs for why that matters)
                  - keccak-256 address derivation + EIP-55 mixed-case checksum
                  - low-s normalised (EIP-2) digest signing + signer-address recovery
  resilience/   Retry with backoff + circuit breaker for outbound Horizon / JSON-RPC calls.
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

## ADR: EVM crypto crate selection (k256 + sha3 + hand-rolled BIP-32, not alloy-primitives)

**Context.** `crates/evm-core` (#217) needs secp256k1 BIP-32/BIP-44 key derivation, keccak-256
EIP-55 addressing, and ECDSA signing with low-s (EIP-2) normalisation. Two realistic paths:

1. `k256` (arithmetic/ecdsa) + `sha3` (Keccak-256) + `hmac`/`sha2` (already workspace
   dependencies, reused for the BIP-32 `HMAC-SHA512` step) + `subtle` (constant-time comparisons),
   with the BIP-32 CKD-priv/CKD-pub walk written directly against `k256`'s `Scalar`/`SecretKey`
   types.
2. `alloy-primitives`/`alloy-signer` (or `coins-bip32` + `ethers`-family crates), which bundle
   address types, RLP, and higher-level signer abstractions on top of the same underlying curve
   arithmetic.

**Decision: (1) — `k256` + `sha3` + a from-scratch BIP-32 implementation.**

**Why.**
- **MSRV.** The workspace pins `rust-version = "1.84.1"` (`Cargo.toml`) with the MSRV-aware
  resolver (`.cargo/config.toml: incompatible-rust-versions = "fallback"`) keeping the whole tree
  on 1.84-compatible dependency versions. `alloy`'s workspace crates track a materially newer
  MSRV than 1.84 (the alloy project moves its floor forward aggressively, tracking recent stable
  releases) and pulls in a large, fast-moving dependency graph (RLP, ABI encoding, multiple signer
  backends, `alloy-consensus`, etc.) most of which this crate does not need — `evm-core` only
  needs derivation, addressing, and raw digest signing, not transaction encoding or provider
  plumbing. `k256`, `sha3`, and `subtle` are individually-versioned RustCrypto crates with a much
  lower, slower-moving MSRV floor that fits 1.84.1 today without pinning transitive versions by
  hand.
- **`cargo deny` surface.** `deny.toml` allows a fixed, small set of permissive licenses and warns
  on multiple-versions/wildcards. `k256`/`sha3`/`hmac`/`sha2`/`subtle` are RustCrypto-ecosystem
  crates already partially present in the tree (`hmac`, `sha2` are workspace deps of
  `wallet-core`'s SEP-0005 path already; `k256`'s own dependency graph — `elliptic-curve`,
  `ecdsa`, `ff`, `group` — is the same family already vetted for `wallet-core`'s ed25519 stack in
  spirit) and license MIT/Apache-2.0, both allowed. Pulling in `alloy-primitives`'s graph would add
  a much larger number of net-new crates (and net-new maintainers/publishers) to audit for the
  same `deny.toml` policy, for functionality (RLP, typed transactions, provider traits) this crate
  does not use.
- **No signing-oracle surface.** `alloy-signer`'s `Signer` trait is designed around signing
  `alloy`'s typed transaction/message types. Taking a dependency on it would pull the crate's
  public API toward "hand me a transaction, I'll sign it" — the opposite of the "no raw-XDR
  oracle" posture `wallet-core/src/signer.rs` established and this crate's `signer.rs` explicitly
  mirrors (sign a caller-supplied 32-byte digest, nothing else; the caller builds whatever
  domain-specific hash it needs).
- **Auditability.** BIP-32 CKD-priv is ~40 lines of scalar arithmetic over `k256::Scalar`
  (`crates/evm-core/src/derive.rs`). Writing it directly against `k256` keeps every step —
  including the "must not be transparently retried" analogue for key derivation, i.e. the
  constant-time invalid-scalar/zero-key rejection required by the BIP-32 spec — visible and
  testable against the spec's own test vectors, rather than trusting an external crate's
  derivation path parser to have the same constant-time discipline this codebase requires
  elsewhere (see `crates/crypto` and `wallet-core`'s zeroize-on-drop conventions).

**Consequence.** `evm-core` carries slightly more from-scratch cryptographic code (the BIP-32 walk)
than it would with a higher-level SDK, in exchange for a materially smaller, MSRV-compatible,
easier-to-audit dependency graph and an API shape consistent with the rest of the codebase's
signing-oracle posture. If a future issue needs RLP/typed-transaction encoding (e.g. building and
broadcasting a legacy or EIP-1559 transaction), that belongs in a higher-level crate that depends
on `evm-core` for keys/signing — not a reason to pull `alloy-primitives` into this one.
