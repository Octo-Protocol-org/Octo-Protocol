# octo Threat Model

> **Honest scope.** No system is "safe against all hacks." This document enumerates the attack
> classes that actually apply to octo's architecture, the concrete defense for each, and the step
> that enforces it. It is a living document — every new feature must say which of these it touches.

## What octo is (for threat-modeling)

octo is a **non-custodial backend service**. A user's wallet key is generated and held
**client-side** (browser/SDK); the server stores only the public account and an opaque backup
blob the client encrypted under the user's password. The server **cannot sign for a user wallet
and cannot decrypt that blob.** It validates client-signed transactions and relays them.

The one exception — and it is the important one for this document — is the per-wallet **gas
tank**: a separate, server-held account carrying *fee float only*, used to sign fee-bump
envelopes for gas sponsorship. That is the sole plaintext key material on the server, and its
worst-case exposure is the gas budget, never customer balances.

octo is **not** a smart-contract system. Therefore the famous web3 exploit classes that assume
on-chain contracts **do not apply**:

| Classic web3 hack | Applies to octo? | Why |
|---|---|---|
| Reentrancy, delegatecall, proxy bugs | ❌ | No smart contracts. We send native Stellar payment ops. |
| Flash-loan / oracle manipulation | ❌ | We don't price or lend. |
| Bridge / cross-chain exploits | ❌ (MVP) | No bridging in the MVP. |
| `tx.origin`, integer overflow in Solidity | ❌ | Not Solidity. Rust + checked arithmetic. |
| Approval / `permit` phishing | ❌ | No ERC-20 allowances on Stellar. |

octo's **real** threat surface is the **submit path** (validating client-signed transactions
before relaying them), the **gas-tank key**, **deposit accounting**, and ordinary web2 backend
security. Note what moved off this list: "an attacker steals the user seed from the server" is no
longer a threat, because there is no such seed to steal. That single change removes the category
responsible for the largest share of real-world crypto theft.

---

## Threat classes that DO apply, and our defenses

### A. Key & seed compromise  *(highest severity — 44% of 2024 crypto theft was key compromise)*
| Threat | Defense | Step |
|---|---|---|
| **User seed stolen from the server** | **Structurally impossible: the server never has it.** Keys are generated client-side; only the public account is transmitted. A total compromise of the API, DB and backups yields no user key | cutover |
| User key backup stolen from DB dump / backup | `encrypted_backup` is ciphertext the **client** produced under the user's password (PBKDF2→AES-256-GCM in the browser). octo stores it opaquely and holds no password or key to open it | cutover |
| Gas-tank seed stolen from DB dump / backup | Seed stored **AES-256-GCM encrypted**, random nonce+salt; master key from KMS/secret-manager, never in the DB or repo. **Loss is bounded by the gas budget — no customer funds** | 3, 5 |
| Seed/keys leaked via logs, crash dumps, swap | Secrets live only in `wallet-core`; `Zeroizing` wrappers wipe seed & derived keys on drop; `Debug` never prints secret bytes; `unwrap`/`panic` denied by clippy there | 3, 4 |
| Master key lingering in memory / core dumps | `MASTER_KEY`, `MASTER_KEY_NEXT` and `AUDIT_CHAIN_KEY` are read into `Zeroizing` buffers, decoded into a fixed zeroizing buffer (no reallocating `Vec`), held as `Zeroizing<[u8; 32]>` and removed from the process environment before the runtime starts any threads. **Limitation:** see "Env-based secrets" below | #434 |
| Master key compromise | KMS-held key; zero-downtime rotation via `sealed_scheme` + `bin/migrate-keys`; defense-in-depth so DB-only compromise is insufficient. Only gas tanks are affected. Procedure: [runbook-key-rotation.md](runbook-key-rotation.md) | 3, rotation |
| Weak randomness in key/nonce generation | Use `OsRng` (CSPRNG) only; never `rand::thread_rng` seeded predictably for key material; test that two seals of same plaintext differ | 3, 4 |
| Derived key reused across contexts | One derivation path per account; keys are ephemeral and zeroized | 4 |
| **User loses password *and* recovery phrase** | **Accepted, unavoidable consequence of non-custody:** octo cannot reset or recover the wallet. This is a deliberate trade — the same property that makes a server breach harmless makes recovery impossible without the user's own secrets. Must be stated plainly in any product UI | product |

### B. Submit-path abuse  *(the relay must not become a "sign anything" oracle)*
| Threat | Defense | Step |
|---|---|---|
| Attacker gets octo to sign an arbitrary/malicious tx **for a user wallet** | **No key exists server-side to coerce.** The submit path only *validates and relays* — it never signs or alters a user transaction | cutover |
| Malicious/forged XDR relayed via `submit-signed` | Validated before relay: must be a v1 `Tx` envelope, carry ≥1 signature, have **source account == this wallet**, and use only allowlisted operations (payment / path-payment / change-trust). Tampering invalidates the client's signature, so Horizon rejects it | 10 |
| Confused-deputy: API caller moves others' funds | The relayed transaction must be signed by the wallet's own key, which the caller does not have. Wallet routes are additionally scoped to the authenticated tenant | 6, 10 |
| Fee/op injection (set-options, merge-account) | Operation-type allowlist rejects `ACCOUNT_MERGE`, `SET_OPTIONS`, and anything else outside the allowlist, on both the submit and sponsor paths | 10 |
| Fee-bump abuse (sponsorship) | The gas tank signs **only the outer fee-bump envelope**; the user's inner tx is passed through untouched. Self-sponsorship rejected. Per-tx fee cap + daily budget reserved atomically under a per-wallet advisory lock (a plain conditional insert raced under READ COMMITTED and over-spent) | sponsorship |

### C. Deposit accounting attacks  *(how exchanges actually get double-spent)*
| Threat | Defense | Step |
|---|---|---|
| **Double-credit on failed/reorged tx** (the Mt. Gox class) | Only credit deposits with `successful == true` from Horizon; key off the **immutable tx hash + operation id**; idempotent insert (unique constraint) so replays can't double-credit | 8 |
| **Memo-less / wrong-memo deposit** misattribution | Attribute strictly by muxed id **or** a valid numeric memo id that maps to a known address; unmatched deposits go to a **quarantine/unattributed** state, never auto-credited to a guess | 8 |
| Replayed Horizon events | Cursor is monotonic + dedup by tx hash; reprocessing the same payment is a no-op | 8 |
| Spoofed asset / fake token deposit | Credit only **whitelisted assets** (issuer + code must match an enabled asset); ignore unknown trustlines/tokens | 8, later (asset mgmt) |
| Claimable-balance side-channel | Treat claimable balances explicitly; credit only on a successful `claim_claimable_balance` **by the master account**, for the amount in its `account_credited` effect; reclaims of our own balances are not deposits (see `docs/deposit-model.md`) | 8, #448 |
| Dust / griefing to inflate accounting | Minimum-amount thresholds; amounts stored as exact integers (stroops), never floats | 8 |

### D. Outbound transfer attacks
> Since the cutover these are largely enforced **by Stellar itself**, not by octo — the client
> signs over the exact destination, amount and sequence number, so the network rejects anything
> octo could alter in transit.

| Threat | Defense | Step |
|---|---|---|
| Double-spend via retried request | The signed transaction pins a **sequence number**; Stellar accepts it at most once. A replayed relay of the same signed XDR is rejected on-chain (`tx_bad_seq`) | protocol |
| Race / TOCTOU on balance | Not octo's to arbitrate: the ledger enforces sufficient balance atomically at apply time (`op_underfunded`) | protocol |
| Amount precision bug (float rounding) | All amounts are integer **stroops** end-to-end; convert at the edge only | 4, 10 |
| Destination tampering in transit | TLS everywhere — **and** the destination is inside the client's signature, so any modification by octo or a MITM invalidates the transaction | 10 |
| Sponsored fee double-charge | Sponsorship dedups on the **inner transaction hash** (unique index → `409`), so the same user tx cannot be fee-bumped twice out of the budget | sponsorship |

### E. Web2 backend surface  *(the unglamorous majority of real breaches)*
| Threat | Defense | Step |
|---|---|---|
| SQL injection | `sqlx` parameterized queries only; no string-built SQL. Blast radius limited by a non-owner runtime role with DML only ([postgres-roles.md](postgres-roles.md)) | 5 |
| AuthN/AuthZ bypass | Dashboard JWT **or** per-wallet API key, with per-route authorization. Sensitive actions (gas-tank provisioning, key-backup read, API-key management) require a JWT and reject API keys. Key-backup reads are rate-limited per user (5/hour) and refuse to serve without writing an audit row | 6 |
| Stolen session token stays valid | Tokens carry a unique `jti`; `logout` **and** `refresh` deny-list the presented token, and every authenticated request checks the deny-list. (Refresh previously re-issued without revoking, and could even return a byte-identical token) | 6 |
| Compromised device keeps a live session | Every token names a `sessions` row (`sid`). Users list sessions and revoke any one, or all others (which also bumps `session_epoch`, killing pre-session tokens); the per-request check rejects a revoked session immediately. Queries are scoped by user id, so another user's session id is a `404` | #435 |
| OTP brute force via parallel guesses | Each attempt is claimed atomically (`attempts < OTP_MAX_ATTEMPTS`, the module constant in `crates/store/src/otps.rs`, in the same `UPDATE` that increments it) before the code is compared, and consumption is conditional, so concurrent guesses can't exceed the cap and one code can't be redeemed twice. (Previously read-then-increment let a burst of parallel guesses all see `attempts = 0`) | #435 |
| Stolen session deletes or exports an account | Both require the current password **and** an emailed OTP with its own purpose (an export code can't delete), capped at 5 attempts per user per hour. Deletion is refused while any wallet or gas tank holds funds, fails closed if Horizon can't confirm, and aborts if the wallet set changed after the check. Exports are built from explicit views, so no hash, seed, backup or webhook secret can leak | #466 |
| Credentials leaking into logs | `tests/log_secret_tests.rs` captures all tracing output at TRACE through the auth, API-key, gas-tank, withdrawal-OTP and password-reset flows and fails on any token, API key, OTP code, password or BIP39 phrase | #436 |
| SSRF via webhook/Horizon URLs | `is_safe_url` blocks loopback, private, link-local, carrier-grade-NAT, reserved/documentation, and other non-routable targets — IPv4 **and bracketed IPv6** (a naive `:`-split previously let `[fe80::1]` through). `OCTO_ALLOW_LOCAL_WEBHOOKS=1` is limited to development/tests and is rejected during mainnet startup | 9 |
| Webhook forgery / tampering | Outbound webhooks **HMAC-SHA256 signed**; consumers verify. Inbound (if any) verified | 9 |
| Replay of API requests | TLS; mutating on-chain actions are pinned by the signed transaction's sequence number, so a replay is rejected on-chain | 10 |
| Secrets in env/CI logs | `.env` git-ignored; CI uses masked secrets; no secret echoed in logs | 2 ✓ |
| Dependency supply-chain (malicious/yanked crate) | `cargo-deny` (advisories + licenses + yanked) in CI; pinned `Cargo.lock`; MSRV-locked tree | 2 ✓ |
| DoS / resource exhaustion | Request limits, timeouts, connection pool caps (`DB_*`) and a per-connection `statement_timeout`; pagination bounds | 6, 11 |
| Rate limits multiplied by replica count / reset by restarts | Counters shared in Postgres (`rate_limit_buckets`, atomic upsert); `X-Forwarded-For` hop must parse as an IP, so junk headers cannot mint unbounded keys | 11 |
| Dust-payment flood starving other wallets' deposits | Ingest polls round-robin, one page per turn, with a per-wallet per-tick record budget; the backlog carries over via the cursor | 7 |
| Two ingest replicas burning Horizon quota / racing cursors | Postgres advisory lock elects one ingest leader per network; the leader re-verifies the lock before each tick (`docs/ha-topology.md`) | 7 |
| Information leak in errors | Typed errors; no internal detail or secret in API responses | 5, 6 |

### E.1 Trusted proxies and client IP derivation
Rate-limit buckets are keyed on the client IP, so *how* that IP is derived is itself a security
control. `client_ip()` in `crates/api/src/rate_limit.rs` only honors `X-Forwarded-For` when the
socket peer address matches `TRUSTED_PROXY_CIDRS`; it then walks the header **right-to-left**,
skipping hops that are themselves trusted proxies, and falls back to the socket peer IP
otherwise. A spoofed header from an untrusted source is therefore ignored.

- **Assumption:** the deployment terminates TLS at a proxy whose CIDRs are listed in
  `TRUSTED_PROXY_CIDRS`, and no untrusted hop can reach the API directly (the API is not
  exposed without passing through the proxy).
- **Owner:** deployment operator.
- **Check:** configuration review of `TRUSTED_PROXY_CIDRS` against the actual ingress CIDRs,
  plus a runtime probe that sends a spoofed `X-Forwarded-For` from an untrusted source and
  confirms the resulting bucket key is the peer IP, not the header value.

### E.2 Rate limiter scope and replica multiplication
`RATE_LIMIT_BACKEND` defaults to `postgres` in `bin/server/src/main.rs`, giving counters shared
across replicas that survive restarts. In `memory` mode the effective limit is multiplied by the
replica count and resets on every restart. If the shared backend errors, `RateLimiter::check`
degrades to the per-process fallback rather than failing open entirely.

- **Assumption:** production sets `RATE_LIMIT_BACKEND=postgres` and the `rate_limit_buckets`
  table is reachable from every replica.
- **Owner:** API team.
- **Check:** a startup log line naming the selected backend, plus an integration test that
  exceeds a limit across two replicas and confirms the shared counter enforces it.

### E.3 CORS policy and allowed origins
`build_router` in `crates/api/src/lib.rs` parses `ALLOWED_ORIGINS` (comma-separated) and
defaults to an **empty allow-list** — no cross-origin browser access — permitting only the
listed methods and headers.

- **Assumption:** `ALLOWED_ORIGINS` is set to the exact production frontend origins and is
  never `*`.
- **Owner:** deployment operator.
- **Check:** configuration review of `ALLOWED_ORIGINS`, plus a preflight request from an
  unlisted origin that must be rejected.

### F. Operational / process
| Threat | Defense | Step |
|---|---|---|
| Unsafe Rust memory bugs | `#![forbid(unsafe_code)]` in every crate (already set) | 2 ✓ |
| Panics that crash or leak | `clippy::unwrap_used`/`expect_used` denied in `wallet-core`; errors propagated | 3, 4 |
| No audit trail | Append-only transaction + webhook-delivery logs; `audit_logs` UPDATE/DELETE/TRUNCATE blocked by DB triggers (`0026`) | 5, 9 |
| Wrong master key / broken RNG discovered only at first signature | Startup self-test (`octo_api::self_test`): canary seal/open + RNG sanity per key, then opens the newest stored sealed row; any failure aborts boot | 4 |
| Audit log edited by someone with DB access | Per-user HMAC hash chain (`AUDIT_CHAIN_KEY`, never stored in the DB) plus a MAC'd chain head: any edit, deletion or truncation fails `octo-server verify-audit-chain`. Appends are serialized per user by an advisory lock; a `UNIQUE (user_id, seq)` index backstops it. See `docs/audit-log.md` for limits | #437 |
| Disaster recovery (user wallet) | **The user's responsibility, by design.** Recovery is via their BIP39 mnemonic, or the password-encrypted backup blob octo stores but cannot read. octo has no ability to recover a wallet whose owner has lost both | cutover |
| Disaster recovery (gas tank) | Gas-tank seeds are server-held and covered by DB backup + master-key rotation (`bin/migrate-keys`). Backups and keys must be held in **separate custody** — a backup without the master key is useless, and the master key without the backup is useless; never co-locate them. Restore drill and custody guidance: [runbook-backup-restore.md](runbook-backup-restore.md) | rotation |
| Master key / JWT secret rotation done ad hoc | Step-by-step rotation procedure with rollback, verification queries and expected downtime: [runbook-key-rotation.md](runbook-key-rotation.md) | rotation |
| Schema migrations silently not applied | sqlx keys migrations by version number, so two files sharing a version means only one ever runs. A test pins the exact applied version set — this had already happened five times before it was caught | 5 |
| Login email enumeration through response timing | Unknown-email logins verify against a precomputed dummy Argon2 hash, matching the expensive work performed for a known email with a wrong password | auth |

---

## Enforced continuously (CI gates)
- `cargo-deny` — advisories, yanked crates, license policy.
- `cargo clippy --all-targets -D warnings` — plus secret-safety lints in `wallet-core`/`crypto`.
- `cargo test --workspace` — including the OpenAPI **drift test**, which validates live responses
  against `docs/openapi.yaml` so the spec cannot silently diverge from the code.
- Tests must include **negative** cases (tamper, replay, wrong-asset, double-spend).
- (Planned) `cargo audit`, secret-scanning, and a fuzz target for derivation/decode.

> **A CI gate that cannot start is not a gate.** These commands are correct, but a dev-dependency
> was committed to `Cargo.lock` at a version requiring a newer Rust than `rust-toolchain.toml`
> pins (`wiremock 0.6.5` needs edition2024 / 1.85; the toolchain is 1.84.1). With `--locked`,
> cargo fails at the *dependency-download* step — before compiling anything — so clippy and the
> test suite never executed, and a series of merges landed with a test suite that had never been
> run. Treat "CI failed to resolve dependencies" as a **red** result, never as infrastructure
> noise to be retried past.

## Known limitations (by design)
- **Browser-held keys shift risk to the client.** Removing the server-side key removes the
  server as a honeypot, but a compromised client (XSS, malicious extension, malware) can reach
  the key at unlock time. Encryption at rest does not help there — mitigation is a strict CSP,
  dependency hygiene, and eventually hardware-wallet signing.
- **Unrecoverable by design.** If a user loses both password and recovery phrase, the funds are
  gone; octo cannot help. This must be said plainly in product UI, not buried.
- **Env-based secrets can't be fully scrubbed.** The server wipes its own copies of
  `MASTER_KEY`/`MASTER_KEY_NEXT`/`AUDIT_CHAIN_KEY` and removes them from its environment, but
  the original strings stay in memory it doesn't own: the kernel's copy (`/proc/<pid>/environ`,
  readable by the same user or root), libc's initial environment block, and whatever the
  orchestrator or `.env` file holds. Treat the env as a delivery channel, not a vault: prefer a
  secret manager or KMS, and disable core dumps for the process (`ulimit -c 0` /
  `RLIMIT_CORE=0` in the container; this crate forbids the `unsafe` a `prctl` call would need).
- **Gas tank remains a hot key** (online, encrypted + zeroized + op-allowlisted). Exposure is
  bounded by the gas budget; MPC/HSM for this key is a later phase.

> If you add a feature, add its row(s) above and the test that proves the defense.