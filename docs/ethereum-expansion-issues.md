# Octo → Ethereum Ecosystem: Contributor Issue Set

**Epic:** Extend Octo from a Stellar-only payment backend to a multi-chain backend whose first
additional ecosystem is Ethereum/EVM (Ethereum L1, Base, Arbitrum, Optimism, Polygon).

**Status:** Planning — issues below are ready to be filed.
**Audience:** external contributors. Every issue is self-contained: it names the files to touch,
the invariants that must not break, and how a reviewer will verify the work.

---

## 1. Why this is not a "add a second chain" refactor

Octo's current design is *correct because* of properties Stellar has and EVM chains do not. Four
of those properties are load-bearing and each one forces real design work rather than a port:

| Stellar property Octo relies on | EVM reality | Consequence |
|---|---|---|
| **Muxed accounts** (`M...`): one base account + a 64-bit customer id means unlimited per-customer deposit addresses with *zero* on-chain accounts, zero reserve, and no sweeping. See [`crates/wallet-core/src/address.rs`](../crates/wallet-core/src/address.rs) and [`docs/deposit-model.md`](./deposit-model.md). | No equivalent. There is no way to tag an inbound ERC-20 `Transfer` with a customer id. | Per-customer deposit addresses must be **real HD-derived EOAs**, which then require a **sweep engine** to consolidate funds and a **gas funding** story for each sweep. Issues #8 and #12. |
| **Instant finality, no reorgs.** A `transaction_successful` payment is final, so [`crates/ingest/src/lib.rs`](../crates/ingest/src/lib.rs) can credit on first sight and dedup on the immutable TOID. | Blocks reorg. A credited deposit can be un-mined. | Credit must be gated on **confirmation depth**, and a **reorg detector** must be able to reverse a credit. This is the single highest-risk correctness item in the epic. Issue #10. |
| **7-decimal integer stroops fit `i64`.** The schema stores `amount_stroops BIGINT` throughout ([`0001_init.sql`](../crates/store/migrations/0001_init.sql)). | ETH is 18 decimals; token amounts are `uint256`. `1 ETH = 10^18` — a single ETH-denominated balance can exceed `i64::MAX` (~9.22 × 10^18) at ~9.22 ETH. | The amount column and every model/serializer must move to arbitrary precision **before** any EVM value touches the database. Issue #3, and it blocks most of Phase 3. |
| **Trustlines** are an explicit on-chain opt-in, so Octo can enumerate what a wallet accepts ([`crates/api/src/routes/trustlines.rs`](../crates/api/src/routes/trustlines.rs)). | ERC-20 has no trustline. Any address can receive any token, including worthless or malicious ones. | Octo needs a curated **token registry** as the authority on what is creditable, plus explicit handling of unsolicited tokens. Issue #11. |

A fifth, softer point: [`crates/crypto`](../crates/crypto/src/lib.rs) is already chain-agnostic (it
authenticated-encrypts bytes and knows nothing about Stellar). It is reused as-is. Do **not**
fork it.

---

## 2. Architecture decisions (settled — do not relitigate in a PR)

These were decided up front so that fifteen contributors do not each invent a different answer.
If you believe one is wrong, open a discussion issue rather than deviating inside a feature PR.

- **AD-1 — Chain identity uses [CAIP-2](https://chainagnostic.org/CAIPs/caip-2).** Chains are
  identified by string slug: `stellar:pubnet`, `stellar:testnet`, `eip155:1`, `eip155:8453`.
  Assets use [CAIP-19](https://chainagnostic.org/CAIPs/caip-19)
  (`eip155:1/erc20:0xA0b8...`). This avoids inventing a private taxonomy and makes the public
  API self-describing.
- **AD-2 — Abstraction is a trait, not an enum.** A `ChainAdapter` trait in a new `octo-chain`
  crate. Adding a chain must not require editing a `match` in twelve files.
- **AD-3 — Amounts are stored as `NUMERIC(78,0)`** (78 digits covers `uint256`, max ≈ 1.16 × 10^77)
  with `decimals` carried by the token registry, never inferred. **Amounts cross the API boundary
  as JSON *strings*** — a `uint256` is not representable in an IEEE-754 double and JS clients
  would silently corrupt it.
- **AD-4 — Octo stays non-custodial for user funds.** The server never holds a user's spending key.
  Two exceptions already exist in the Stellar design and carry over: the **gas tank** (fee float
  only) and — new for EVM — **deposit-address sweep keys**, which hold customer funds transiently.
  Sweep keys are the largest new attack surface in this epic; see #12.
- **AD-5 — The submit-asymmetry rule holds.** [`octo-resilience`](../crates/resilience/src/lib.rs)
  distinguishes `CallKind::Read` (retryable) from submits (not retryable). Blind retry of an EVM
  broadcast is *usually* safe because of nonces but is **not** safe once gas-price replacement is
  in play. Keep submits non-retried at the transport layer; handle replacement explicitly (#14).
- **AD-6 — No new chain may regress Stellar.** Stellar behaviour is the compatibility baseline.
  The existing suites — [`crates/ingest/tests/`](../crates/ingest/tests/),
  [`crates/api/tests/`](../crates/api/tests/), [`crates/store/tests/`](../crates/store/tests/) —
  must pass unmodified except where an issue explicitly authorises a change.

### Dependency-conscious note on crate selection

`ethers-rs` is deprecated; prefer the [`alloy`](https://github.com/alloy-rs/alloy) stack. **However
this workspace pins Rust 1.84.1** ([`rust-toolchain.toml`](../rust-toolchain.toml)) and enforces
`cargo deny check` ([`deny.toml`](../deny.toml)). Recent `alloy` releases have raised their MSRV
past 1.84. **Issue #5 owns resolving this** and its outcome is binding on #6, #13, and #14: either
(a) a compatible `alloy` version is pinned, (b) the MSRV is raised workspace-wide with sign-off, or
(c) we use the narrower `k256` + `sha3` + `bip32` primitives directly. Do not assume an answer —
read #5's resolution before starting a dependent issue.

---

## 3. Dependency graph

```
Phase 1 — chain-agnostic foundation (blocks everything)
  #1 octo-chain trait + Stellar adapter
  #2 multi-chain schema migration          ← depends on #1
  #3 arbitrary-precision amounts           ← depends on #2
  #4 per-chain config & registry           ← depends on #1

Phase 2 — EVM primitives (parallelisable once #1 lands)
  #5 octo-evm-core (keys, addresses)       ← depends on #1
  #6 octo-evm-rpc (JSON-RPC client)        ← depends on #5
  #7 Anvil integration harness             ← depends on #6

Phase 3 — inbound / deposits
  #8  EVM deposit address model            ← #2, #5
  #9  EVM ingest worker                    ← #6, #8, #11
  #10 confirmation depth + reorg handling  ← #9    ⚠ highest risk
  #11 ERC-20 token registry                ← #2, #3
  #12 sweep engine                         ← #8, #13, #14   ⚠ holds customer funds

Phase 4 — outbound
  #13 EVM signed-transaction relay         ← #6, #11
  #14 nonce / gas / tx lifecycle           ← #13
  #15 multi-chain API surface + OpenAPI    ← #3, #4, #8, #13
```

**Good first issues:** #7, #11. **Do not start #10 or #12 as a first contribution** — both can
lose customer funds if wrong, and both require a maintainer as co-reviewer.

---

## 4. Conventions every issue inherits

**Branch naming:** `<type>/<short-kebab-summary>`, matching existing history
(`feat/email-otp-signup-withdrawal`, `fix/signup-otp-rollback`, `chore/add-bruno-api-test-collection`).

**Commits:** [Conventional Commits](https://www.conventionalcommits.org/), per
[`CONTRIBUTING.md`](../CONTRIBUTING.md).

**Local gate before pushing:**
```bash
just fmt-check      # cargo fmt --all -- --check
just test           # cargo test --workspace
just lint           # cargo clippy --workspace --all-targets -- -D warnings
cargo deny check    # licences + advisories
```
`just check` runs the subset that works on every toolchain. If you hit
`E0514: found crate X compiled by an incompatible version of rustc`, run `cargo clean` — see the
troubleshooting note in [`CONTRIBUTING.md`](../CONTRIBUTING.md).

**Global Definition of Done** — a PR is not reviewable until all of these hold:

1. `just ci` is green (or CI is green if your toolchain hits the clippy E0514 issue).
2. **No Stellar regression.** The full pre-existing suite passes unmodified. If your issue
   authorises a test change, the PR description says which and why.
3. **New public items carry doc comments** in the established style: state the invariant and *why*
   it holds, not just what the function does. Read
   [`crates/store/src/lib.rs`](../crates/store/src/lib.rs) or
   [`crates/crypto/src/lib.rs`](../crates/crypto/src/lib.rs) for the register expected.
4. **Secret-handling code** lives behind `zeroize`, and the crate carries the same lint wall used
   by `crypto`/`wallet-core`:
   `#![forbid(unsafe_code)]`,
   `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`,
   `#![deny(clippy::cast_possible_truncation, clippy::cast_sign_loss)]`.
5. **Never log** seeds, private keys, decrypted material, or full signed transactions.
6. **Migrations are append-only and forward-only.** Never edit a merged migration file. The
   highest merged migration is `0020_username`; take the next free number and rebase if you collide.
7. **OpenAPI stays in sync.** [`docs/openapi.yaml`](./openapi.yaml) is enforced by
   [`crates/api/tests/drift_tests.rs`](../crates/api/tests/drift_tests.rs). An API change with no
   spec change is a failing PR.
8. **Security-relevant changes update [`docs/threat-model.md`](./threat-model.md).**

**PR description template:** what changed and why · which issue it closes · migrations added ·
security impact · how a reviewer reproduces the test evidence.

---

---

# Phase 1 — Chain-agnostic foundation

---

## Issue #1 — Introduce the `octo-chain` abstraction and refactor Stellar behind it

**Labels:** `epic:evm` · `area:architecture` · `size:L` · `blocking`
**Depends on:** nothing. **Blocks:** every other issue in this epic.

### Description

Every chain-specific concept in Octo is currently reachable directly from callers: `octo-api` imports
`StellarNetwork` into its shared state ([`crates/api/src/state.rs`](../crates/api/src/state.rs)),
`octo-ingest` imports `decode_muxed` at [`crates/ingest/src/lib.rs`](../crates/ingest/src/lib.rs),
and route handlers speak XDR. Adding EVM by branching at each of these call sites would produce a
combinatorial mess and guarantee that chain three is as expensive as chain two.

Create a new `crates/chain` (`octo-chain`) crate defining the trait boundary between Octo's
business logic and any specific chain, then make the existing Stellar implementation the first
adapter. **This issue must not change any behaviour** — it is a pure refactor, and the existing
test suite passing unmodified is the primary evidence of that.

### Requirements and context

- The trait must be `Send + Sync + 'static` and object-safe (`Arc<dyn ChainAdapter>`), because
  `AppState` is cloned across Axum handlers and the ingest supervisor runs one task per wallet.
- Async trait methods: use `async_trait` for object safety, or return
  `Pin<Box<dyn Future + Send>>`. Native RPITIT is not object-safe on this MSRV.
- Model the abstraction on **capabilities, not on the union of both chains**. Stellar has muxed
  addresses and no reorgs; EVM has reorgs and no memos. A trait that is the union of both will rot.
  Prefer a small required core plus optional capability sub-traits queried via
  `fn capabilities(&self) -> ChainCapabilities`.
- Chain identity is the CAIP-2 slug (AD-1). Parsing/validating that slug belongs in this crate.
- **Security:** this crate must never gain a dependency on `octo-crypto` internals or handle raw
  key material — it defines shapes, adapters hold secrets.

### Suggested execution

Branch: `feat/chain-abstraction-trait`

### Implement changes

- Add `crates/chain` to the workspace `members` and `[workspace.dependencies]` in
  [`Cargo.toml`](../Cargo.toml) as `octo-chain = { path = "crates/chain" }`.
- Define the core types: `ChainId` (CAIP-2, validated), `ChainKind { Stellar, Evm }`,
  `ChainCapabilities { supports_memo, supports_muxed_addresses, has_reorgs, native_decimals, .. }`,
  and `ChainError`.
- Define `trait ChainAdapter` with the minimum viable surface, each method documented with the
  invariant it must uphold: `chain_id`, `capabilities`, `validate_address`, `normalize_address`
  (the generalisation of [`to_base_account`](../crates/wallet-core/src/address.rs)),
  `derive_deposit_address`, and `explain_failure` (the generalisation of `explain_code` in
  [`crates/api/src/routes/submit.rs`](../crates/api/src/routes/submit.rs)).
- Add `crates/chain/src/stellar.rs` — a `StellarAdapter` that delegates to the existing
  `octo-wallet-core` functions. Zero reimplementation; it is a thin forwarding layer.
- Introduce a `ChainRegistry` (`HashMap<ChainId, Arc<dyn ChainAdapter>>`) with lookup returning
  `ChainError::UnsupportedChain` rather than panicking.

### Test and commit

- Unit-test `ChainId` parsing against the CAIP-2 spec's own examples, including the rejection
  cases (empty namespace, over-length reference, invalid characters).
- Add a `StellarAdapter` conformance test asserting it produces byte-identical results to the
  direct `octo-wallet-core` calls for the SEP-0005 Test 1 vectors already used in
  [`crates/wallet-core/src/address.rs`](../crates/wallet-core/src/address.rs).
- Write a reusable `chain_conformance_suite(adapter)` harness that #5's EVM adapter will be
  required to pass. This is deliverable, not optional — it is how we keep adapters honest.
- Document the trait boundary in [`docs/architecture.md`](./architecture.md), including an explicit
  statement of what belongs in an adapter versus in business logic.

### Example commit message

```
feat(chain): add ChainAdapter trait and Stellar adapter

Introduces octo-chain as the boundary between business logic and
chain-specific behaviour, with CAIP-2 chain identity and a capability
model rather than a union-of-chains interface.

Stellar becomes the first adapter, forwarding to octo-wallet-core with
no behaviour change; the existing suite passes unmodified.

Refs #1
```

### Guidelines

Pure refactor — a behaviour change hidden in this PR is the failure mode reviewers will look for
hardest. If you find a latent Stellar bug while refactoring, file it separately and leave a
`// TODO(#NNN)` rather than fixing it here.

---

## Issue #2 — Multi-chain database schema migration

**Labels:** `epic:evm` · `area:store` · `size:L` · `blocking` · `needs-maintainer-review`
**Depends on:** #1. **Blocks:** #3, #8, #11.

### Description

The schema hard-codes Stellar in column names, constraints, and unique indexes. From
[`0001_init.sql`](../crates/store/migrations/0001_init.sql):

- `wallets.network TEXT CHECK (network IN ('mainnet','testnet'))` — no room for a chain dimension
  at all; `mainnet` is ambiguous once Base and Arbitrum exist.
- `wallets.stellar_account_g`, `wallets.next_muxed_id`, `wallets.gas_tank_account_g`
- `addresses.muxed_id`, `addresses.muxed_address` (`UNIQUE (muxed_address)` — globally unique
  across all wallets, which is a *wrong* assumption for EVM where a deposit address is unique only
  within a chain)
- `transactions.stellar_tx_hash`, `transactions.operation_index`, `transactions.memo_id`,
  `transactions.ledger`, `transactions.horizon_op_id`
- `uq_tx_onchain (stellar_tx_hash, operation_index) WHERE stellar_tx_hash IS NOT NULL` — the
  anti-double-credit guard. **An EVM tx hash is not globally unique across chains** (the same
  signed transaction can be replayed on two chains sharing an address space), so this index must
  gain `chain_id` or it will incorrectly deduplicate legitimate deposits on different chains.

Generalise this to a multi-chain schema, migrating existing Stellar rows in place with zero data
loss and zero downtime.

### Requirements and context

- **Backward compatibility is mandatory.** There is live production data on Stellar. The migration
  must be online-safe: no long `ACCESS EXCLUSIVE` lock on `transactions`. Prefer additive columns
  plus a backfill plus a constraint added `NOT VALID` and then `VALIDATE CONSTRAINT`, over an
  in-place rewrite.
- Renaming a column breaks the running old binary during deploy. Either (a) do the rename in two
  releases with a view or generated column for compatibility, or (b) keep legacy names and add
  generic ones. **State your chosen strategy in the PR and justify it** — this is the main
  reviewable decision in the issue.
- All new chain-scoped uniqueness must include `chain_id`.
- Preserve the guarantees documented in [`crates/store/src/lib.rs`](../crates/store/src/lib.rs):
  atomic address allocation, idempotent deposit recording, idempotent withdrawal creation.
- **Security:** the anti-double-credit invariant is the highest-value property in the system. Any
  window during the migration where it does not hold is a fund-loss vulnerability.

### Suggested execution

Branch: `feat/multi-chain-schema`

### Implement changes

- New migration `00NN_multi_chain.sql` creating a `chains` registry table (`chain_id` CAIP-2 slug
  PK, `kind`, `native_symbol`, `native_decimals`, `confirmation_depth`, `enabled`), seeded with the
  existing Stellar rows.
- Add `chain_id` (FK → `chains`) to `wallets`, `addresses`, and `transactions`; backfill from the
  current `network` column; then set `NOT NULL`.
- Replace `uq_tx_onchain` with a chain-scoped equivalent over
  `(chain_id, tx_hash, operation_index)`, created `CONCURRENTLY` and only dropped after the new one
  is live. Generalise `operation_index` to cover the EVM log index.
- Generalise `addresses`: `UNIQUE (muxed_address)` → `UNIQUE (chain_id, deposit_address)`; add a
  nullable `derivation_index` for EVM HD addresses (Stellar keeps using `muxed_id`).
- Update [`crates/store/src/models.rs`](../crates/store/src/models.rs) and every affected query in
  [`crates/store/src/lib.rs`](../crates/store/src/lib.rs).

### Test and commit

- **Write a migration round-trip test**: seed a database with representative pre-migration Stellar
  rows, run the migration, assert every row is intact and every invariant still holds. This is the
  deliverable reviewers will weight most.
- Add a regression test proving the same `(tx_hash, operation_index)` on two different `chain_id`s
  is accepted, and that a repeat on the *same* chain is still rejected.
- Extend [`crates/store/tests/store_tests.rs`](../crates/store/tests/store_tests.rs) for the
  generalised allocation path.
- Note: [`crates/api/tests/drift_tests.rs`](../crates/api/tests/drift_tests.rs) asserts the expected
  migration set — update it (this is the one authorised test change; see the precedent in commit
  `c78cf1d`).
- Document the schema in [`docs/architecture.md`](./architecture.md) with an ER diagram.

### Example commit message

```
feat(store): generalise schema to multi-chain

Adds a chains registry and chain_id to wallets/addresses/transactions,
and re-scopes the anti-double-credit unique index to
(chain_id, tx_hash, operation_index) — an EVM tx hash is not unique
across chains, so the old two-column index would have dropped
legitimate cross-chain deposits.

Migration is online-safe: additive columns, backfill, CONCURRENTLY-built
index, old index dropped only after the new one is live.

Refs #2
```

### Guidelines

Requires maintainer co-review. Include the actual `EXPLAIN` output and a timing estimate against a
production-sized `transactions` table in the PR description.

---

## Issue #3 — Arbitrary-precision amounts (replace `i64` stroops)

**Labels:** `epic:evm` · `area:store` · `area:api` · `size:L` · `blocking` · `breaking-change`
**Depends on:** #2. **Blocks:** #9, #11, #12, #13, #15.

### Description

Amounts are `i64` stroops everywhere — schema (`amount_stroops BIGINT CHECK (amount_stroops > 0)`),
models ([`crates/store/src/models.rs`](../crates/store/src/models.rs)), the ingest amount parser
([`crates/ingest/src/amount.rs`](../crates/ingest/src/amount.rs)), and API serialisation. This
encodes two Stellar-specific assumptions: **7 decimal places**, and **values that fit in 64 bits**.

Both fail on EVM. ETH and most ERC-20s use 18 decimals; `1 ETH = 10^18` and `i64::MAX ≈ 9.22 × 10^18`,
so a balance of ~9.3 ETH overflows. Token amounts are `uint256`, up to ~1.16 × 10^77. An overflow
here does not throw — it silently credits the wrong amount, which is a fund-loss bug.

Introduce an arbitrary-precision `Amount` type and migrate storage and serialisation to it.

### Requirements and context

- **Storage:** `NUMERIC(78,0)` — integer base units, no fractional component. Decimals live in the
  token registry (#11), never inferred from the value.
- **Rust type:** `rust_decimal` is **not** acceptable (96-bit mantissa). Use `sqlx::types::BigDecimal`
  (enable the `bigdecimal` feature) at the storage boundary and `U256` in EVM-facing code. Justify
  your choice of the `U256` implementation (`alloy-primitives`, `ruint`, `primitive-types`) against
  the MSRV constraint — coordinate with #5.
- **API representation:** JSON **strings**, per AD-3. A `uint256` in a JSON number silently loses
  precision in every JavaScript client. This is a breaking API change and must be versioned — see
  #15.
- **No floats, ever.** Note that `format_amount` in
  [`crates/api/src/routes/submit.rs`](../crates/api/src/routes/submit.rs) currently round-trips
  through `f64`. That is tolerable for 7-decimal stroops and **not** tolerable at 18 decimals.
  Replace it with integer/string formatting.
- The `wallet-core` and `crypto` lint walls already deny `clippy::cast_possible_truncation` and
  `cast_sign_loss` — extend that posture to any crate handling amounts.
- **Security:** an unchecked `as i64` or a silent saturation is a credit-amount vulnerability.
  Conversions must be fallible and return an error, never truncate.

### Suggested execution

Branch: `feat/arbitrary-precision-amounts`

### Implement changes

- Add an `Amount` newtype in `octo-chain` wrapping an unsigned big integer, with a documented
  invariant that it is always a non-negative integer count of base units, plus fallible
  `TryFrom<i64>` / `to_i64()` conversions for the Stellar path.
- Migration `00NN_numeric_amounts.sql`: add `amount_base_units NUMERIC(78,0)`, backfill from
  `amount_stroops`, add the `> 0` check, and keep the old column through one release for rollback.
- Implement `Serialize`/`Deserialize` as strings, with a deserializer that **rejects** JSON numbers
  outright rather than accepting and truncating them.
- Replace `format_amount`'s `f64` path with exact integer→decimal-string formatting parameterised
  by `decimals`.
- Update `octo-store` models and queries, and `octo-ingest`'s amount parsing.

### Test and commit

- **Property tests** (`proptest` is already a workspace dependency): round-trip
  `Amount → NUMERIC → Amount` and `Amount → JSON string → Amount` for the full `uint256` range.
- Explicit boundary cases: `0`, `1`, `i64::MAX`, `i64::MAX + 1`, `u64::MAX`, `2^256 - 1`.
- A regression test asserting that a JSON *number* amount is **rejected**, not coerced.
- A test that the exact value `10^18` (1 ETH) survives a full store→API→client round-trip
  bit-identically — this is the case the old `i64` schema could not represent.
- Update [`docs/api.md`](./api.md) and [`docs/openapi.yaml`](./openapi.yaml) for the string
  representation.

### Example commit message

```
feat(store): arbitrary-precision amounts for EVM compatibility

i64 stroops assume 7 decimals and 64-bit range; ETH is 18 decimals and
ERC-20 amounts are uint256, so ~9.3 ETH would silently overflow.

Amounts move to NUMERIC(78,0) with decimals owned by the token registry,
and cross the API as JSON strings — a uint256 in a JSON number loses
precision in every JS client.

BREAKING CHANGE: amount fields serialise as strings.

Refs #3
```

### Guidelines

Breaking API change: coordinate with #15 on versioning before merge. Call out every remaining
`as i64` in the diff and explain why each is safe.

---

## Issue #4 — Per-chain configuration and runtime chain registry

**Labels:** `epic:evm` · `area:api` · `area:config` · `size:M`
**Depends on:** #1. **Blocks:** #15.

### Description

Configuration assumes exactly one chain. [`AppState`](../crates/api/src/state.rs) holds a single
`network: StellarNetwork`, one `horizon: Horizon`, one `horizon_url`, one `friendbot_url`; the
ingest supervisor takes one Horizon URL. There is no way to express "Stellar mainnet **and** Base
**and** Arbitrum, each with its own endpoint, confirmation depth, and enable flag."

Replace the flat configuration with a per-chain structure that `bin/server` loads at startup and
resolves into the `ChainRegistry` from #1.

### Requirements and context

- Support N chains where N ≥ 1, configured without recompiling.
- **Fail fast and loudly at startup.** A chain configured with a bad RPC URL must abort boot with a
  clear message, not fail lazily on the first customer deposit. Follow the existing precedent in
  [`CloudinaryConfig::from_env`](../crates/api/src/state.rs) — but note that *disabled-when-absent*
  is right for image uploads and **wrong** for a chain that has live customer balances.
- Env-var-only config does not scale to N chains with ~8 settings each. Prefer a config file
  (TOML) with env-var override for secrets, and document the precedence order.
- Preserve the existing resilience wiring: `RetryPolicy` and `CircuitBreaker` are currently
  per-process, and must become **per-chain** — a degraded Base RPC must not open the circuit on
  Stellar. See [`crates/ingest/tests/supervisor_network_isolation_tests.rs`](../crates/ingest/tests/supervisor_network_isolation_tests.rs)
  for the isolation property already asserted.
- **Security:** RPC URLs frequently embed API keys (Alchemy, Infura). They must never appear in
  logs, error messages, or health endpoints. Wrap in a redacting `Debug` impl.

### Suggested execution

Branch: `feat/per-chain-configuration`

### Implement changes

- Define `ChainConfig { chain_id, rpc_url (redacted Debug), enabled, confirmation_depth, poll_interval, retry, circuit, faucet_url }`
  and `AppConfig { chains: Vec<ChainConfig>, .. }`.
- Refactor `AppState` to hold `Arc<ChainRegistry>` instead of `network`/`horizon`/`horizon_url`,
  keeping accessors for the Stellar path so route handlers change minimally in this PR.
- Add startup validation: chain ids are well-formed and unique, at least one chain is enabled, every
  enabled chain's RPC answers a liveness probe within a timeout.
- Move `friendbot_url` into the Stellar chain config (it is a Stellar-only concept and does not
  belong in shared state).
- Add a `/health` detail per chain — reachability and last successful poll, reusing
  [`LastPollTracker`](../crates/ingest/src/lib.rs). **Redact credentials.**

### Test and commit

- Test config parse: valid multi-chain file; duplicate chain id rejected; unknown chain id rejected;
  no-enabled-chains rejected.
- Test env-var override precedence explicitly.
- **Test that a redacted RPC URL never appears in `Debug`/`Display` output or in a `/health`
  response** — assert on the API-key substring being absent.
- Test that one chain's circuit breaker opening does not affect another's.
- Update `.env.example`, [`README.md`](../README.md), and the deployment section of
  [`docs/architecture.md`](./architecture.md) with a worked multi-chain example.

### Example commit message

```
feat(config): per-chain configuration and runtime registry

Replaces single-chain AppState fields with a ChainRegistry built from
per-chain config, each carrying its own RPC endpoint, confirmation
depth, and resilience policy so a degraded RPC on one chain cannot
open the circuit on another.

RPC URLs use a redacting Debug impl — provider URLs embed API keys.

Refs #4
```

### Guidelines

Keep this PR mechanical. Do not add EVM chains here — this issue delivers the *shape*, and #5/#6
deliver an adapter to put in it.

---

---

# Phase 2 — EVM primitives

---

## Issue #5 — `octo-evm-core`: secp256k1 keys, BIP-44 derivation, EIP-55 addresses

**Labels:** `epic:evm` · `area:crypto` · `size:L` · `security-sensitive` · `needs-maintainer-review`
**Depends on:** #1. **Blocks:** #6, #8, #13.

### Description

[`octo-wallet-core`](../crates/wallet-core/src/lib.rs) is entirely Stellar: SEP-0005 SLIP-0010
**ed25519** derivation at `m/44'/148'/index'` ([`derive.rs:16`](../crates/wallet-core/src/derive.rs)),
strkey addresses, XDR signing. EVM needs a different curve (**secp256k1**), a different derivation
standard (**BIP-32/BIP-44**, non-hardened change/index levels), a different coin type (**60**), and
a different address format (last 20 bytes of the keccak-256 of the uncompressed public key, with an
[EIP-55](https://eips.ethereum.org/EIPS/eip-55) mixed-case checksum).

Create `crates/evm-core` (`octo-evm-core`) providing these primitives and an `EvmAdapter`
implementing `ChainAdapter`. **This issue also owns resolving the `alloy` MSRV question** (see §2)
and its resolution binds #6, #13, #14.

### Requirements and context

- **This crate handles secret key material.** It inherits `wallet-core`'s full lint wall and
  `zeroize`-on-drop discipline. A panic in this crate can surface key bytes in a backtrace.
- Derivation path: `m/44'/60'/0'/0/{index}` — note the last two levels are **non-hardened**, unlike
  Stellar's all-hardened SEP-0005 path. This is what allows xpub-based address derivation, and it
  is also why a leaked child private key plus the xpub compromises **every sibling key**. Document
  that consequence prominently; #8 and #12 depend on understanding it.
- Reuse [`octo-crypto`](../crates/crypto/src/lib.rs) for sealing unchanged. Do **not** add a second
  encryption scheme. The `context` AAD string must distinguish chains (e.g. `"octo:eip155:1"`) so a
  sealed EVM key cannot be opened in a Stellar context.
- **Test vectors are mandatory**, per [`CONTRIBUTING.md`](../CONTRIBUTING.md): "crypto and derivation
  code must include test vectors."
- **Security:** low-`s` signature normalisation (EIP-2) is required or signatures are malleable.
  Constant-time secret comparison. Never construct a signing key from an uncontrolled byte slice
  without validating it is in the curve order.

### Suggested execution

Branch: `feat/evm-core-keys-and-addresses`

### Implement changes

- Add `crates/evm-core`; resolve and **document the crate-selection decision** (`alloy-primitives`
  vs `k256` + `sha3` + `bip32`) against MSRV 1.84.1 and `cargo deny check` in a short ADR in
  [`docs/architecture.md`](./architecture.md).
- `derive.rs`: BIP-32 secp256k1 derivation from the same BIP-39 mnemonic type already used, at
  `m/44'/60'/0'/0/{index}`, returning a `Zeroizing` secret.
- `address.rs`: keccak-256 → 20-byte address; EIP-55 checksum encode; a `validate_address` that
  accepts all-lowercase, all-uppercase, and correctly-checksummed mixed case, and **rejects an
  incorrect mixed-case checksum** (a typo-detection property that silently vanishes if you
  lowercase before comparing).
- `signer.rs`: sign a 32-byte digest, produce `(r, s, v)` with low-`s` normalisation, and recover
  the signer address. Mirror the "no raw-XDR oracle" posture of
  [`wallet-core/src/signer.rs`](../crates/wallet-core/src/signer.rs): expose typed operations, not
  a sign-arbitrary-bytes primitive.
- `EvmAdapter` implementing `ChainAdapter`, passing #1's `chain_conformance_suite`.

### Test and commit

- **BIP-32/BIP-44 test vectors** from BIP-32's own Test Vector 1 and 2, plus a known
  mnemonic→address set cross-checked against an independent implementation (MetaMask or
  `ethers.js`) — record the source in the test file.
- **EIP-55 test vectors**: every example from the EIP-55 spec, plus the negative cases
  (wrong-checksum mixed case must be **rejected**).
- Signature tests: known `(digest, key) → (r, s, v)` vectors; assert `s` is always in the lower
  half of the curve order; round-trip recovery returns the signing address.
- Assert secrets are zeroized on drop.
- A test that a seed sealed with an `eip155` context **fails** to open with a `stellar` context.

### Example commit message

```
feat(evm-core): secp256k1 derivation, EIP-55 addresses, signing

Adds BIP-44 m/44'/60'/0'/0/i derivation, keccak-256 address encoding
with EIP-55 checksum validation, and low-s normalised signing (EIP-2).

Seals reuse octo-crypto with a chain-scoped AAD context so an EVM key
cannot be opened in a Stellar context.

Verified against BIP-32 vectors 1-2 and the full EIP-55 example set.

Refs #5
```

### Guidelines

Security-sensitive: requires maintainer review and will not be merged without test vectors from an
authoritative source. Cite where each vector came from.

---

## Issue #6 — `octo-evm-rpc`: resilient JSON-RPC client

**Labels:** `epic:evm` · `area:ingest` · `size:M`
**Depends on:** #5. **Blocks:** #7, #9, #13.

### Description

Octo talks to Stellar through two purpose-built clients —
[`crates/ingest/src/horizon.rs`](../crates/ingest/src/horizon.rs) for deposit polling and
[`crates/api/src/horizon.rs`](../crates/api/src/horizon.rs) for API-side reads/submits — both
wrapped in [`octo-resilience`](../crates/resilience/src/lib.rs). EVM needs the equivalent over
JSON-RPC 2.0.

Build `crates/evm-rpc` (`octo-evm-rpc`) as a typed client covering the methods this epic needs,
with the same resilience posture.

### Requirements and context

- **Honour the submit-asymmetry rule (AD-5).** `eth_call`, `eth_getLogs`, `eth_blockNumber`,
  `eth_getTransactionReceipt` are `CallKind::Read` and retryable.
  `eth_sendRawTransaction` **must not** be transparently retried — see the header comment in
  [`crates/ingest/src/horizon.rs`](../crates/ingest/src/horizon.rs) for the established reasoning.
- **JSON-RPC error handling is a trap.** A JSON-RPC error is HTTP 200 with an `error` member. A
  client that only checks HTTP status will treat every failure as success. Handle the error object
  explicitly and distinguish transport failure from protocol error from execution revert.
- Providers differ in real, breaking ways: `eth_getLogs` block-range caps (Alchemy 2k, Infura 10k,
  others unbounded), rate-limit responses, and inconsistent revert-data encoding. The client must
  surface a typed `RangeTooLarge` so #9 can adaptively bisect rather than stall.
- All quantities are hex-encoded strings (`0x`-prefixed, minimal-length). Parse into the `U256`
  type chosen in #5 — **never into `u64` or `f64`**.
- **Security:** RPC URLs contain API keys — never log the URL (see #4). Cap response body size;
  a malicious or compromised RPC returning a multi-GB response must not OOM the worker.

### Suggested execution

Branch: `feat/evm-rpc-client`

### Implement changes

- Add `crates/evm-rpc` using the workspace `reqwest` (already `rustls-tls`, no OpenSSL).
- Implement typed wrappers: `eth_blockNumber`, `eth_getBlockByNumber`, `eth_getLogs`,
  `eth_getTransactionReceipt`, `eth_getTransactionCount`, `eth_call`, `eth_estimateGas`,
  `eth_feeHistory`, `eth_chainId`, `eth_sendRawTransaction`.
- Wire `execute(CallKind::Read, ..)` with per-chain `RetryPolicy`/`CircuitBreaker` from #4 for reads
  only; document at the call site why the submit path is excluded.
- Add a startup assertion that `eth_chainId` matches the configured CAIP-2 chain id — **a
  misconfigured RPC pointing at the wrong chain is a fund-loss bug**, and this one-line check
  prevents it.
- Typed errors: `Transport`, `JsonRpc { code, message }`, `Revert { data }`, `RangeTooLarge`,
  `RateLimited { retry_after }`, `CircuitOpen`.

### Test and commit

- Mock-server tests in the style of
  [`crates/ingest/tests/horizon_mock_tests.rs`](../crates/ingest/tests/horizon_mock_tests.rs) and
  [`crates/api/tests/horizon_resilience_tests.rs`](../crates/api/tests/horizon_resilience_tests.rs).
- **A test that HTTP 200 with a JSON-RPC `error` member is treated as an error**, not success.
- Test retry/backoff on 5xx and the circuit opening after `failure_threshold`.
- **A test asserting `eth_sendRawTransaction` is called exactly once on failure** — no silent retry.
- Test hex parsing edge cases: `0x0`, values above `u64::MAX`, malformed input, and a response body
  exceeding the size cap.
- Test the chain-id mismatch guard rejects at startup.

### Example commit message

```
feat(evm-rpc): typed JSON-RPC client with per-chain resilience

Reads go through octo-resilience retry + circuit breaker;
eth_sendRawTransaction deliberately does not, preserving the
submit-asymmetry rule.

JSON-RPC errors arrive as HTTP 200 with an error member, so status-only
checking would read every failure as success — handled explicitly.

Startup asserts eth_chainId matches the configured CAIP-2 id; an RPC
pointed at the wrong chain is a fund-loss bug.

Refs #6
```

### Guidelines

Do not pull in a full EVM SDK for this. A focused client keeps the dependency audit small and the
`cargo deny` surface reviewable.

---

## Issue #7 — Anvil-based EVM integration test harness

**Labels:** `epic:evm` · `area:testing` · `size:M` · `good-first-issue`
**Depends on:** #6. **Blocks:** #9, #10, #12, #13, #14 (all need it to be testable).

### Description

Stellar work is testable locally: the `StellarNetwork::Standalone` variant
([`crates/wallet-core/src/signer.rs`](../crates/wallet-core/src/signer.rs)) exists specifically so
contributors can run against a local node "without depending on public testnet availability or
friendbot rate limits", and `just test-live` gates network tests behind `OCTO_LIVE_TESTS=1`.

EVM work needs the same. Without a local devnet, every downstream issue is either untested or
dependent on a flaky public testnet — and **#10 (reorg handling) is untestable at all**, because you
cannot induce a reorg on a public network on demand. Anvil (from Foundry) can, via
`anvil_snapshot`/`anvil_revert`.

### Requirements and context

- Tests must **skip cleanly, not fail**, when Anvil is absent, mirroring how the Horizon live tests
  gate on `OCTO_LIVE_TESTS`. A contributor without Foundry must still get a green `just test`.
- Each test needs an isolated chain instance — a random free port and its own process, so tests can
  run in parallel without shared-state flakiness.
- Deterministic accounts: use Anvil's standard mnemonic so funded test accounts are reproducible.
- Deploy a mock ERC-20 with **configurable decimals** — 6 (USDC), 18 (DAI), and 0 must all be
  exercised, since decimal handling is where #3 and #11 will break.
- Expose reorg controls (`anvil_snapshot`, `anvil_revert`, `evm_mine`, `anvil_setNextBlockBaseFeePerGas`)
  as harness methods — this is the deliverable #10 depends on most.
- Process cleanup must be reliable on panic, or a failing test run leaves orphan Anvil processes.

### Suggested execution

Branch: `chore/anvil-integration-harness`

### Implement changes

- Add `crates/evm-rpc/tests/common/anvil.rs` (or a small `test-support` crate if #9/#12 also need
  it): an `AnvilInstance` guard that spawns on a free port, waits for readiness by polling
  `eth_chainId`, and kills the process in `Drop`.
- Add a `MockErc20` deploy helper with parameterised `decimals`, plus `mint`/`transfer` helpers so
  tests can produce real `Transfer` logs.
- Add reorg helpers: `snapshot()`, `revert_to(id)`, `mine(n)`, `set_base_fee(x)`.
- Add `just test-evm` to the [`justfile`](../justfile) alongside `test-live`, and gate on an
  `OCTO_EVM_TESTS` env var plus an Anvil-on-PATH probe.
- Document Foundry installation in [`CONTRIBUTING.md`](../CONTRIBUTING.md).

### Test and commit

- A self-test proving the harness works: start Anvil, mine blocks, assert `eth_blockNumber` advances.
- **A self-test proving snapshot/revert actually reorgs**: mine a block containing a `Transfer`,
  snapshot, mine more, revert, and assert the transaction receipt is gone. If this test does not
  pass, #10 cannot be verified.
- A test that the suite skips (not fails) when Anvil is unavailable.
- A test that `Drop` kills the process even when the test panics.
- Add CI: install Foundry and run `just test-evm`.

### Example commit message

```
chore(testing): add Anvil-based EVM integration harness

Gives EVM work the local-devnet story Stellar already has via
StellarNetwork::Standalone, with per-test isolated instances on random
ports and deterministic funded accounts.

Exposes anvil_snapshot/anvil_revert so reorg handling (#10) is testable
at all — a reorg cannot be induced on a public testnet on demand.

Skips cleanly when Foundry is absent so `just test` stays green.

Refs #7
```

### Guidelines

Good first issue — self-contained, no fund-loss risk, and it unblocks five other issues. Prioritise
reliability: a flaky harness poisons every downstream PR.

---

---

# Phase 3 — Inbound / deposits

---

## Issue #8 — EVM per-customer deposit addresses (HD derivation)

**Labels:** `epic:evm` · `area:store` · `area:wallet` · `size:L` · `security-sensitive`
**Depends on:** #2, #5. **Blocks:** #9, #12.

### Description

This is the deepest conceptual gap in the epic. Octo's deposit model
([`docs/deposit-model.md`](./deposit-model.md)) gives every customer a muxed address: one base
account plus a 64-bit id, so a deposit lands in a single account already tagged with the customer
id — **no new on-chain account, no reserve, no sweep**.
[`Store::allocate_address`](../crates/store/src/lib.rs) just bumps `next_muxed_id` in a transaction.

EVM has no such mechanism. Each customer needs a **real, distinct, HD-derived EOA**, which changes
the economics and the risk profile:

- Funds arrive at N different addresses and must be **swept** to a treasury (#12).
- Sweeping costs gas **at the deposit address**, which holds no native token — so the sweeper must
  fund it first, or use a smart-contract forwarder.
- The address's private key must be derivable to sweep — so the server **does** hold keys that can
  move customer funds, a departure from the non-custodial posture in
  [`0012_client_custody.sql`](../crates/store/migrations/0012_client_custody.sql). AD-4 permits this
  narrowly; it must be documented, bounded, and understood.

Implement EVM deposit-address allocation, preserving the atomicity guarantee the Stellar path has.

### Requirements and context

- **Atomicity is non-negotiable.** Two concurrent allocations must never receive the same
  derivation index. Reuse the existing transaction + row-lock pattern in `allocate_address`.
- **Evaluate CREATE2 forwarders as an alternative** and record the decision in the PR. Trade-off:
  HD EOAs are simpler and need no deployment, but need pre-funding for gas and hold live keys.
  CREATE2 forwarders can be counterfactual (address known before deployment) and let the sweep be
  pull-based, but cost more gas and add contract risk. **Either is acceptable; an undocumented
  choice is not.**
- Derivation index space and the `addresses.derivation_index` column from #2 must agree. BIP-44's
  non-hardened index level is bounded at `2^31 - 1`.
- **Security — this is the critical one:** with non-hardened derivation, **xpub + any one child
  private key ⇒ every sibling private key**. If the extended public key is exposed anywhere (an
  API response, a log, a webhook payload) and a single deposit key ever leaks, every customer
  deposit address on that wallet is compromised. Treat the xpub as a secret and say so in the
  threat model.
- The same address must be re-derivable deterministically from the seed + index for disaster
  recovery. Store the index, not just the address.

### Suggested execution

Branch: `feat/evm-deposit-addresses`

### Implement changes

- Extend `Store::allocate_address` (or add a chain-dispatched sibling) to allocate an EVM address:
  bump a per-wallet `next_derivation_index` under the same row lock, derive via #5, and insert with
  `chain_id`.
- Store the EIP-55 checksummed form for display but **index and compare on the lowercase form** —
  otherwise a client sending a lowercase address will fail to match a checksummed stored row. Add
  a functional index or a normalised column.
- Implement `ChainAdapter::derive_deposit_address` for `EvmAdapter`; Stellar's implementation keeps
  returning the muxed pair unchanged.
- Update the addresses API in [`crates/api/src/routes/addresses.rs`](../crates/api/src/routes/addresses.rs)
  to return chain-appropriate shapes — EVM responses must **not** carry `memo_id`, and clients must
  not be encouraged to send a memo (there is nowhere for it to go).
- Update [`docs/deposit-model.md`](./deposit-model.md) with the EVM model, side by side with the
  muxed model, including the economic differences.

### Test and commit

- **Concurrency test**: N parallel allocations on one wallet yield N distinct indexes and N distinct
  addresses, with no gaps that would break recovery. Model it on the existing
  [`supervisor_concurrency_tests.rs`](../crates/ingest/tests/supervisor_concurrency_tests.rs).
- Determinism test: the same seed + index always produces the same address across runs and processes.
- Case-normalisation test: looking up a deposit address by its lowercase, uppercase, and
  checksummed forms all resolve to the same row.
- Test that a Stellar wallet still allocates muxed addresses with completely unchanged behaviour.
- Update [`docs/threat-model.md`](./threat-model.md) with the xpub + sibling-key-derivation risk.

### Example commit message

```
feat(store): EVM per-customer deposit addresses via HD derivation

Stellar muxed accounts have no EVM equivalent, so each customer gets a
real derived EOA at m/44'/60'/0'/0/i, allocated under the same row lock
that guarantees gap-free muxed ids today.

Addresses are stored EIP-55 checksummed for display but indexed
lowercase, so client lookups match regardless of casing.

Documents the non-hardened derivation risk: xpub plus one leaked child
key compromises every sibling.

Refs #8
```

### Guidelines

Security-sensitive. The PR must state plainly which keys the server now holds, what they can move,
and what bounds the exposure.

---

## Issue #9 — EVM ingest worker (ERC-20 `Transfer` log scanning)

**Labels:** `epic:evm` · `area:ingest` · `size:XL`
**Depends on:** #6, #8, #11. **Blocks:** #10.

### Description

[`octo-ingest`](../crates/ingest/src/lib.rs) polls Horizon `/payments` oldest-first from a saved
`paging_token`, attributes each payment by muxed id or memo id, and records it idempotently, with
dedup on the Horizon TOID. EVM deposit detection is structurally different:

- **No per-account payments feed.** You scan `eth_getLogs` for ERC-20 `Transfer` events whose
  `to` topic matches one of your deposit addresses.
- **The cursor is a block number**, not an opaque token.
- **Native ETH transfers emit no logs at all** — they are only visible by inspecting block
  transactions or `debug_traceBlock`. Decide and document whether native ETH deposits are in scope
  (recommendation: **out of scope for v1**, ERC-20 stablecoins only, stated explicitly in the docs
  rather than silently unsupported).
- Non-standard ERC-20s exist: fee-on-transfer tokens where the amount received ≠ the amount in the
  event, and rebasing tokens. The registry (#11) is the defence; this worker must trust the
  registry, not the token.

Build the EVM ingest worker to the same reliability bar as the Stellar one.

### Requirements and context

- **Reuse the existing supervisor and backoff design.** `wallets_due_for_poll`
  ([`crates/store/src/lib.rs`](../crates/store/src/lib.rs)) already implements activity-based poll
  tiers (active/idle/dormant); do not build a parallel scheduler.
- **Crash safety**: the cursor advances only after a record is durably processed, matching the
  guarantee documented in [`crates/ingest/src/lib.rs`](../crates/ingest/src/lib.rs). A crash mid-batch
  must resume without missing or double-processing.
- **Adaptive range bisection**: on `RangeTooLarge` from #6, halve the block range and retry. A fixed
  range will fail on some providers and waste requests on others.
- **This issue does not credit deposits.** It detects and records them as *unconfirmed*. Crediting
  is gated by #10. Merging #9 without #10 must not create spendable balances — enforce that in code,
  not by convention.
- Preserve the quarantine behaviour: a transfer to a known address for an unregistered token is
  recorded without attribution rather than guessed or dropped.
- **Security:** verify the log's `address` field is the **registered token contract**. Anyone can
  deploy a contract emitting a fake `Transfer` event with any topics; attributing on topics alone
  lets an attacker mint balances for free. This is the single most important check in this issue.

### Suggested execution

Branch: `feat/evm-ingest-worker`

### Implement changes

- Add `crates/ingest/src/evm.rs` with an `EvmIngestor` mirroring `Ingestor`'s shape and returning
  the same `Processed { Recorded, Duplicate, Skipped }` enum.
- Implement log scanning: `eth_getLogs` filtered by registered token addresses and the
  `Transfer(address,address,uint256)` topic0, with the `to` topic matched against deposit addresses.
- Decode `Transfer` correctly: `from`/`to` are **indexed** (topics 1 and 2, left-padded to 32 bytes)
  and `value` is in **data**. Parse `value` as `U256` via #3's `Amount`.
- Persist a block-number cursor per (wallet, chain), reusing the `ingest_cursor` table with the
  chain-scoped columns from #2, and keep `mark_polled`'s "looked at" vs "saw activity" distinction.
- Dedup on `(chain_id, tx_hash, log_index)` via the index from #2.

### Test and commit

- Anvil integration tests (#7): a real ERC-20 transfer to a deposit address is detected, attributed,
  and recorded with the exact amount at 6 and 18 decimals.
- **Adversarial test — the critical one:** deploy a hostile contract that emits a
  `Transfer` event with a deposit address in the `to` topic and a huge `value`, and assert it is
  **not** credited because the emitting contract is not a registered token. Model on
  [`crates/ingest/tests/adversarial_replay_tests.rs`](../crates/ingest/tests/adversarial_replay_tests.rs).
- Replay/idempotency test: processing the same log range twice records nothing new.
- Crash-resume test: kill mid-batch, restart, assert exactly-once processing. Mirror
  [`resume_replay_tests.rs`](../crates/ingest/tests/resume_replay_tests.rs).
- Range-bisection test: a mock RPC returning `RangeTooLarge` causes bisection, not a stall.
- Test that a transfer of an unregistered token to a known address is quarantined, not credited.
- Update [`docs/ingest-integration.md`](./ingest-integration.md).

### Example commit message

```
feat(ingest): EVM deposit detection via ERC-20 Transfer logs

Scans eth_getLogs for registered token contracts with a block-number
cursor, advancing only after durable processing so a crash resumes
exactly-once — the same guarantee the Horizon path gives.

Logs are matched on the emitting contract address, not topics alone:
any contract can emit a Transfer event with arbitrary topics, so
topic-only attribution would let an attacker mint balances.

Deposits are recorded unconfirmed; crediting is gated on #10.

Refs #9
```

### Guidelines

Large issue — split into stacked PRs (cursor/scanning, then decoding/attribution) if that helps
review. Do not merge a version that credits balances before #10 lands.

---

## Issue #10 — Confirmation depth and reorg handling

**Labels:** `epic:evm` · `area:ingest` · `size:XL` · `security-critical` · `needs-maintainer-review`
**Depends on:** #9. **Blocks:** #12.

### Description

**This is the highest-risk issue in the epic.** Octo currently credits a deposit the moment it sees
it, because on Stellar that is correct: a `transaction_successful` payment is final and the ledger
does not reorganise. That assumption is wired into the design — see the guarantees at the top of
[`crates/ingest/src/lib.rs`](../crates/ingest/src/lib.rs) and
[`crates/store/src/lib.rs`](../crates/store/src/lib.rs).

On EVM, blocks reorg. A deposit seen at block N can vanish. If Octo credits on sight, an attacker
can deposit, get credited, force or exploit a reorg, and withdraw against a balance that no longer
exists. Even absent an attacker, ordinary 1–2 block reorgs happen routinely on L1 and L2s.

Introduce a confirmation state machine and a reorg detector that can reverse a credit.

### Requirements and context

- Deposits move through explicit states: `detected` → `confirming` → `confirmed` → creditable.
  Only `confirmed` funds are spendable. A separate `orphaned` terminal state records reversals for
  audit — **never delete the row**; the ledger is append-only and reversals must be visible.
- **Confirmation depth is per chain**, configured in #4. Ethereum L1 and an L2 with a centralised
  sequencer have very different risk profiles, and L2s can have *deep* reorgs on sequencer
  failover. Do not hard-code a number.
- **Reorg detection**: store the block hash alongside the block number for each processed block, and
  on each poll verify the parent hash still matches. A number-only cursor cannot detect a reorg —
  the same height with a different hash looks identical.
- On reorg: rewind the cursor to the last common ancestor, mark affected deposits `orphaned`, emit a
  reversal webhook, and re-scan. Rewinding must be bounded — an unbounded rewind on a malicious RPC
  is a DoS.
- **Security:** the window between crediting and finality is the exploitable window. State clearly
  in the threat model what depth is used per chain and what that implies. Consider whether an
  orphaned deposit that was already withdrawn against is possible, and what the system does about
  it — an honest "this is prevented by requiring N confirmations before spendability" is the
  expected answer.
- Consider `finalized` / `safe` block tags (post-Merge) as a stronger signal than depth counting
  where the provider supports them.

### Suggested execution

Branch: `feat/evm-confirmation-and-reorg`

### Implement changes

- Migration `00NN_deposit_confirmations.sql`: add `confirmation_state`, `block_number`,
  `block_hash`, `confirmations`, and `orphaned_at` to `transactions`; add a partial index over
  rows still confirming, since that is the hot query.
- Add a confirmation tracker that re-checks confirming deposits each tick, promotes them at depth,
  and emits `deposit.confirmed`.
- Add reorg detection via parent-hash chaining, with a bounded rewind depth (configurable, default
  ≥ 2× confirmation depth) and a loud alert if the bound is hit.
- Add reversal: mark `orphaned`, adjust balances, emit `deposit.orphaned` via
  [`octo-webhooks`](../crates/webhooks/src/lib.rs).
- Ensure balance queries only sum `confirmed` rows. **Audit every existing balance/aggregate query**
  for this — one missed query makes unconfirmed funds spendable and defeats the whole issue.

### Test and commit

- **Reorg integration test using Anvil snapshot/revert (#7):** deposit at block N, confirm it, force
  a reorg, assert the deposit is marked `orphaned`, the balance is reduced, and the webhook fires.
  This is the acceptance test for the issue.
- Test that a deposit below confirmation depth is **not** spendable — attempt a withdrawal against
  it and assert rejection.
- Test progressive confirmation counting and promotion at exactly the configured depth.
- Test deep-reorg bounding: a reorg deeper than the rewind bound alerts rather than looping.
- Test that re-scanning after a reorg re-detects a transaction that survived, without
  double-crediting.
- Test that Stellar deposits are unaffected and still credit immediately.
- Update [`docs/threat-model.md`](./threat-model.md) and [`docs/deposit-model.md`](./deposit-model.md)
  with the per-chain depths and the reasoning behind each.

### Example commit message

```
feat(ingest): confirmation depth and reorg handling for EVM

Stellar finality is instant, so Octo credits on sight. EVM blocks
reorg, so crediting on sight would let an attacker deposit, withdraw,
and reorg away the deposit.

Deposits now progress detected → confirming → confirmed, with only
confirmed rows spendable, and reorgs are detected by parent-hash
chaining (a number-only cursor cannot see a same-height different-hash
reorg). Affected deposits are marked orphaned and never deleted.

Refs #10
```

### Guidelines

Security-critical. Requires two maintainer reviewers. Do not attempt as a first contribution. The
PR description must include the reorg test output and a per-chain depth justification.

---

## Issue #11 — ERC-20 token registry

**Labels:** `epic:evm` · `area:store` · `size:M` · `good-first-issue`
**Depends on:** #2, #3. **Blocks:** #9, #13.

### Description

On Stellar, a wallet's acceptable assets are knowable on-chain: a trustline is an explicit opt-in,
which is what [`crates/api/src/routes/trustlines.rs`](../crates/api/src/routes/trustlines.rs)
exposes. ERC-20 has no equivalent — **any address can receive any token, unsolicited**, including
tokens designed to look like real ones.

There is also an existing wart worth fixing here: the testnet USDC issuer is a hard-coded constant
duplicated in two crates, with a comment acknowledging the duplication — see
`USDC_TESTNET_ISSUER` in [`crates/ingest/src/lib.rs`](../crates/ingest/src/lib.rs) and
[`crates/api/src/routes/payment_links.rs`](../crates/api/src/routes/payment_links.rs). A registry
subsumes both.

Build a per-chain token registry that is the **single authority** on what Octo will credit.

### Requirements and context

- Registry rows are keyed by CAIP-19 asset id (AD-1) and carry `chain_id`, contract address,
  symbol, `decimals`, and `enabled`.
- **`decimals` must be verified on-chain at registration** by calling `decimals()`, not taken from
  operator input. USDC is 6 and DAI is 18; a wrong value here misprices every deposit of that token
  by a factor of 10^12.
- **Unregistered tokens are never credited.** They may be recorded for visibility (quarantine),
  matching how unattributable Stellar deposits are handled today.
- Registration is an **admin-only** operation. A user-registerable registry reintroduces exactly the
  attack it exists to prevent.
- Document the known-bad token classes explicitly, since operators will ask: fee-on-transfer
  (received ≠ event value), rebasing (balance changes without a transfer), and tokens with an
  upgradeable proxy or a blacklist/pause function that can freeze Octo's own treasury.
- **Security:** an attacker deploying a contract with `symbol() == "USDC"` costs nothing. Symbol is
  a display string with **no uniqueness guarantee** — match on contract address only, never symbol.

### Suggested execution

Branch: `feat/erc20-token-registry`

### Implement changes

- Migration `00NN_token_registry.sql`: a `tokens` table keyed by CAIP-19 with the fields above,
  `UNIQUE (chain_id, contract_address)` on the lowercase-normalised address, and rows seeded for
  USDC on the target chains plus the existing Stellar assets so the hard-coded constants can be
  deleted.
- Store methods: `register_token` (admin), `list_tokens(chain_id)`, `get_token(caip19)`,
  `is_creditable(chain_id, contract_address)`.
- On registration, call `decimals()` / `symbol()` via #6 and **reject** a mismatch against the
  submitted values rather than silently trusting either side.
- Replace both `USDC_TESTNET_ISSUER` constants with registry lookups.
- Add read-only API endpoints so clients can discover supported assets per chain.

### Test and commit

- Test that registration rejects a `decimals` mismatch against the on-chain value.
- Test that a disabled token is not creditable and that an unregistered token is quarantined rather
  than credited or dropped.
- Test address normalisation: registering `0xABC...` and looking up `0xabc...` resolves.
- **Test that two different contracts both reporting `symbol() == "USDC"` are distinct registry
  entries**, and only the registered one is creditable.
- Test that the Stellar asset path still resolves the same USDC issuer it did via the constant —
  proving the constant removal is behaviour-preserving.
- Document the registry and the known-bad token classes in [`docs/architecture.md`](./architecture.md).

### Example commit message

```
feat(store): per-chain ERC-20 token registry

ERC-20 has no trustline equivalent, so any address can receive any
token; the registry becomes the single authority on what Octo credits.

decimals() is read on-chain at registration rather than trusted from
input — USDC is 6 and DAI is 18, and a wrong value misprices deposits
by 10^12. Matching is on contract address only, never symbol, which
any attacker can spoof for free.

Also removes the duplicated USDC_TESTNET_ISSUER constants in
octo-ingest and octo-api.

Refs #11
```

### Guidelines

Good first issue — well-bounded, valuable, and it cleans up existing duplication. Read the comment
above `USDC_TESTNET_ISSUER` before starting.

---

## Issue #12 — Deposit sweep engine

**Labels:** `epic:evm` · `area:wallet` · `size:XL` · `security-critical` · `needs-maintainer-review`
**Depends on:** #8, #13, #14. **Blocks:** nothing (terminal).

### Description

Because EVM deposits land at N distinct per-customer addresses (#8) rather than in one muxed base
account, funds must be **consolidated into a treasury address**. This has no Stellar analogue at
all — the muxed model exists precisely so that sweeping is unnecessary
([`docs/deposit-model.md`](./deposit-model.md)).

Sweeping is genuinely hard and this issue holds real customer funds:

- A deposit address holds ERC-20 tokens but **no native ETH**, so it cannot pay gas for its own
  transfer. The sweeper must send gas first, then sweep — a two-transaction dance where a crash
  between the two must be recoverable.
- Gas cost can exceed the deposit value. Sweeping a $2 deposit for $4 of gas destroys value.
- Sweeps must be idempotent. A double-sweep wastes gas; a lost sweep record strands funds.
- **The sweeper must hold spending keys for every deposit address**, which is the largest departure
  from Octo's non-custodial posture in the entire epic (AD-4).

### Requirements and context

- **Only sweep `confirmed` deposits** (per #10). Sweeping an unconfirmed deposit that then reorgs
  means paying gas to move money that never existed.
- **Economic gating is required, not optional:** do not sweep when
  `estimated_gas_cost > sweep_value × threshold`. Accumulate and batch instead. Make the threshold
  configurable per chain — it is completely different on L1 versus Base.
- Every sweep must be **idempotent and crash-recoverable**. Persist intent before broadcasting, and
  reconcile on restart. Reuse the idempotency-key pattern from
  [`Store::create_withdrawal`](../crates/store/src/lib.rs).
- Reuse #14's nonce management. Do not build a second nonce allocator.
- **Security — state these plainly in the threat model:**
  - The sweeper's key material can move all unswept customer funds. Bound the exposure: what is the
    maximum unswept balance at any time, and what is the blast radius of a sweeper compromise?
  - Non-hardened derivation (#8) means a leaked deposit key plus a leaked xpub compromises all
    siblings — so the sweeper's key store and the xpub must not share a compromise boundary.
  - Gas-funding transfers to deposit addresses are visible on-chain and **fingerprint Octo's entire
    deposit address set** to any observer. Note this as an accepted privacy trade-off, or mitigate.
  - Keys must be sealed with [`octo-crypto`](../crates/crypto/src/lib.rs) at rest and only opened
    inside the signing boundary, zeroized after.

### Suggested execution

Branch: `feat/evm-sweep-engine`

### Implement changes

- Migration `00NN_sweeps.sql`: a `sweeps` table recording source address, token, amount, gas-funding
  tx hash, sweep tx hash, state machine (`pending` → `gas_funded` → `submitted` → `confirmed` /
  `failed`), and an idempotency key.
- Implement the sweep worker: select eligible confirmed deposits, apply the economic gate, fund gas,
  build and sign the ERC-20 `transfer` to treasury, submit via #13/#14, and track to confirmation.
- Implement crash recovery: on startup, reconcile every non-terminal sweep against on-chain state
  before initiating anything new.
- Add operational metrics and alerts: unswept balance per chain, sweeps blocked by the economic
  gate, sweeps stuck in a non-terminal state.
- **Evaluate and document** whether a CREATE2 forwarder design (if chosen in #8) removes the
  gas-funding step.

### Test and commit

- Anvil tests (#7): fund a deposit address with a mock ERC-20, run the sweeper, assert the treasury
  balance increases by exactly the deposit amount and the sweep row reaches `confirmed`.
- **Crash-recovery test**: kill the process between gas funding and sweep, restart, assert exactly
  one sweep occurs and no gas is double-sent.
- Economic-gating test: a dust deposit whose gas exceeds its value is **not** swept.
- Idempotency test: running the sweeper twice concurrently over the same deposit produces one sweep.
- Test that an unconfirmed deposit is never swept.
- A failure-path test: the sweep transaction reverts, and the sweep row lands in `failed` with the
  funds still safely at the deposit address.
- Update [`docs/threat-model.md`](./threat-model.md) with the full sweeper key-exposure analysis.

### Example commit message

```
feat(wallet): EVM deposit sweep engine

Per-customer EOAs (#8) mean funds must be consolidated into a treasury,
which the Stellar muxed model never required.

Sweeps are gas-funded then executed as a two-step, persisted-intent
state machine that reconciles against on-chain state on restart, so a
crash between funding and sweeping cannot double-send or strand funds.
Dust below the configurable gas-to-value threshold accumulates instead
of being swept at a loss.

Only confirmed deposits are swept — sweeping a reorg-able deposit
spends gas moving money that never existed.

Refs #12
```

### Guidelines

Security-critical, holds customer funds. Two maintainer reviewers, and a written threat-model
section is part of the deliverable, not a follow-up.

---

---

# Phase 4 — Outbound

---

## Issue #13 — EVM signed-transaction relay

**Labels:** `epic:evm` · `area:api` · `size:L` · `security-sensitive`
**Depends on:** #6, #11. **Blocks:** #12, #14, #15.

### Description

[`POST /submit-signed`](../crates/api/src/routes/submit.rs) is the non-custodial core: the client
signs locally, Octo validates the signed envelope
([`crates/api/src/submit_validation.rs`](../crates/api/src/submit_validation.rs)), relays to
Horizon, and records history. The private key never touches the server. Deliver the EVM equivalent.

The validation layer matters as much as the relay. Octo's Stellar validator deliberately refuses to
be a blind signing oracle — it inspects the envelope and enforces policy. The EVM version must do
the same against RLP-encoded, EIP-1559 (type 2) transactions.

### Requirements and context

- Support EIP-1559 (type 2) as the default and legacy (type 0) for compatibility. Decode with a
  strict RLP parser; reject unknown transaction types rather than guessing.
- **Recover the sender from the signature and verify it matches the authorised wallet.** This is the
  central check. Also verify the `chainId` in the signature matches the target chain — a
  transaction signed for chain A must never be relayed to chain B
  ([EIP-155](https://eips.ethereum.org/EIPS/eip-155) replay protection exists precisely because
  this was once possible).
- **Enforce policy on the decoded transaction**, mirroring `submit_validation.rs`: destination
  against the withdrawal allowlist
  ([`0013_withdrawal_allowlist.sql`](../crates/store/migrations/0013_withdrawal_allowlist.sql)),
  token contract against the registry (#11), and amount limits. For an ERC-20 transfer this means
  **decoding the calldata** — `transfer(address,uint256)` selector `0xa9059cbb` — because the
  transaction's `to` is the token contract, not the recipient. Validating `to` alone would allow
  transfers to any recipient.
- The withdrawal-OTP flow in [`submit.rs`](../crates/api/src/routes/submit.rs) must work identically
  for EVM. Reuse it; do not fork it.
- Generalise `explain_code` (Stellar result codes) into `ChainAdapter::explain_failure`, decoding
  EVM revert reasons (`Error(string)` selector `0x08c379a0`) into readable messages.
- **Security:** never accept a raw pre-signed blob and relay it unvalidated. Never log the full
  signed transaction. Enforce a body-size limit — RLP decoding untrusted input is an attack surface;
  use a size cap and a recursion-depth-bounded parser.

### Suggested execution

Branch: `feat/evm-signed-tx-relay`

### Implement changes

- Add `crates/api/src/evm_submit_validation.rs`: decode the signed transaction, recover the sender,
  verify chain id and sender, decode ERC-20 calldata, and enforce allowlist/registry/limit policy.
- Extend the submit route to dispatch on the wallet's `chain_id`, sharing the OTP, audit
  ([`crates/api/src/audit.rs`](../crates/api/src/audit.rs)), and webhook paths with Stellar.
- Implement `explain_failure` for EVM: revert-reason decoding plus common
  pre-broadcast failures (`nonce too low`, `replacement transaction underpriced`,
  `insufficient funds for gas * price + value`).
- Record the relayed transaction with `chain_id`, hash, and block, feeding the same ledger the
  ingest worker writes to.

### Test and commit

- Test that a transaction signed for chain A is **rejected** when submitted to chain B.
- Test that a transaction whose recovered sender is not the authorised wallet is **rejected**.
- **Test calldata decoding: an ERC-20 `transfer` to a non-allowlisted recipient is rejected even
  though the transaction's `to` (the token contract) is registered.** This is the test that proves
  the validator is not fooled by the indirection.
- Test rejection of an unregistered token contract.
- Anvil test (#7): a valid signed transfer relays, mines, and is recorded.
- Test revert-reason decoding produces a readable message.
- Malformed-input tests in the style of
  [`crates/api/tests/malformed_body_tests.rs`](../crates/api/tests/malformed_body_tests.rs):
  truncated RLP, oversized body, deeply nested RLP, unknown tx type — none may panic.
- Update [`docs/openapi.yaml`](./openapi.yaml), [`docs/api.md`](./api.md), and
  [`docs/non-custodial-flow.md`](./non-custodial-flow.md).

### Example commit message

```
feat(api): EVM signed-transaction relay with policy validation

Mirrors the Stellar /submit-signed contract: the client signs locally
and Octo validates, relays, and records — never a blind signing oracle.

Validation recovers the sender from the signature, pins the EIP-155
chain id so a transaction signed for one chain cannot be relayed to
another, and decodes ERC-20 calldata so allowlist checks apply to the
actual recipient rather than to the token contract in `to`.

Refs #13
```

### Guidelines

Security-sensitive. The calldata-decoding check is the piece reviewers will scrutinise — make it
obvious and well-commented.

---

## Issue #14 — Nonce management, gas pricing, and transaction lifecycle

**Labels:** `epic:evm` · `area:api` · `size:XL` · `security-sensitive`
**Depends on:** #13. **Blocks:** #12.

### Description

Stellar sequence numbers are handled by the client and surface as a `tx_bad_seq` error the user
retries — see `explain_code` in [`submit.rs`](../crates/api/src/routes/submit.rs). EVM nonces
cannot be treated that way for server-originated transactions (gas funding and sweeps, #12), because
the server owns those accounts and must sequence them itself.

EVM adds three problems Stellar simply does not have:

1. **Nonce gaps block the account.** Nonces must be strictly sequential. Transaction `n+1` cannot
   mine until `n` does. One stuck transaction halts every subsequent one on that account.
2. **Transactions get stuck.** An underpriced transaction can sit in the mempool indefinitely. The
   only fix is replacement — resubmitting the *same nonce* with ≥ 10% higher gas.
3. **Transactions can be dropped.** A mempool eviction means a transaction you believe is pending
   simply does not exist any more, with no notification.

Build nonce management and a transaction lifecycle tracker for server-originated transactions.

### Requirements and context

- **Nonce allocation must be atomic and gap-free** per (chain, account). Reuse the transactional
  row-lock pattern from [`Store::allocate_address`](../crates/store/src/lib.rs) — the problem is the
  same shape as muxed-id allocation.
- Reconcile against `eth_getTransactionCount` with both `latest` and `pending` tags on startup and
  periodically. **These two disagree by design**, and using the wrong one causes either gaps or
  collisions — document which you use where and why.
- **Note the tension with AD-5.** Replacement is a resubmit at the same nonce, which is exactly the
  operation the submit-asymmetry rule forbids doing *blindly*. Replacement is safe only because the
  nonce makes it mutually exclusive with the original. Make that reasoning explicit at the call
  site so a future reader does not "fix" it by adding transport-level retries.
- EIP-1559 gas: use `eth_feeHistory` for `maxFeePerGas` / `maxPriorityFeePerGas`. Cap the maximum
  gas price — **an unbounded escalation loop during a gas spike can drain the gas tank.**
- Handle nonce-gap recovery: if nonce `n` is permanently stuck, submit a self-transfer of 0 at
  nonce `n` to unblock the queue.
- **Security:** the gas price cap and the escalation policy bound how much a compromised or buggy
  worker can spend. Treat them as security controls, not tuning parameters.

### Suggested execution

Branch: `feat/evm-nonce-and-tx-lifecycle`

### Implement changes

- Migration `00NN_evm_tx_lifecycle.sql`: an `evm_transactions` table with (chain, from_address,
  nonce) unique, gas parameters, submission attempts, state machine (`pending` → `submitted` →
  `mined` → `confirmed`, plus `replaced` / `dropped` / `failed`), and the replacement chain.
- Implement `allocate_nonce(chain_id, address)` under a row lock, with startup reconciliation
  against on-chain counts.
- Implement the lifecycle tracker: poll receipts for submitted transactions, detect drops
  (submitted, absent from the mempool, nonce not advanced), and promote on confirmation depth.
- Implement replacement: escalate gas by ≥ 12.5% (above the 10% minimum, for margin), resubmit at
  the same nonce, and record the replacement chain so both hashes resolve to one logical transaction.
- Add metrics and alerts: stuck transactions, replacement counts, gas spend per chain, nonce-gap
  detection.

### Test and commit

- Concurrency test: N parallel allocations on one account produce N sequential, gap-free nonces.
- Anvil test (#7): submit an underpriced transaction, trigger replacement, assert the replacement
  mines and the original is marked `replaced` — not `failed`, and not double-counted.
- Test the gas price cap is enforced and escalation stops there rather than looping.
- Test nonce-gap recovery via a 0-value self-transfer.
- Test drop detection and resubmission.
- Test startup reconciliation with both a `latest`/`pending` divergence and a pre-existing on-chain
  nonce ahead of the database.
- Document the lifecycle in [`docs/architecture.md`](./architecture.md) with a state diagram.

### Example commit message

```
feat(api): EVM nonce allocation and transaction lifecycle

Server-originated transactions (gas funding, sweeps) need strictly
sequential nonces: one stuck transaction halts every later one on the
account. Allocation reuses the row-lock pattern that keeps muxed ids
gap-free.

Adds replacement (same nonce, +12.5% gas) with an explicit price cap so
an escalation loop during a gas spike cannot drain the gas tank, plus
drop detection and 0-value self-transfer gap recovery.

Replacement resubmits at the same nonce, which is safe precisely
because the nonce makes it mutually exclusive with the original —
documented at the call site so it is not mistaken for a violation of
the submit-asymmetry rule.

Refs #14
```

### Guidelines

Complex and easy to get subtly wrong. Write the state machine down before writing code, and put the
diagram in the PR description.

---

## Issue #15 — Multi-chain API surface, OpenAPI, and webhooks

**Labels:** `epic:evm` · `area:api` · `area:docs` · `size:L` · `breaking-change`
**Depends on:** #3, #4, #8, #13. **Blocks:** nothing (terminal).

### Description

The public API assumes one chain. Responses carry Stellar-shaped fields (`stellar_account_g`,
`muxed_address`, `memo_id`, `stellar_tx_hash`), amounts are numbers, and there is no way for a
client to say which chain it wants. Payment links
([`crates/api/src/routes/payment_links.rs`](../crates/api/src/routes/payment_links.rs)) resolve a
single hard-coded asset. Webhook payloads ([`octo-webhooks`](../crates/webhooks/src/lib.rs)) carry
no chain identity, so a consumer receiving `deposit.confirmed` cannot tell which chain it came from.

Expose multi-chain support coherently across the API, the OpenAPI spec, and webhooks, without
breaking existing Stellar integrations.

### Requirements and context

- **Existing Stellar clients must keep working.** Choose and document a compatibility strategy:
  default `chain_id` to Stellar when the field is absent, and/or version the API. Amount-as-string
  (#3) is already breaking — bundle the breaks into one clearly-communicated version rather than
  dribbling them out.
- Every resource that is chain-scoped must expose `chain_id` in responses, and accept it on creation.
- **Chain-specific fields must be nested, not flattened.** A flat response with `memo_id: null` on
  EVM and `derivation_index: null` on Stellar teaches clients to guess. Nest under a `chain_details`
  discriminated union keyed on chain kind.
- Payment links gain chain selection: a link should support one or more chains, with the payer
  choosing at checkout and each choice yielding a chain-appropriate deposit address (#8).
- **Webhooks must carry `chain_id`** in every event, and new events from this epic
  (`deposit.confirmed`, `deposit.orphaned` from #10) need documented payloads. Webhook signing
  ([`crates/webhooks/src/sign.rs`](../crates/webhooks/src/sign.rs)) is unchanged.
- **`drift_tests.rs` enforces spec/implementation agreement** — every change here needs a matching
  [`docs/openapi.yaml`](./openapi.yaml) change or CI fails.
- **Security:** authorisation is per wallet and must remain per wallet. Adding a `chain_id`
  parameter must not create a path where a client passes a chain id to reach another tenant's
  resources. Extend
  [`crates/api/tests/authz_matrix_tests.rs`](../crates/api/tests/authz_matrix_tests.rs)
  with chain-scoped cases.

### Suggested execution

Branch: `feat/multi-chain-api-surface`

### Implement changes

- Add `chain_id` to wallet/address/transaction/payment-link request and response schemas, with the
  documented default for absent values, and nest chain-specific fields under a discriminated union.
- Add `GET /v1/chains` — supported chains, their tokens (#11), confirmation depths, and enabled
  status, so clients can discover capability rather than hard-code it.
- Extend payment links to multi-chain: chain selection at creation, per-chain deposit address at
  checkout, `chain_id` recorded on payment rows.
- Add `chain_id` to every webhook payload and document the new deposit lifecycle events.
- Update [`docs/openapi.yaml`](./openapi.yaml), [`docs/api.md`](./api.md), and the Bruno collection
  in [`api-tests/`](../api-tests/) added in `4cd1bd2`.

### Test and commit

- Extend [`crates/api/tests/drift_tests.rs`](../crates/api/tests/drift_tests.rs) to cover the new
  and modified endpoints. **Note: this file currently has a compile error on `main`
  (`statusN` at line 47) — fix it as part of this PR.**
- **Backward-compatibility tests**: a request with no `chain_id` behaves exactly as it does today,
  asserted against the current response shapes.
- Authorization tests: a client cannot reach another tenant's wallet by varying `chain_id`.
- Webhook tests: every event carries a correct `chain_id`; existing signature verification is
  unchanged.
- Multi-chain payment-link end-to-end test covering creation, chain selection, and per-chain address
  issuance.
- Write a migration guide for API consumers documenting every breaking change and how to adapt.

### Example commit message

```
feat(api): multi-chain API surface, OpenAPI, and webhooks

Adds chain_id across chain-scoped resources with Stellar as the default
for absent values, nests chain-specific fields under a discriminated
union so clients stop guessing at null columns, and adds GET /v1/chains
for capability discovery.

Payment links gain chain selection with per-chain deposit addresses,
and every webhook payload now carries chain_id.

Also fixes a pre-existing compile error in drift_tests.rs.

BREAKING CHANGE: amount fields are strings; chain-specific fields moved
under chain_details.

Refs #15
```

### Guidelines

Last issue in the epic and the one users actually see. Write the migration guide as if you were the
integrator receiving it.

---

---

## Appendix A — Stellar coupling inventory

Reference map of every Stellar-specific touchpoint, and which issue addresses it.

| Location | Coupling | Issue |
|---|---|---|
| [`crates/wallet-core/src/derive.rs`](../crates/wallet-core/src/derive.rs) | SEP-0005 ed25519, coin type 148 | #5 |
| [`crates/wallet-core/src/address.rs`](../crates/wallet-core/src/address.rs) | muxed accounts, strkey | #5, #8 |
| [`crates/wallet-core/src/signer.rs`](../crates/wallet-core/src/signer.rs) | XDR, fee-bump, `StellarNetwork` | #5, #13 |
| [`crates/wallet-core/src/asset.rs`](../crates/wallet-core/src/asset.rs) | Stellar credit-asset codes | #11 |
| [`crates/store/migrations/0001_init.sql`](../crates/store/migrations/0001_init.sql) | `stellar_*`, `muxed_*`, stroops, `uq_tx_onchain` | #2, #3 |
| [`crates/store/src/models.rs`](../crates/store/src/models.rs) | `i64` stroops, Stellar column names | #2, #3 |
| [`crates/ingest/src/horizon.rs`](../crates/ingest/src/horizon.rs) | Horizon `/payments`, paging token | #6, #9 |
| [`crates/ingest/src/lib.rs`](../crates/ingest/src/lib.rs) | muxed/memo attribution, TOID dedup, `USDC_TESTNET_ISSUER` | #9, #11 |
| [`crates/ingest/src/amount.rs`](../crates/ingest/src/amount.rs) | stroop parsing (7 dp) | #3 |
| [`crates/api/src/state.rs`](../crates/api/src/state.rs) | single `network`/`horizon`/`horizon_url` | #4 |
| [`crates/api/src/horizon.rs`](../crates/api/src/horizon.rs) | Horizon client | #6 |
| [`crates/api/src/submit_validation.rs`](../crates/api/src/submit_validation.rs) | XDR envelope validation | #13 |
| [`crates/api/src/routes/submit.rs`](../crates/api/src/routes/submit.rs) | `explain_code`, `format_amount` (`f64`) | #3, #13 |
| [`crates/api/src/routes/sponsor.rs`](../crates/api/src/routes/sponsor.rs) | fee-bump sponsorship | #14 |
| [`crates/api/src/routes/trustlines.rs`](../crates/api/src/routes/trustlines.rs) | trustlines (no EVM analogue) | #11 |
| [`crates/api/src/routes/payment_links.rs`](../crates/api/src/routes/payment_links.rs) | hard-coded USDC issuer | #11, #15 |
| [`crates/crypto/src/lib.rs`](../crates/crypto/src/lib.rs) | **already chain-agnostic — reuse unchanged** | — |
| [`crates/resilience/src/lib.rs`](../crates/resilience/src/lib.rs) | **already chain-agnostic — reuse unchanged** | — |
| [`crates/webhooks/src/lib.rs`](../crates/webhooks/src/lib.rs) | mostly agnostic; needs `chain_id` | #15 |

## Appendix B — Known pre-existing issues

Found while surveying the codebase for this plan. Not part of the epic, but contributors will trip
over them.

1. **[`crates/api/tests/drift_tests.rs:47`](../crates/api/tests/drift_tests.rs#L47) does not
   compile** — `statusN` should be `status`. Assigned to #15, but any contributor may fix it sooner
   in a standalone `fix:` PR.
2. **`FUTURE_FIXES.md` step 1 is already resolved.** It flags the `payment_link_payments.status`
   CHECK constraint as possibly rejecting `underpaid`/`overpaid` writes; migration
   [`0018_payment_status_expansion.sql:11`](../crates/store/migrations/0018_payment_status_expansion.sql#L11)
   already widened it. The remaining items in that document (frontend display, refund flow) are
   still open and are **not** part of this epic.
