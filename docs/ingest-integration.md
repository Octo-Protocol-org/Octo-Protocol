# Ingest Integration: Reorg, Replay, and Dedup Guarantees

> **Audience:** Platform engineers, security reviewers, and maintainers who need to understand
> the exact behaviour of octo's deposit pipeline when Horizon re-delivers, reorders, or reorgs a
> payment event.
>
> **Scope:** `crates/ingest` → `crates/store`. The webhook delivery layer is out of scope except
> where relevant to idempotency.

---

## Table of Contents

1. [Overview](#overview)
2. [Cursor-Resume Contract](#cursor-resume-contract)
3. [Two-Layer Dedup](#two-layer-dedup)
   - [Primary: `horizon_op_id` (TOID)](#primary-horizon_op_id-toid)
   - [Secondary: `(stellar_tx_hash, operation_index)`](#secondary-stellar_tx_hash-operation_index)
   - [Which One Fires First?](#which-one-fires-first)
4. [Horizon Reorg Behaviour](#horizon-reorg-behaviour)
   - [What the Code Actually Does](#what-the-code-actually-does)
   - [What It Does NOT Do](#what-it-does-not-do)
5. [Quarantine (Unattributed-Deposit) Path](#quarantine-unattributed-deposit-path)
6. [Known Limitations](#known-limitations)
7. [References](#references)

---

## Overview

octo's deposit pipeline has two components:

| Component | Crate | Role |
|-----------|-------|------|
| **Ingestor** | `crates/ingest/src/lib.rs` | Polls Horizon's `/payments` endpoint, attributes each payment to a customer, and calls the store. |
| **Store** | `crates/store/src/lib.rs` | Persists deposits idempotently. Two unique indexes prevent double-credit. |

The end-to-end flow:

```
Horizon ──► Ingestor::poll_once() ──► Ingestor::process(rec)
                                          │
                                          ▼
                                    Store::record_deposit(&dep)
                                          │
                                  ┌───────┴───────┐
                                  ▼               ▼
                              Ok(Some(tx))    Ok(None)
                              → Recorded      → Duplicate (no-op)
```

The cursor is persisted **after each record** so a crash resumes from the last-processed event
without missing or double-processing.

---

## Cursor-Resume Contract

### Where It Lives

The cursor (a Horizon [paging token](https://developers.stellar.org/api/horizon/resources/payments))
is stored in the `ingest_cursor` table — one row per wallet:

```sql
-- crates/store/migrations/0001_init.sql, lines 151–155
CREATE TABLE ingest_cursor (
    wallet_id    UUID PRIMARY KEY REFERENCES wallets(id) ON DELETE CASCADE,
    paging_token TEXT,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### How It Advances

In `crates/ingest/src/lib.rs`, `Ingestor::poll_once()` (lines 65–83):

```rust
pub async fn poll_once(&self, limit: u32) -> Result<usize, IngestError> {
    let cursor = self.store.get_cursor(self.wallet_id).await?;
    let records = self
        .horizon
        .payments_after(&self.account_g, cursor.as_deref(), limit)
        .await
        .map_err(|_| IngestError::Horizon)?;

    let mut count = 0;
    for rec in &records {
        self.process(rec).await?;
        // Advance the cursor after each record so a crash resumes cleanly.
        self.store
            .set_cursor(self.wallet_id, &rec.paging_token)
            .await?;
        count += 1;
    }
    Ok(count)
}
```

**Contract:**

1. On startup (or after a crash), the cursor is read from `ingest_cursor`.
2. Horizon is queried for payments **strictly after** that cursor (`payments_after`).
3. Each payment is processed sequentially.
4. The cursor is updated **after each successful `process()` call** — never before.
5. If the process crashes between records, the cursor still points to the last **fully-processed**
   event. On restart, Horizon re-delivers the events that follow. Any already-inserted deposit
   rows are caught by the dedup indexes (see [Two-Layer Dedup](#two-layer-dedup)).

### Resume vs. Re-Delivery

Because the cursor is per-wallet and monotonic, a restart never skips events. The cost of this
safety is that some events may be **re-processed** at startup if the cursor write succeeded but
the loop counter did not advance. This is harmless because `record_deposit` is idempotent.

---

## Two-Layer Dedup

The store has **two** unique indexes on the `transactions` table. Both are partial — they only
constrain rows where the relevant column is non-NULL.

### Primary: `horizon_op_id` (TOID)

Added in migration `0002_horizon_op_id.sql` (lines 10–12):

```sql
CREATE UNIQUE INDEX uq_tx_horizon_op_id
    ON transactions (horizon_op_id)
    WHERE horizon_op_id IS NOT NULL;
```

- **Key:** The Horizon operation's [TOID](https://developers.stellar.org/api/horizon/resources/payments)
  — a globally-unique string like `"123456789-1-1"` that encodes `(ledger, transaction_index, operation_index)`.
- **Why:** The TOID is the most reliable dedup key because it is globally unique across all of
  Stellar. Every Horizon payment record carries an `id` field that is this TOID.
- **Coverage:** Every deposit recorded by `Ingestor::process()` supplies `rec.id` as
  `horizon_op_id` (`crates/ingest/src/lib.rs`, line 161).

### Secondary: `(stellar_tx_hash, operation_index)`

Added in migration `0001_init.sql` (lines 84–86):

```sql
CREATE UNIQUE INDEX uq_tx_onchain
    ON transactions (stellar_tx_hash, operation_index)
    WHERE stellar_tx_hash IS NOT NULL;
```

- **Key:** The Stellar transaction hash + operation index within that transaction.
- **Why:** This was the original dedup strategy. It remains as a legacy guard in case a code path
  ever inserts a row without a `horizon_op_id` (or with a NULL one).
- **Coverage:** `Ingestor::process()` always sets `operation_index: 0` (line 163). This is a
  simplification — the Horizon payments endpoint returns one record per operation, but the
  operation index is not directly exposed. Setting it to `0` means the secondary index provides
  weaker guarantees for multi-operation transactions (see [Known Limitations](#known-limitations)).

### Which One Fires First?

Both indexes are checked at insert time by Postgres. Which one raises the conflict depends on
the data:

- If the row has a non-NULL `horizon_op_id` (which it always does for the ingest path), both
  indexes apply. Postgres evaluates them independently, and whichever reports first wins.
- In practice, since `horizon_op_id` is globally unique and always present, the
  `uq_tx_horizon_op_id` index is the effective guard.
- The `uq_tx_onchain` index is a defence-in-depth measure: if a future code path ever omits
  `horizon_op_id`, the `(tx_hash, operation_index)` pair still prevents double-credit.

### The Idempotent Insert in Code

In `crates/store/src/lib.rs`, `Store::record_deposit()` (lines 368–401):

```rust
pub async fn record_deposit(&self, d: &NewDeposit) -> Result<Option<Transaction>, StoreError> {
    let result = sqlx::query_as::<_, Transaction>(
        r#"
        INSERT INTO transactions
            (wallet_id, address_id, direction, asset_code, asset_issuer, amount_stroops,
             source_account, destination_account, stellar_tx_hash, operation_index,
             horizon_op_id, ledger, memo_id, status)
        VALUES ($1, $2, 'deposit', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'confirmed')
        RETURNING *
        "#,
    )
    // ... binds ...
    .await;

    match result {
        Ok(tx) => Ok(Some(tx)),
        Err(e) => match StoreError::from_sqlx_conflict(e) {
            StoreError::Conflict => Ok(None), // already recorded — benign
            other => Err(other),
        },
    }
}
```

The return value communicates whether the deposit was new:

| Return value | Meaning |
|---|---|
| `Ok(Some(tx))` | First insert — deposit was **recorded**. |
| `Ok(None)` | Conflict — deposit was **already recorded** (idempotent no-op). |

The caller (`Ingestor::process()`, lines 166–172) uses this to distinguish `Recorded` from
`Duplicate`:

```rust
match self.store.record_deposit(&dep).await? {
    Some(tx) => {
        self.fire_deposit_webhook(&tx).await;
        Ok(Processed::Recorded { attributed })
    }
    None => Ok(Processed::Duplicate),
}
```

---

## Horizon Reorg Behaviour

### What the Code Actually Does

**The ingest pipeline does not handle Horizon reorgs.**

Here is what happens on every `process()` call:

1. **`transaction_successful` is checked** (line 101). If `false`, the record is skipped.
   This value comes from the **current** Horizon response — it reflects what Horizon believes
   at query time.
2. **No finality re-check occurs.** Once a deposit is inserted with `status = 'confirmed'`, it
   is never revisited. There is no background job, re-org listener, or ledger-watermark comparison
   that would reverse or correct a deposit that was later reverted.
3. **The cursor advances monotonically.** Even if a reorg shifts the ledger history, the cursor
   never regresses. Horizon handles cursor-based pagination across reorgs internally — it may
   return different records for the same cursor position — but octo does not attempt to detect
   this.

### What This Means in Practice

| Scenario | Current Behaviour |
|---|---|
| Normal steady state | All deposits are recorded correctly and credited once. |
| Horizon re-delivers the same event | Detected by dedup index → `Duplicate` → no action. |
| A previously-successful payment is reorged away | The deposit **remains in the database** with `status = 'confirmed'`. No reversal occurs. |
| The reorg produces the same payment in a different ledger sequence | The `horizon_op_id` (TOID) changes → treated as a **new** deposit → double-credit. |
| The reorg produces the same payment with the same TOID | Detected by dedup index → `Duplicate` → no action. |

The most concerning case is when a reorg **changes the TOID** of a previously-recorded deposit:
the old deposit stays in the DB (credited), and the new one is also credited. This is a
double-credit scenario that the current codebase **does not prevent**.

### Why This Design Choice Exists

The MVP's threat model (see `docs/threat-model.md`, row "Double-credit on failed/reorged tx")
states the defense as:

> Only credit deposits with `successful == true` from Horizon; key off the immutable tx hash +
> operation id; idempotent insert (unique constraint) so replays can't double-credit.

The implicit assumption is that the combination of:
- checking `transaction_successful` at ingest time,
- the TOID dedup,
- and the cursor-based resume

is sufficient for **replays and re-deliveries** (which it is), but **not** for deep reorgs that
change the TOID of a payment. This is a known gap that would need to be addressed for
production deployments on fallible networks (or for any Stellar network where the reorg window
is non-trivial).

---

## Quarantine (Unattributed-Deposit) Path

When a payment arrives that cannot be linked to any customer, it goes to **quarantine**. This
means the deposit is still recorded, but with `address_id = NULL` (no customer attribution).

### How Attribution Works

In `crates/ingest/src/lib.rs`, the `Ingestor::attribute()` method (lines 214–219):

```rust
fn attribute(&self, rec: &PaymentRecord) -> Option<i64> {
    if let Some(id) = self.muxed_id(rec) {
        return Some(id);
    }
    self.memo_id(rec)
}
```

**Attribution order:**

1. **Muxed id** (`M...` address): If the payment was sent to a muxed address that decodes to
   the wallet's base account (`G...`), the 64-bit muxed id is used.
2. **Memo id** (fallback): If no muxed id, the transaction memo (type `id`) is used.
3. **Neither**: If neither is present, `attribute()` returns `None`.

### Quarantine Insert

When `attribute()` returns `None` (`crates/ingest/src/lib.rs`, lines 128–135):

```rust
let address_id = match customer_id {
    Some(id) => self
        .store
        .address_by_muxed_id(self.wallet_id, id)
        .await?
        .map(|a| a.id),
    None => None,
};
let attributed = address_id.is_some();
```

- `address_id` is `None` → the deposit row has `address_id = NULL`.
- The deposit is still recorded in `transactions` with `status = 'confirmed'`.
- A webhook is fired with `"attributed": false` and empty `metadata`.
- The deposit is **never** later re-attributed to a customer — there is no "guess onto a
  customer" path (as noted in the module doc-comment, line 6).

### Why Quarantine Matters for Reorgs

If a reorg changes the memo or muxed id of a payment (extremely unlikely — these are
immutable parts of the transaction), the quarantine path means:

1. The original attributed deposit stays in the DB with its original attribution.
2. The reorged version may arrive with different attribution data and may or may not match
   a customer.
3. Because there is no reorg-reversal handler, the original deposit is never corrected.

In practice, memo and muxed data do not change during a reorg (they are part of the transaction
envelope), so this is not a real concern. It is documented here for completeness.

---

## Known Limitations

### 1. No Reorg-Reversal Handler

The ingest pipeline does **not**:
- Track ledger sequence numbers to detect reorganisations.
- Re-check `transaction_successful` after initial recording.
- Reverse or adjust deposits that were confirmed on a forked ledger.
- Maintain a watermark of "safe" ledgers (e.g., wait for N confirmations before finalising).

**Impact:** A deep reorg that changes a payment's TOID can cause a double-credit. This is
acceptable for the MVP but should be addressed before mainnet with high-value wallets.

**Suggested approaches for a future iteration:**
- Track the latest known ledger sequence from Horizon and refuse to process payments
  above a configurable confirmation depth.
- Introduce a `status` transition from `pending` → `confirmed` after a trust period.
- Listen for Stellar's `ledger_closed` events and reconcile against recorded deposits.

### 2. `operation_index` Hardcoded to `0`

In `Ingestor::process()` (line 163):

```rust
operation_index: 0,
```

The Horizon payments endpoint returns one record per operation, but the operation index within
the transaction is not directly exposed by the endpoint. Setting this to `0` means the
`uq_tx_onchain` (secondary) index provides weaker dedup for multi-operation transactions.

In practice, since the primary `uq_tx_horizon_op_id` index uses the TOID (which includes the
operation index), this is not a correctness issue — it just means the secondary index is less
useful as a standalone guard.

### 3. No Cross-Wallet Dedup

Each wallet has its own ingest cursor and its own set of deposit rows. The dedup indexes are
per-row, not global. If the same on-chain operation were somehow processed by two different
wallets, both would record it. This is prevented by the architecture (each wallet has its own
Horizon account) and is noted here for completeness.

### 4. Cursor Persistence on Shutdown

The cursor is persisted after each record inside `poll_once()`. If the process is killed between
`process()` succeeding and `set_cursor()` returning, the cursor reverts to the previous value.
On restart, the processed record is re-fetched from Horizon and hits the dedup index — correct
but wasteful.

---

## References

### Source Files

| File | Key Content |
|------|-------------|
| `crates/ingest/src/lib.rs` | `Ingestor::process()` (line 99), `Ingestor::poll_once()` (line 65), `Ingestor::attribute()` (line 214) |
| `crates/store/src/lib.rs` | `Store::record_deposit()` (line 368), `Store::get_cursor()` (line 681), `Store::set_cursor()` (line 692) |
| `crates/store/src/models.rs` | `NewDeposit` struct (line 164), `Transaction` model (line 42) |
| `crates/store/migrations/0001_init.sql` | `uq_tx_onchain` index (line 84), `ingest_cursor` table (line 151) |
| `crates/store/migrations/0002_horizon_op_id.sql` | `horizon_op_id` column + `uq_tx_horizon_op_id` index (lines 8–12) |

### Documentation

| Document | Relevant Section |
|----------|-----------------|
| `docs/deposit-model.md` | Attribution: muxed id → memo id fallback |
| `docs/threat-model.md` | Row C: "Double-credit on failed/reorged tx", "Replayed Horizon events" |
| `docs/architecture.md` | Ingest flow overview |

---

> **Document maintainers:** If the dedup strategy or reorg handling changes (e.g., adding a
> confirmation-depth check, a reorg detector, or a `pending → confirmed` state machine), update
> this document to reflect the new behaviour. The [Known Limitations](#known-limitations) section
> in particular must be kept honest.

---

## EVM Deposit Detection (ERC-20 Transfer Logs)

> **Added:** Issue #221. **Blocks:** #222 (confirmation/crediting).

### Architecture

The EVM ingest worker (`crates/ingest/src/evm.rs`) mirrors the Stellar `Ingestor`'s shape and
reliability contract but operates on a fundamentally different data model:

| Dimension | Stellar | EVM |
|---|---|---|
| **Scan method** | `Horizon /payments` feed per account | `eth_getLogs` with a block range filter |
| **Cursor type** | Horizon paging token (opaque string) | Block number (`u64`) |
| **Customer attribution** | Muxed id embedded in the payment destination | Deposit address registered in `addresses` table |
| **Dedup key** | `horizon_op_id` (Horizon TOID) | `(chain_id, tx_hash, log_index)` |
| **Initial status** | `confirmed` (Stellar has instant finality) | `unconfirmed` (EVM has probabilistic finality) |

### What is detected

The EVM worker detects **ERC-20 Transfer events** only. Specifically, it calls `eth_getLogs`
filtered by:

- **Address list:** all registered token contracts on the chain (from `RegisteredToken`).
- **Topic 0:** the `Transfer(address,address,uint256)` event signature hash
  (`0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef`).

### Native ETH is out of scope for v1

Native ETH transfers emit **no logs**. They are only detectable by inspecting block transactions
(`eth_getBlockByNumber`) or via `debug_traceBlock`, which are significantly more expensive than a
targeted `eth_getLogs` filter — and `debug_traceBlock` is not available on all providers.

**Decision:** For v1, native ETH deposits are **explicitly out of scope**. This is a deliberate,
documented choice, not a silent omission.

- Operators must communicate to their users that only ERC-20 tokens are accepted at EVM deposit
  addresses.
- A customer who sends ETH directly to their deposit address will **not** have it credited.
- Supporting native ETH is tracked as a future enhancement; the architecture does not prevent it.

### Security: contract address verification

**The single most important invariant in the EVM ingest module:**

Logs are matched on the **emitting contract address** (`log.address`), not on topics alone.

Any contract can emit a `Transfer` event with arbitrary topics — including a deposit address in
`topics[2]` (the `to` field) and an enormous value in `data`. If the worker attributed transfers
based on topics alone, an attacker could:

1. Deploy a hostile contract.
2. Call it, emitting a `Transfer` event with an octo deposit address as `to` and e.g.
   `2^64 - 1` units as the value.
3. Receive a credit for that amount, without ever sending any tokens.

The defence is in `EvmIngestor::process_log` (step 1):

```rust
// Step 1: Verify the log was emitted by a registered token contract.
let token = self.registered_tokens.iter()
    .find(|t| t.contract_address.eq_ignore_ascii_case(&log.address));

let token = match token {
    Some(t) => t,
    None => return Ok(Processed::Skipped), // not a registered contract → skip
};
```

This check happens **before** reading any topic. A log from an unregistered contract is always
`Skipped`, regardless of what its topics claim.

The adversarial test `fake_transfer_from_unregistered_contract_is_skipped` in
`crates/ingest/tests/evm_ingest_tests.rs` is the primary regression guard for this property.

### Non-standard ERC-20s: fee-on-transfer and rebasing tokens

Fee-on-transfer tokens (e.g. SafeMoon clones) emit a `Transfer` event with a `value` that is
**larger than the amount actually received** by the `to` address (a fee is deducted in transit).
Rebasing tokens (e.g. AMPL) change holders' balances without emitting Transfer events.

**Defence:** The token registry (`RegisteredToken`) is the gate. Only tokens explicitly
registered are credited. Operators must not register fee-on-transfer or rebasing tokens until
the crediting layer (#222) has explicit support for them. The `amount_base_units` stored is
the value from the Transfer event — for registered stablecoins (USDC, USDT, DAI) this is
accurate. For fee-on-transfer tokens it would overstate the received amount, which is why
only the registry can admit new tokens.

### Cursor contract

The block-number cursor is stored in `ingest_cursor(wallet_id, chain_id)` and advances
**after each log is durably processed**, not at the end of a batch. If the process crashes
mid-range:

1. On restart, `get_evm_cursor` returns the last durably-processed block.
2. `poll_once` starts from `cursor + 1`.
3. Any logs in the current block that were already processed are caught by the
   `(chain_id, tx_hash, log_index)` dedup index in `transactions` and returned as `Duplicate`.

This is the same crash-safety guarantee the Stellar path gives via the Horizon paging token.

### Unconfirmed status

EVM deposits are recorded as `status = 'unconfirmed'`, not `'confirmed'`. They must not be
treated as spendable until issue #222 (confirmation-depth check) promotes them.

This is enforced at the DB level: `Store::record_evm_deposit` always inserts
`status = 'unconfirmed'`. Merging the ingest worker (#221) before the crediting layer (#222)
cannot create spendable balances.

The test `evm_deposit_status_is_always_unconfirmed` in `crates/ingest/tests/evm_ingest_tests.rs`
locks this in as a non-negotiable regression guard.

### Adaptive range bisection

Different EVM providers cap `eth_getLogs` block ranges differently (Alchemy: 2 000 blocks,
Infura: 10 000 blocks, self-hosted: unlimited). A fixed range would stall on providers with
tighter caps.

When `eth_getLogs` returns a `RangeTooLarge` error (detected by message pattern matching on
the JSON-RPC error object), `EvmIngestor::poll_once` halves the block range and retries, up
to `MAX_BISECTIONS = 16` times. If the range reaches `MIN_BLOCK_RANGE = 1` and still fails,
the error is surfaced as `EvmIngestError::RangeTooLargeExhausted`.

### Schema changes (migration 0021)

Migration `crates/store/migrations/0021_evm_ingest.sql` adds:

| Table | Change |
|---|---|
| `ingest_cursor` | Nullable `chain_id TEXT` and `block_number BIGINT` columns; unique index `uq_ingest_cursor_wallet_chain (wallet_id, chain_id) WHERE chain_id IS NOT NULL` |
| `transactions` | Nullable `chain_id TEXT` and `evm_log_index INTEGER` columns; unique index `uq_tx_evm_onchain (chain_id, stellar_tx_hash, evm_log_index) WHERE chain_id IS NOT NULL AND ...` |
| `transactions` | Status constraint extended to include `'unconfirmed'` |

All new columns are nullable — existing Stellar rows are unaffected. The migration is
forward-only and append-only.

### Store functions added

| Function | Purpose |
|---|---|
| `Store::get_evm_cursor(wallet_id, chain_id)` | Read the EVM block-number cursor |
| `Store::set_evm_cursor(wallet_id, chain_id, block)` | Advance the cursor after a durable record |
| `Store::mark_evm_polled(wallet_id, chain_id)` | Record "looked at" time (drives backoff tiers) |
| `Store::record_evm_deposit(NewEvmDeposit)` | Idempotent insert of an EVM deposit row |
| `Store::evm_address_by_hex(wallet_id, hex)` | Look up a deposit address by hex (case-insensitive) |

### Test coverage

| Test | File | What it verifies |
|---|---|---|
| `erc20_transfer_to_deposit_address_is_recorded` | `evm_ingest_tests.rs` | Happy path; attributed, unconfirmed |
| `dai_transfer_18_decimals_stored_correctly` | `evm_ingest_tests.rs` | 18-decimal amounts fit in `i64` correctly |
| `fake_transfer_from_unregistered_contract_is_skipped` | `evm_ingest_tests.rs` | **Critical security test** |
| `replay_same_log_is_idempotent` | `evm_ingest_tests.rs` | Dedup on `(chain_id, tx_hash, log_index)` |
| `cursor_advances_per_block_and_resume_is_exactly_once` | `evm_ingest_tests.rs` | Crash-resume contract |
| `transfer_of_unregistered_token_to_known_address_is_skipped` | `evm_ingest_tests.rs` | Quarantine of unregistered tokens |
| `range_too_large_error_causes_bisection_not_stall` | `evm_ingest_tests.rs` | Adaptive range bisection |
| `removed_log_is_never_processed` | `evm_ingest_tests.rs` | Reorged logs ignored |
| `transfer_to_non_deposit_address_is_skipped` | `evm_ingest_tests.rs` | Non-deposit addresses ignored |
| `evm_deposit_status_is_always_unconfirmed` | `evm_ingest_tests.rs` | `status = 'unconfirmed'` invariant |

Unit tests for `EvmLog` parsing (amount, address extraction, hex parsing) are in
`crates/ingest/src/evm.rs` under `#[cfg(test)]`.