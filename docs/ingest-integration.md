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