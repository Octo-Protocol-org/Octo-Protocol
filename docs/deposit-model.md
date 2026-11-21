# Deposit model: muxed-primary + memo fallback

## The idea

A **muxed account** (`M...`, [SEP-0023](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md))
is one real Stellar account (`G...`) plus a 64-bit **id** encoded into the address. octo gives
each customer their own `M...`. All customers' funds land in the **single** base account, and each
payment record carries the id, so we attribute deposits without:

- per-customer on-chain accounts,
- per-customer XLM base reserves,
- an auto-sweep transaction.

Generating a customer address is therefore a cheap, **off-chain** operation: take the next id,
encode `M...`.

```
Customer A → M…(id=1) ┐
Customer B → M…(id=2) ├─►  one account on-chain:  G…XYZ  (master wallet)
Customer C → M…(id=3) ┘
deposit to M…(id=2) → lands in G…XYZ, record says id=2 → attributed to Customer B
```

## Why a fallback is needed

A muxed address is mathematically identical to **base `G...` + id**. The legacy Stellar pattern
for "many users, one account" is **base `G...` + a numeric memo (id)**. Same information, older
encoding. Some senders — notably several centralized exchanges — still only accept a `G...`
address plus a memo and cannot send to an `M...` string.

So octo exposes **both** forms of every customer address:

| Form | Use |
|---|---|
| `muxed_address` (`M...`) | Default. Modern wallets/SDKs. No "forgot the memo" footgun. |
| `{ base_address: G..., memo_id }` | Fallback for senders that only accept `G...` + memo. |

## Attribution

The `ingest` crate matches an incoming payment to a customer by:

1. the **destination muxed id** (if the payment was sent to an `M...`), or
2. the **transaction memo id** (if sent to the base `G...` with a numeric memo).

Both map to the same customer row. No data-model difference — we store the base account and the
`u64` id once.

## Path payments

`path_payment_strict_send` and `path_payment_strict_receive` are credited like a plain payment.
Horizon reports the **received** side in `amount` / `asset_*` and the sender's spend in
`source_amount` / `source_asset_*`; octo only ever reads the received side. Attribution (muxed id,
then memo id) and dedup (operation id) are unchanged. A path payment from the master account to
itself is an asset conversion, not new funds, and is skipped.

## Claimable-balance claims

A sender can create a claimable balance naming the master account as claimant. Nothing is credited
when the balance is **created** — the funds are not ours until claimed. When the master account
submits a successful `claim_claimable_balance`, ingest records **one** deposit for that claim
operation:

| Field | Source |
|---|---|
| Dedup key (`horizon_op_id`, tx hash + op index) | The **claim** operation — one claim, one row |
| `amount_stroops`, asset | The claim's `account_credited` effect for the master account (`/operations/{id}/effects`) |
| `source_account` (origin) | The balance's **creator**: the `create_claimable_balance` op from `/claimable_balances/{id}/operations` |
| `memo_id` / customer | The creating transaction's numeric memo id, resolved like the memo fallback above |
| `destination_account` | The claimant (the master `G...`) |

Rules:

- **Origin is the creator, never the claimer.** The claim transaction is ours, so its memo or muxed
  source says nothing about who paid; only the sender's creating transaction can attribute.
- A claim with no memo id on the creating transaction is recorded but **quarantined**
  (`address_id = NULL`), exactly like a memo-less payment.
- A claim of a balance the master account **created itself** (reclaiming returned funds) is not a
  deposit and is skipped.
- Claims by any other account are skipped without a Horizon lookup.
- If Horizon cannot answer the effects or origin lookup, processing fails and the cursor does not
  advance, so the claim is retried rather than dropped or recorded with a guessed origin.

To see claims at all, ingest reads `/accounts/{G}/operations` rather than `/payments` (claims are
not payments in Horizon's view). Paging tokens are the same operation TOIDs on both endpoints, so
cursors carry over unchanged.

## Failed transactions

An operation whose transaction failed on-chain moved no funds and **never** creates a deposit, for
every operation type above. This is enforced at a single point (`is_from_successful_tx`, the first
check in `Ingestor::process`, which returns `Processed::FailedTransaction`), not by relying on
Horizon hiding failed transactions. It fails closed: a record without `transaction_successful` is
treated as failed. The cursor still advances past such operations so they are not re-fetched.
Regression tests: `invariant_failed_transactions_never_create_deposits` and
`invariant_failed_payment_from_horizon_creates_no_deposit_row`.
