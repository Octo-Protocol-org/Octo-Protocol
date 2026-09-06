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
