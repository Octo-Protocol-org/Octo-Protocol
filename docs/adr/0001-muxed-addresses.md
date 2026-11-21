# 0001: Use Muxed Addresses as Primary Deposit Address

- **Status:** Accepted
- **Date:** 2024-01-01

## Context

Stellar accounts are identified by a public key (`G...`). A single account can
receive many deposits, but on-chain payments to a bare `G...` address carry no
information about which end user or invoice the payment is for. Historically
this was disambiguated with a memo attached to the transaction, which requires
the sender to construct the payment correctly and for the receiver to match
`(address, memo)` pairs.

Memos are fragile in practice:

- Many wallets and exchanges do not let users attach a memo, or attach it to the
  wrong field, causing deposits to be misattributed or lost.
- Memo matching is a receiver-side convention; there is no protocol-level
  guarantee that a memo is present or unique.
- The deposit model documented in `docs/deposit-model.md` needs a stable,
  self-describing identifier per deposit so that funds can be routed to the
  correct end user without out-of-band coordination.

Stellar supports **muxed accounts** (introduced with CAP-27): an address of the
form `M...` that encodes a `G...` account together with a 64-bit memo ID. A
payment to an `M...` address is credited to the underlying `G...` account, and
the memo ID is available on-chain to the receiver. This gives us a first-class,
protocol-supported way to tag deposits.

## Decision

We will use **muxed addresses (`M...`) as the primary deposit address** for each
end user / deposit stream. Each deposit is assigned a unique 64-bit memo ID, and
the corresponding `M...` address is derived from our custody `G...` account and
that ID. Senders pay to the `M...` address directly; we read the memo ID from the
operation to attribute the deposit.

As a **fallback**, for senders or integrations that cannot handle `M...`
addresses, we continue to accept payments to the bare `G...` account **with a
memo** carrying the same identifier. The fallback path is matched on
`(G..., memo)` exactly as before, and is treated as a lower-priority,
compatibility-only route.

The deposit model in `docs/deposit-model.md` is updated to describe `M...` as the
canonical address and the `G...` + memo form as the legacy fallback.

## Consequences

**Positive**

- Deposits are self-describing: the memo ID travels with the payment at the
  protocol level, removing a class of misattribution bugs.
- Senders do not need to understand or correctly populate a separate memo field
  when using the primary path.
- The 64-bit ID space is large enough to allocate IDs without reuse concerns.

**Negative / trade-offs**

- Some wallets and exchanges still do not support `M...` addresses, so we must
  maintain and test the `G...` + memo fallback indefinitely.
- We must handle both routing paths in ingestion, reconciliation, and reporting,
  which adds branching complexity.
- Memo IDs must be allocated and persisted durably; collisions or reuse would
  misroute funds, so allocation requires care.

**Follow-ups**

- Document ID allocation and uniqueness guarantees.
- Add monitoring to detect deposits that arrive via the fallback path so we can
  track adoption of muxed addresses.
- Ensure all client SDKs and docs present the `M...` address first.