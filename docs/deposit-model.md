# Deposit model: Stellar muxed-primary + EVM HD-derived

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

---

# EVM model: HD-derived per-customer EOAs

## Why muxed doesn't carry over

A muxed address is mathematically `base account + id`, decoded by whoever controls the base
account. EVM chains have no equivalent encoding: an ERC-20 `Transfer` event names exactly one
`to` address, and there is no id field anywhere in the transfer to decode. **The only way to get a
customer-identifying destination on EVM is to give each customer a real, distinct on-chain
address.**

So octo derives one externally-owned account (EOA) per customer, using [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)/[BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
hierarchical deterministic (HD) derivation at:

```
m / 44' / 60' / 0' / 0 / {index}
        purpose  coin  acct  chg  customer
                 type       (0=deposit)
```

`60` is Ethereum's SLIP-44 coin type (the same derivation applies on any `eip155:*` chain — Base,
Arbitrum, etc. all use coin type 60 too). `index` is a per-wallet counter — the EVM analogue of
`next_muxed_id` — bumped atomically under the same row-lock pattern as the Stellar path (see
[`Store::allocate_evm_address`](../crates/store/src/lib.rs)).

```
Customer A → m/44'/60'/0'/0/0 → 0xAaAa...  ┐
Customer B → m/44'/60'/0'/0/1 → 0xBbBb...  ├─►  N distinct on-chain EOAs, one per customer
Customer C → m/44'/60'/0'/0/2 → 0xCcCc...  ┘
deposit to 0xBbBb... → the Transfer's `to` topic IS the customer identity, no decoding needed
```

## Economic differences from the muxed model

| | Stellar (muxed) | EVM (HD-derived) |
|---|---|---|
| On-chain accounts created | 1 (the master), ever | N (customer-visible EOAs) — though allocation itself creates no on-chain transaction, since the address exists cryptographically the moment it's derived |
| Per-customer reserve | None | None to *allocate* — but see sweep, below |
| Funds land at | The single master account | Each customer's own address |
| Getting funds usable | Nothing further needed | Must be **swept** to a treasury (tracked separately — sweeping needs a design decision of its own, see below) |
| Gas for the sweep | N/A | The deposit address holds no native token, so the sweeper must either pre-fund it with gas or use a smart-contract forwarder pattern |
| Server-held keys | None (fully non-custodial) | The seed that derives every deposit key — a real custody exception, see the Security section below and `docs/threat-model.md` |

**Sweep-mechanism decision (recorded here per the issue that introduced EVM deposit addresses):**
two designs were considered for moving swept funds off deposit addresses:

- **HD EOAs + relayer-funded sweep** (what this repo implements): simplest, needs no contract
  deployment, but the deposit address needs native-token gas before it can send anything, and the
  server holds a real spending key for every deposit address.
- **CREATE2 forwarder contracts**: the deposit address is a *counterfactual* contract address
  (known before deployment), and sweeping can be pull-based (a relayer calls the contract, which
  forwards its balance) rather than needing the deposit address itself to hold gas. Trade-off: more
  gas cost per sweep (contract deployment + call, vs. a plain transfer) and real contract-code
  attack surface (see the "not a smart-contract system" caveat in `docs/threat-model.md`, which
  this would revoke).

Both are legitimate; this repo takes the HD-EOA path because it needs no contract deployment or
audit to ship deposit-address allocation, and because the sweep engine itself (which key funds
gas, when sweeps trigger, how sweep failures are retried) is separate, larger, follow-on work.
**Sweeping is not implemented by the deposit-address-allocation work this section documents** —
until it lands, EVM deposit funds sit at the customer's own address, unswept.

## Security: the xpub is a secret

This is the one property of BIP-44 that most needs to be understood correctly, so it is restated
here as well as in `docs/threat-model.md`:

> The path above is **hardened** through `m/44'/60'/0'` and **non-hardened** for `/0/{index}`.
> Non-hardened derivation means the extended *public* key (xpub) at `m/44'/60'/0'/0` plus any
> **one** leaked child *private* key is enough to reconstruct **every sibling private key** at
> that depth — the child key is `k_i = IL + k_par (mod n)`, a reversible modular addition, and
> `IL` is computable from the xpub alone. Practically: if the xpub for this branch is ever exposed
> (a log line, an API response, a webhook payload, a debugging session) and a single customer's
> deposit key is later compromised by any means, **every customer's deposit key on that wallet is
> compromised**, not just the one that leaked.

octo never constructs or exposes an xpub — every derivation walks the full path from the sealed
seed on demand (see [`octo_evm_core::deposit_address_from_sealed`](../crates/evm-core/src/lib.rs))
— but this is a structural property of the choice to use non-hardened derivation for the
deposit-facing branch, not an implementation detail that could be "fixed" without changing the
derivation scheme. Any future code that adds xpub-based (watch-only) derivation must carry this
warning forward.

## Recoverability

Only the **index** is guaranteed to reproduce the address — not the address string alone. Given
the wallet's seed (recovered from its BIP39 mnemonic, out-of-band) and a stored `derivation_index`,
`octo_evm_core::derive_deposit_address` always reproduces the exact same address. This is why
`addresses.derivation_index` is a real column, not a derived/cached value: it is the only durable
record of *how* to re-derive a given customer's key for disaster recovery.

## Case handling

An EVM address's mixed-case form ([EIP-55](https://eips.ethereum.org/EIPS/eip-55)) is a
**checksum**, not part of the address's identity — `0xf39F...` and `0xf39f...` (all-lowercase) are
the same address. octo stores the checksummed form for display but indexes and looks up on the
lowercase form (a generated column, `evm_address_lower`), so a client that sends any casing —
lowercase, uppercase, or checksummed — still resolves to the same row. See
`migrations/0021_evm_deposit_addresses.sql`.

## Confirmation depth and reorg handling (EVM only)

Stellar deposits are credited (`status = 'confirmed'`) the instant they're seen, because Stellar
consensus has instant finality — a `transaction_successful` payment cannot later be reorged away.
EVM blocks can and routinely do reorg (1–2 blocks is common on both L1 and L2s; deeper reorgs
happen on L2 sequencer failover), so crediting an EVM deposit on sight would let an attacker
deposit, get credited, force or exploit a reorg, and withdraw against a balance that no longer
exists.

Instead, an EVM deposit moves through explicit states, tracked in `transactions.confirmation_state`:

```
detected → confirming → confirmed          (spendable only from here)
                      ↘
                        orphaned            (reorg reversed it — terminal, never deleted)
```

`status` (the column every balance/aggregate query filters on) only ever becomes `'confirmed'` at
the same moment `confirmation_state` does — see `Store::progress_evm_confirmation` — so an
unconfirmed EVM deposit is invisible to every existing balance query with zero changes to those
queries. `orphaned` is a distinct terminal `status`, never reusing `'failed'`: an orphaned deposit
once existed and was later reversed (audit-relevant), whereas `'failed'` never existed as a credit
at all.

**Why depth is per-wallet, not a constant.** `wallets.confirmation_depth` and
`wallets.reorg_rewind_bound` are set at wallet-provisioning time, not hard-coded, because
different `eip155:*` chains carry very different reorg risk:

| Chain type | Suggested `confirmation_depth` | Why |
|---|---|---|
| Ethereum L1 | ~12 | Standard "high-value deposit" depth; covers ordinary 1–2 block reorgs with a wide margin |
| L2 with a centralized sequencer | Deeper (chain-specific) | A sequencer failover can reorg much further back than an L1 block-producer ever would; use the chain's own finality guidance, not the L1 number |
| Any chain, `reorg_rewind_bound` | `≥ 2 × confirmation_depth` (this repo's default) | The bound is how far the tracker will search for a common ancestor before giving up — it must comfortably exceed the depth an ordinary reorg could reach, or every confirmed-then-reorged deposit would also blow the bound |

Where a provider supports post-Merge `finalized`/`safe` block tags, those are a **stronger**
signal than depth-counting (the tag itself encodes finality, rather than an operator's estimate of
it) — `EvmRpcClient::block_by_tag` exposes this, though the tracker itself currently drives off
depth-counting only; switching a chain to tag-based finality is a config-level follow-on, not a
schema change.

**Reorg detection.** A cursor that only remembers a block *number* cannot detect a same-height,
different-hash reorg — the number looks identical either way. The tracker instead chains blocks by
*hash*: `evm_block_headers` stores `(block_number, block_hash, parent_hash)` for every block it has
verified, and each tick re-checks that the cursor's on-chain hash still matches what was recorded
before trusting anything newer. A mismatch (at the cursor, or discovered mid-walk-forward)
triggers a **bounded** backward search — comparing recorded vs. on-chain hash one block at a time
— for the last common ancestor, capped at `reorg_rewind_bound`. Finding one: every deposit at or
after `ancestor + 1` is marked `orphaned` (never deleted — the ledger stays append-only and the
reversal stays visible for audit) and a `deposit.orphaned` webhook fires per row. Not finding one
within the bound: the tracker alerts (`tracing::error!`, surfaced as `TickOutcome::DeepReorgAlert`)
and leaves state untouched rather than guessing at or looping past a malicious/misbehaving RPC —
see `docs/threat-model.md`'s reorg rows for the reasoning.

**Can an already-withdrawn deposit be reorged away?** No — this is the property the whole
confirmation-depth mechanism exists to guarantee. Withdrawal eligibility and reorg reversal are
gated on the exact same `status = 'confirmed'`, which is only ever set after `confirmation_depth`
confirmations elapsed. A deposit an attacker could withdraw against by definition already survived
that depth of reorg risk; the residual risk is only a reorg *deeper than the configured depth*,
which is a policy choice (see `docs/threat-model.md`'s "Known limitations"), not a gap in the
mechanism itself.

Implementation: `crates/ingest/src/confirmation.rs` (`ConfirmationTracker`, one per EVM wallet;
`EvmSupervisor` fans this out the same way `Supervisor` does for Stellar Horizon polling) and
`crates/ingest/src/evm_rpc.rs` (a minimal `eth_getBlockByNumber`-only JSON-RPC client — no
alloy/ethers dependency, per this workspace's narrow-primitives ADR). Migration:
`crates/store/migrations/0022_evm_confirmation_and_reorg.sql`.

## API shape

`POST /v1/wallets/{id}/addresses` and `GET /v1/wallets/{id}/addresses` return a chain-appropriate
shape: Stellar responses carry `muxed_address` / `base_address` / `memo_id`; EVM responses carry
`address` instead and **omit `memo_id` entirely** (not `null`) — there is nowhere for a memo to go
on an EVM chain, so the field isn't there to invite a client to send one. Both shapes carry
`chain_kind` so a client can branch without inspecting which optional fields are present. See
[`crates/api/src/routes/addresses.rs`](../crates/api/src/routes/addresses.rs).
