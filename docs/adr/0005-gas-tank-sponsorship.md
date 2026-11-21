# ADR 0005: Gas Tank Sponsorship

- **Status:** Accepted
- **Date:** 2024-01-01
- **Deciders:** Core engineering team
- **Related:** [Non-custodial flow](../non-custodial-flow.md), [API](../api.md)

## Context

Users of the platform should not need to hold the native gas token to
interact with the protocol. Requiring users to acquire and manage gas
introduces friction, especially for first-time users and for flows where the
user's funds are held in a sealed, non-custodial seed that the server cannot
spend from.

At the same time, we must not compromise the non-custodial guarantees
described in [docs/non-custodial-flow.md](../non-custodial-flow.md). The
server must never be able to move user funds, only to pay for the network fees
associated with a transaction the user has already authorized. Any sponsorship
mechanism therefore has to be strictly limited in what it can sign and how much
it can spend.

We considered three broad approaches:

1. **User pays their own fees.** Simplest and most trustless, but requires
   every user to hold and manage the native token, which is a significant
   onboarding barrier.
2. **Server holds user funds and pays fees from them.** Rejected outright: this
   is custodial and violates the non-custodial flow.
3. **A separate, server-held "gas tank" that sponsors fees only.** The server
   maintains a dedicated account funded with the native token. It uses this
   account solely to sign the fee-bump wrapper of a transaction, never the
   user's signed payload.

## Decision

We will sponsor transaction fees using a **separate, server-held gas tank**.

- The gas tank is a dedicated account funded with the native gas token. It is
  operationally and logically separate from any user funds.
- When a user submits a transaction, the server wraps the user's already-signed
  payload in a fee-bump transaction and signs **only the fee-bump wrapper** with
  the gas tank key. The server never signs, alters, or has authority over the
  user's signed payload. This preserves the non-custodial guarantee: the gas
  tank can pay fees but cannot redirect or move user funds.
- Sponsorship is bounded by a **daily budget**. The gas tank tracks spend
  against a configurable per-day cap; once the cap is reached, further
  sponsorship requests are rejected and the client is expected to fall back to
  paying its own fees.
- The sponsorship behavior is exposed through the transaction submission
  endpoints documented in [docs/api.md](../api.md), which surface whether a
  transaction was sponsored and the relevant budget state.

## Consequences

### Positive

- Users can transact without holding the native gas token, removing a major
  onboarding barrier.
- The non-custodial model is preserved: the gas tank signs only the fee-bump
  wrapper and has no ability to move user funds.
- The daily budget caps the platform's exposure and makes sponsorship costs
  predictable and auditable.

### Negative

- The platform bears real operational cost for sponsored fees, which must be
  monitored and topped up.
- The gas tank key becomes a valuable operational secret; its compromise allows
  an attacker to drain the tank (though still not user funds). It requires the
  same key-management rigor as other server secrets.
- Budget exhaustion creates a degraded experience; clients must handle the
  fallback path where the user pays their own fees.

### Neutral

- Sponsorship policy (budget size, per-user limits, eligibility) becomes an
  operational concern that may need tuning over time.
- Additional monitoring and alerting are required to track tank balance and
  daily spend against the cap.