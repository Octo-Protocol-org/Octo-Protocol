# 0004: Non-Custodial Key Management

## Status

Accepted

## Context

The service relays transactions on behalf of users, and an early design sketch considered holding user keys server-side so that the backend could sign on the user's behalf. That approach would make the server a custodian of user funds: a compromise of the server, a rogue operator, or a subpoena could expose every user's keys and therefore every user's balance. It would also require the server to store long-lived secrets, expanding the attack surface and the compliance burden considerably.

The flow documented in `docs/non-custodial-flow.md` describes the alternative we want: the client is the only party that ever sees a private key. The server's role is limited to validating requests and relaying already-signed transactions to the network.

## Decision

User keys are generated and held exclusively client-side. The server never receives, stores, derives, or has any means of reconstructing a user's private key or seed material.

Concretely:

- Key generation happens in the client. The server is not involved in and has no visibility into the generation process.
- The client signs transactions locally. Only signed transactions are submitted to the server.
- The server validates submitted transactions (structure, signatures, and policy checks) and relays them to the network. It cannot alter, re-sign, or originate transactions on a user's behalf.
- Any server-side state associated with a user is limited to non-secret metadata needed to relay and track requests.

## Consequences

Positive:

- A server compromise does not expose user funds; there is no key material on the server to steal.
- Users retain ultimate control over their assets, which aligns with the trust model users expect from a relay service.
- The server holds no long-lived secrets for user accounts, simplifying key management, auditing, and compliance obligations.

Negative:

- Users are solely responsible for backing up their keys; lost keys cannot be recovered by the service. This must be communicated clearly in client UX and documentation.
- The server cannot perform operations that require signing on the user's behalf, so any such feature must be redesigned around client-side signing.
- Validation on the server is necessarily limited to what can be checked from signed data; the server cannot enforce invariants that depend on knowledge of the private key.

Neutral:

- The client bears more responsibility and complexity (key storage, signing), which must be reflected in client-side security guidance.
- Recovery and account-restoration features, if ever added, must be designed without introducing server-side custody of keys.