# 0002: Version Sealed Seeds with an Explicit `sealed_scheme` and Chain/Account-Scoped AAD

## Status

Accepted

## Context

Sealed seeds are the encrypted-at-rest representation of a wallet's seed material. Over time the sealing format has needed to evolve: the cryptographic primitives change, the metadata bound into the ciphertext changes, and new chains or account models are introduced. Without an explicit version marker, a reader cannot tell which format a given sealed seed was produced with, and any change to the sealing logic risks silently misinterpreting or failing to open older seeds.

Two related problems motivate this decision:

1. **Format evolution.** The sealing algorithm and its parameters (KDF, AEAD construction, serialization) are expected to change. A sealed seed must carry enough information for the reader to select the correct unsealing path, and to reject formats it does not understand rather than guessing.

2. **Binding to context.** A sealed seed should only be usable for the chain and account it was created for. If a sealed seed is copied, swapped, or replayed against a different chain or account, unsealing must fail. This requires binding the chain and account identity into the authenticated associated data (AAD) of the AEAD, so that tampering with that context is detected cryptographically rather than relying on out-of-band checks.

Previously, the sealing format was implicit in the code and the context binding was not consistently enforced. This made migrations fragile and left room for cross-context misuse of sealed seeds.

## Decision

We will version sealed seeds with an explicit `sealed_scheme` field and bind chain/account context into the AEAD's associated data.

- **Explicit scheme identifier.** Every sealed seed records a `sealed_scheme` value that identifies the sealing format (primitives, parameters, and serialization) used to produce it. Readers dispatch on this value to the correct unsealing implementation. Unknown or unsupported schemes are rejected with a clear error rather than being interpreted with a default.
- **Chain/account-scoped AAD.** The chain identifier and account identifier are included in the AAD passed to the AEAD during both sealing and unsealing. Unsealing recomputes the AAD from the expected chain and account and fails authentication if the sealed seed was produced for a different context.
- **Forward-compatible evolution.** New sealing formats are introduced by adding a new `sealed_scheme` value and a corresponding unsealing path, leaving existing schemes readable. Scheme values are never reused or repurposed.
- **Migration on read.** When an older scheme is encountered, the seed may be unsealed with the legacy path and re-sealed under the current scheme, subject to the normal write path.

## Consequences

- **Positive:** Sealed seeds are self-describing, so format changes can be rolled out without ambiguity about how to read existing data. Cross-chain and cross-account misuse of a sealed seed is detected cryptographically. Rejecting unknown schemes fails safe instead of risking misinterpretation.
- **Positive:** Adding a new scheme is a localized change: a new identifier plus a new unsealing path, with no need to mutate existing formats.
- **Negative:** Every sealed seed carries additional metadata (`sealed_scheme`), and the AAD construction must be kept in exact agreement between sealing and unsealing. A mismatch in how chain/account identifiers are encoded into AAD will cause authentication failures.
- **Negative:** Supporting multiple schemes means maintaining legacy unsealing code until all stored seeds have been migrated. Tests must cover each supported scheme and the context-binding failure cases.
- **Operational:** Migrations must preserve the original scheme identifier until re-sealing completes, and any tooling that inspects sealed seeds must understand the `sealed_scheme` field.