# Architecture Decision Records

This directory contains the Architecture Decision Records (ADRs) for this project.
An ADR captures a single significant design decision together with the context that
motivated it and the consequences that follow from it. ADRs are immutable once
accepted: to change a decision, add a new ADR that supersedes the old one.

## Index

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-muxed-addresses.md) | Muxed addresses for per-payment identification | Accepted |
| [0002](0002-sealed-seed-versioning.md) | Sealed-seed versioning | Accepted |
| [0003](0003-polling-based-ingest.md) | Polling-based ingest | Accepted |
| [0004](0004-non-custodial-key-model.md) | Non-custodial key model | Accepted |
| [0005](0005-gas-tank-sponsorship.md) | Gas-tank sponsorship | Accepted |

## Numbering

- ADRs are numbered sequentially with a zero-padded four-digit prefix
  (`0001`, `0002`, ...). The number is assigned when the ADR is first proposed
  and is never reused, even if the ADR is later rejected or deprecated.
- The filename is `<number>-<kebab-case-title>.md`.
- References to an ADR use its number (e.g. "see ADR-0003") so links survive
  file renames.

## Status conventions

Each ADR carries exactly one status:

| Status | Meaning |
| --- | --- |
| Proposed | Under discussion; not yet binding. |
| Accepted | Agreed and in effect. |
| Deprecated | No longer recommended, but not yet replaced. |
| Superseded | Replaced by a later ADR; the superseding ADR is linked in the header. |
| Rejected | Considered and declined; kept for historical context. |

When an ADR is superseded, update its status and add a `Superseded by:` line to
its header. Do not edit the body of an accepted ADR.

## Template

Copy the block below into a new file named `<number>-<kebab-case-title>.md`.

```markdown
# ADR-<number>: <Title>

- **Status:** Proposed
- **Date:** YYYY-MM-DD
- **Supersedes:** <!-- ADR-NNNN, or "None" -->
- **Superseded by:** <!-- ADR-NNNN, or "None" -->

## Context

What is the problem or force that requires a decision? Describe the constraints,
requirements, and any options that were considered.

## Decision

What is the decision, stated in the active voice ("We will ...")? Be specific
enough that a reader can tell whether a future change complies with it.

## Consequences

What follows from the decision? Include both positive and negative outcomes,
trade-offs accepted, and any follow-up work or migration required.