# evm-rpc

JSON-RPC client for EVM-compatible chains.

## Overview

`evm-rpc` is the workspace member that talks to EVM nodes over JSON-RPC. It
wraps transport, request building and response decoding so callers in the
workspace do not hand-roll HTTP or JSON handling.

## Behaviour

- **Submit-once rule:** a request is submitted at most once per call. Retries
  are the caller's responsibility; the client never silently re-sends a
  request, so non-idempotent methods cannot be duplicated by accident.
- **Response size cap:** responses are bounded by a maximum size. Oversized
  payloads are rejected rather than buffered without limit, protecting the
  process from memory exhaustion by a misbehaving or hostile node.

## Security

See [`docs/threat-model.md`](../../docs/threat-model.md) for the threat model
this crate is expected to respect. Never log secrets, tokens or personal data.

## Usage

See `src/lib.rs` for the public API and the crate's `Cargo.toml` for the
canonical one-line description.
