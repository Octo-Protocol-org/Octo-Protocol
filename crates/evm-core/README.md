# evm-core

Core EVM primitives for the workspace: secp256k1 keys, BIP-44 derivation, EIP-55 addresses and signing helpers.

## What's inside

- **secp256k1 / BIP-44 derivation** — derive account keys from a seed along a BIP-44 path.
- **EIP-55 addresses** — checksummed `0x`-prefixed address formatting and parsing.
- **Signing helpers** — sign and recover messages and transactions with a derived key.

## Warning: non-hardened derivation paths

Non-hardened BIP-44 segments allow an attacker who learns a child private key plus the
parent public key to recover the parent key. Prefer hardened segments for account-level
keys, and never expose extended public keys for non-hardened branches.

## Security

See [`docs/threat-model.md`](../../docs/threat-model.md) for the threat model this crate
is expected to uphold. Never commit secrets, `.env` files or real keys; use public test
vectors only.

## Development

Run `just fmt-check`, `just lint` and `just test` before pushing (see
[`CONTRIBUTING.md`](../../CONTRIBUTING.md)).
