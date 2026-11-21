# octo-crypto

AES-256-GCM seal/open of the HD seed at rest (random nonce + salt). No blockchain knowledge.

## Public surface

- `seal` / `open` — encrypt and decrypt the HD seed at rest.
- `SealedSeed` — the sealed seed type.
- `SCHEME_V1` / `SCHEME_V2` — supported sealing schemes.
- `self_test` — boot self-test of the crypto primitives.

See [sealed seed versioning](../../docs/sealed-seed-versioning.md) for scheme details.