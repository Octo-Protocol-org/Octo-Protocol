# octo-seed

Idempotent seed binary producing demo users, wallets and deposits for local development.

## What it creates

- A verified demo user, `demo@octo.local`.
- Demo wallets owned by that user.
- Two sample USDC deposits with stable transaction hashes and operation ids.

## Idempotency

All writes are upserts keyed on stable identifiers, so re-running the binary is a no-op.

## Mainnet refusal

Setting `NETWORK=mainnet` aborts before touching the database.

## Usage

```sh
NETWORK=testnet DATABASE_URL=postgres://... cargo run -p octo-seed
```

Environment variables:

- `NETWORK` — target network; `mainnet` is refused.
- `DATABASE_URL` — Postgres connection string.

## See also

- [`docs/threat-model.md`](../../docs/threat-model.md) — no secrets, tokens or personal data.
- [`docs/environment-variables.md`](../../docs/environment-variables.md) — environment variable reference.