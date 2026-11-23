# Octo operator CLI

Run `cargo run -p octo-admin -- --help` for the command list. Add `--help`
after a command to see its arguments. Set `DATABASE_URL` in the environment.
Use a read-only database role for inspection. The CLI does not run migrations.

| Command | Purpose |
| --- | --- |
| `list-wallets` | Print one JSON object per wallet with its ID, public account, network and ingest status. |
| `verify-audit-chain [--user UUID]` | Check all chains or one user's chain. Exits nonzero if a chain is broken. |
| `pause-ingest WALLET_UUID --actor USER_UUID --apply` | Pause ingestion and preserve the wallet's cursor. |
| `requeue-deliveries ENDPOINT_UUID DELIVERY_UUID --actor USER_UUID --apply` | Immediately retry one dead event on its active endpoint. |

Verification and writes require the same base64-encoded 32-byte
`AUDIT_CHAIN_KEY` as the server. An operator's database credentials establish
their access. Use their existing Octo user UUID for `--actor` so the action
is attributed to their audit chain.

Pause and its audit entry commit together. The CLI records retry intent
before contacting the receiver and uses the normal signed webhook sender
and retry policy. It leaves the original delivery record in place and
reports the new delivery ID when available. Inspect the delivery log before
re-running a retry after a connection failure, since the receiver may have
accepted the event before the CLI could report the outcome.
