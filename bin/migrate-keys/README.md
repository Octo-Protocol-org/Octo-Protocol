# migrate-keys

Rotates the encryption keys used by the indexer, re-encrypting stored records from the old key to the new one.

## When to run

Run this tool when you are rotating the key material referenced by the service configuration, for example:

- scheduled key rotation;
- responding to a suspected key compromise;
- migrating to a new key version before decommissioning the old one.

Do not run it against a live database without a backup and a maintenance window. See the runbook for the full procedure, prerequisites and rollback steps: [`docs/runbook-migrate-keys.md`](../../docs/runbook-migrate-keys.md).

## Usage

```sh
migrate-keys --batch-size 500
```

### `--batch-size`

Number of records re-encrypted per batch. Smaller batches reduce memory use and lock contention; larger batches finish faster. Defaults to the value documented in the runbook.

## Security

Never commit keys, `.env` files or real key material. Follow [`docs/threat-model.md`](../../docs/threat-model.md).
