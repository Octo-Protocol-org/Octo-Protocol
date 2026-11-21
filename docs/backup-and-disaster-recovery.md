# Backup and Disaster Recovery

This document describes what an operator must back up to recover an Octo server, how that material must be stored, and how to prove that a restore actually works.

Sealed seeds are only as recoverable as the keys that seal them. A database backup without the master key is a pile of ciphertext; a master key without the database is a secret with nothing to open. **Both are required, and they must not live together.**

## What to back up

| Item | Where it lives | Secret? | Notes |
| --- | --- | --- | --- |
| PostgreSQL database | `pg_dump` output | Yes (contains sealed seeds, audit chain, user records) | The primary data asset. |
| `MASTER_KEY` | Key store (see below) | **Yes — critical** | Without it, every sealed seed is unrecoverable. |
| `MASTER_KEY_NEXT` | Key store | **Yes — critical** | Only present during a rotation window. Back it up while it exists; see [runbook-key-rotation.md](runbook-key-rotation.md). |
| `AUDIT_CHAIN_KEY` | Key store | **Yes** | Required to verify and continue the audit chain after restore. |
| `JWT_SECRET` | Key store | **Yes** | Active token-signing secret. |
| `JWT_SECRET_PREVIOUS` | Key store | **Yes** | Present during token rotation; needed so in-flight tokens remain valid after restore. |
| Non-secret configuration | Config repo / IaC | No | Server config, feature flags, role definitions, connection strings (without embedded secrets). |

If any of the key-store items above is missing from a backup set, that backup set is **incomplete** and must not be recorded as a valid recovery point.

## Separate custody

Database backups and key material MUST be stored in **different systems**, under **different access controls**, and — where staffing allows — managed by **different operators**.

- **Database backups** go to the backup/object-storage system, governed by the database operators.
- **Key material** goes to the secret manager / key store, governed by the key custodians.
- No single person, role, or credential should be able to read both a database backup and the corresponding key material. Restore requires two people (or two independent authorisations) to come together.

This split is what makes the sealing meaningful. See [threat-model.md](threat-model.md) for the adversary model this defends against.

### Warning: never co-locate the master key with the database backup

> **Do not store `MASTER_KEY` (or any key-store item) alongside, inside, or in the same system as a database backup.**
>
> Sealed seeds are encrypted at rest precisely so that a stolen database is useless on its own. Putting the master key next to the backup defeats that entirely: a single compromise — one leaked bucket, one stolen laptop, one over-broad IAM role — turns into **full disclosure of every seed**. The separation is the security control, not a convenience.

## Recovery targets

Set and review these targets with the business owner. Suggested starting points:

| Metric | Target | Meaning |
| --- | --- | --- |
| **RPO** (recovery point objective) | ≤ 15 minutes | Maximum acceptable data loss. Drives backup frequency / WAL archiving. |
| **RTO** (recovery time objective) | ≤ 2 hours | Maximum acceptable downtime from incident declaration to serving traffic. |

Backups must be taken at least as often as the RPO allows, and the restore drill below must complete within the RTO.

## Restore drill

Run this drill on a schedule (at least quarterly) and after any change to backup tooling, key handling, or schema. It is fully reproducible: every step is a command an operator can run.

### Prerequisites

- Access to the latest database backup (database operator).
- Access to the corresponding key material (key custodian).
- A scratch PostgreSQL instance that is **not** the production database.
- The `octo-server` binary matching the backup's schema version.

### Steps

1. **Restore the database into a scratch database.**

   ```sh
   createdb octo_restore_drill
   pg_restore --clean --if-exists --no-owner \
     --dbname=octo_restore_drill \
     /path/to/latest-octo.dump
   ```

   (If the backup is plain SQL from `pg_dump`, use `psql --dbname=octo_restore_drill --file=/path/to/latest-octo.sql`.)

2. **Restore key material from the separate key store** into the drill environment's secret store. Retrieve `MASTER_KEY`, `MASTER_KEY_NEXT` (if present), `AUDIT_CHAIN_KEY`, `JWT_SECRET`, and `JWT_SECRET_PREVIOUS` (if present). Do not copy these into the database host or the backup directory.

3. **Start the server against the restored database**, pointed at the drill key store:

   ```sh
   DATABASE_URL=postgres://localhost/octo_restore_drill \
   MASTER_KEY=... MASTER_KEY_NEXT=... \
   AUDIT_CHAIN_KEY=... \
   JWT_SECRET=... JWT_SECRET_PREVIOUS=... \
   octo-server serve
   ```

4. **Run verification queries** against the restored database to confirm integrity:

   ```sql
   -- Row counts match expectations for the backup's age
   SELECT count(*) FROM seeds;
   SELECT count(*) FROM users;

   -- No sealed seed is missing its version metadata
   SELECT count(*) FROM seeds WHERE sealed_version IS NULL;
   ```

   The second query must return `0`. See [sealed-seed-versioning.md](sealed-seed-versioning.md) for the versioning model.

5. **Verify the audit chain:**

   ```sh
   octo-server verify-audit-chain --database-url=postgres://localhost/octo_restore_drill
   ```

   This must report a valid chain. A broken chain means the backup or the `AUDIT_CHAIN_KEY` is wrong — investigate before declaring the drill passed.

6. **Confirm a sealed seed opens.** Pick a known seed and unseal it through the server (e.g. via the CLI or API) using the restored `MASTER_KEY`. If it decrypts to the expected plaintext, the key and data are correctly paired.

7. **Record the result.** Note the backup timestamp, the drill date, the operator(s), and whether each step passed. File any failures as incidents.

### Pass criteria

The drill passes only if **all** of the following hold:

- `pg_restore` completes without errors.
- Verification queries return the expected counts and zero rows with missing version metadata.
- `octo-server verify-audit-chain` reports a valid chain.
- A sealed seed unseals to its expected plaintext.
- The whole drill completes within the RTO.

## Related documents

- [sealed-seed-versioning.md](sealed-seed-versioning.md) — how sealed seeds are versioned and what the version metadata means.
- [postgres-roles.md](postgres-roles.md) — database roles and least-privilege setup for backup and restore.
- [runbook-key-rotation.md](runbook-key-rotation.md) — rotating `MASTER_KEY` and `JWT_SECRET`, and why `MASTER_KEY_NEXT` / `JWT_SECRET_PREVIOUS` must be backed up during rotation.
- [threat-model.md](threat-model.md) — the adversary model that motivates separate custody.