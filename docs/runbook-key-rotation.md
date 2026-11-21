# Key Rotation Runbook: `MASTER_KEY` and `JWT_SECRET`

This runbook describes the end-to-end procedure for rotating the two long-lived secrets used by octo-server:

- **`MASTER_KEY`** — the key used to seal wallet seed material at rest (`sealed_ciphertext`). Rotation is performed online via the dual-key window implemented by `bin/migrate-keys`.
- **`JWT_SECRET`** — the key used to sign session tokens. Rotation is performed via a dual-secret window using `JWT_SECRET_PREVIOUS`.

> **Status:** This procedure has been walked through end-to-end on a staging database (see [Verification record](#verification-record)). It has not yet been exercised against production.

Related documents:

- [`docs/runbook-migrate-keys.md`](./runbook-migrate-keys.md) — operational details of the `octo-migrate-keys` tool.
- [`docs/sealed-seed-versioning.md`](./sealed-seed-versioning.md) — how `sealed_scheme` versioning and the dual-key window work.
- [`docs/threat-model.md`](./threat-model.md) — threat model; this runbook is referenced from the key-compromise and key-rotation sections.

---

## 1. Prerequisites and access

Before starting, confirm you have all of the following:

- [ ] **Operator access** to the secret store / deployment configuration where `MASTER_KEY` and `JWT_SECRET` are set (e.g. the environment manager, Kubernetes Secret, or vault entry used by your deployment).
- [ ] **Database access** with permission to run `SELECT` queries against the `wallets` table and to take a backup/snapshot.
- [ ] **Shell access** to a host that can reach the database and has the octo-server source tree checked out (to run `cargo run --release -p octo-migrate-keys`).
- [ ] **`octo-server` binary** available on the host for running `verify-audit-chain`.
- [ ] **New key material** generated for the key(s) you are rotating (see §2.1 for length/entropy requirements).
- [ ] **A maintenance/change window** booked. `MASTER_KEY` rotation requires **no downtime**; `JWT_SECRET` rotation **invalidates existing sessions** (see §5).
- [ ] **A second operator** available to review commands and to execute rollback if needed.

> ⚠️ Never rotate both keys in the same change window unless you have a specific reason. Rotate one key at a time so that any failure can be attributed and rolled back cleanly.

---

## 2. Pre-rotation checks

Run all of these **before** touching any secret.

### 2.1 Validate new key length and entropy

Both keys must be high-entropy random values of sufficient length. Generate them with a CSPRNG, e.g.:

```sh
# 32 bytes of randomness, base64-encoded
openssl rand -base64 32
```

Checks:

- [ ] New `MASTER_KEY` is at least 32 bytes of entropy (e.g. 32 random bytes, base64/hex encoded).
- [ ] New `JWT_SECRET` is at least 32 bytes of entropy.
- [ ] Neither key is a passphrase, a reused value, or derived from a previous key.
- [ ] Keys are stored only in the secret store — never in shell history, tickets, or chat. Prefer reading them from a file or the secret store directly.

### 2.2 Record current sealed scheme counts

Capture the baseline distribution of sealed wallet ciphertexts:

```sql
SELECT sealed_scheme, count(*) FROM wallets WHERE sealed_ciphertext IS NOT NULL GROUP BY sealed_scheme;
```

Record the output. After a completed `MASTER_KEY` rotation, all rows should be on the new scheme (see §4.1).

### 2.3 Take a database backup

- [ ] Take a full backup or snapshot of the database (or at minimum the `wallets` table) and record the backup identifier and timestamp.
- [ ] Verify the backup completed successfully before proceeding.

### 2.4 Check the migrate-keys checkpoint file state

`octo-migrate-keys` persists progress in a checkpoint file so an interrupted run can resume. Before starting:

- [ ] Locate the checkpoint file (see [`docs/runbook-migrate-keys.md`](./runbook-migrate-keys.md) for the configured path).
- [ ] Confirm there is **no stale checkpoint** from a previous, unrelated run. If one exists, confirm it corresponds to a completed rotation and archive/remove it per the migrate-keys runbook before starting a new rotation.

---

## 3. Rotating `MASTER_KEY` (dual-key window)

**Expected downtime: none.** Wallets remain readable throughout because the server accepts both the current and next key during the window.

### 3.1 Open the dual-key window

1. Generate the new key (§2.1).
2. In the secret store / deployment config, set:
   - `MASTER_KEY` — **unchanged** (still the current key).
   - `MASTER_KEY_NEXT` — the **new** key.
3. Roll out the configuration so the server picks up `MASTER_KEY_NEXT`. The server now accepts both keys for unsealing.

### 3.2 Run the migration tool

From the source tree on a host that can reach the database:

```sh
cargo run --release -p octo-migrate-keys -- --batch-size 100
```

The tool re-seals each wallet's `sealed_ciphertext` from the current key to `MASTER_KEY_NEXT`, in batches of 100, recording progress in the checkpoint file.

### 3.3 Monitor until complete

- [ ] Watch the tool's logs for progress and errors.
- [ ] Periodically re-run the count query to confirm progress:

  ```sql
  SELECT sealed_scheme, count(*) FROM wallets WHERE sealed_ciphertext IS NOT NULL GROUP BY sealed_scheme;
  ```

- [ ] Continue until the tool reports **0 wallets remaining** to migrate and exits successfully.

> If the tool is interrupted, re-run the same command — it resumes from the checkpoint file. Do **not** change keys while a run is incomplete.

### 3.4 Promote the new key

Once 0 wallets remain:

1. In the secret store, set `MASTER_KEY` to the value that was in `MASTER_KEY_NEXT`.
2. **Unset** `MASTER_KEY_NEXT`.
3. Roll out the configuration.

The dual-key window is now closed; only the new key is in use.

### 3.5 Clean up

- [ ] Archive or remove the checkpoint file per [`docs/runbook-migrate-keys.md`](./runbook-migrate-keys.md).
- [ ] Securely destroy the old key material from any temporary storage.

---

## 4. Rotating `JWT_SECRET` (dual-secret window)

**Expected downtime: none for the service, but existing sessions are invalidated** (see §5). Users will need to log in again once the old secret is removed.

### 4.1 Open the dual-secret window

1. Generate the new secret (§2.1).
2. In the secret store, set:
   - `JWT_SECRET` — the **new** secret.
   - `JWT_SECRET_PREVIOUS` — the **old** secret.
3. Roll out the configuration. New tokens are signed with the new secret; tokens signed with the old secret continue to verify during the window.

### 4.2 Hold the window for the token TTL

- [ ] Keep `JWT_SECRET_PREVIOUS` set for **at least the token TTL** so that all tokens issued under the old secret expire naturally.

### 4.3 Close the window

After the TTL has elapsed:

1. **Unset** `JWT_SECRET_PREVIOUS`.
2. Roll out the configuration.

Any token still signed with the old secret is now rejected; those sessions are invalidated.

---

## 5. Expected downtime summary

| Step | Downtime | User impact |
| --- | --- | --- |
| `MASTER_KEY` rotation (§3) | **None** | None — wallets readable throughout via dual-key window. |
| `JWT_SECRET` rotation (§4) | **None** for the service | Existing sessions invalidated once `JWT_SECRET_PREVIOUS` is removed; users must log in again. |

---

## 6. Verification

After completing a rotation, verify:

### 6.1 Sealed scheme counts

Re-run the count query and compare against the §2.2 baseline:

```sql
SELECT sealed_scheme, count(*) FROM wallets WHERE sealed_ciphertext IS NOT NULL GROUP BY sealed_scheme;
```

- [ ] After a completed `MASTER_KEY` rotation, all rows are on the new scheme and none remain on the old scheme.

### 6.2 Audit chain integrity

```sh
octo-server verify-audit-chain
```

- [ ] Command reports the audit chain is intact.

### 6.3 Spot-check authentication

- [ ] Log in with a test account and confirm a token is issued.
- [ ] Refresh the token and confirm it succeeds.
- [ ] Confirm a token issued **before** the `JWT_SECRET` rotation (if any remain) is rejected after `JWT_SECRET_PREVIOUS` is removed.

---

## 7. Rollback

### 7.1 `MASTER_KEY` — migration in progress

If the migration tool must be stopped before completion:

1. Stop the tool (Ctrl-C). Progress is preserved in the checkpoint file.
2. To abandon the rotation, swap the keys back: set `MASTER_KEY` to the original key and unset `MASTER_KEY_NEXT`, then roll out the configuration. Wallets that were already re-sealed to the next key remain readable **only while the next key is still configured** — so if any wallets were migrated, keep `MASTER_KEY_NEXT` set until you either resume or complete the rotation. Do not remove `MASTER_KEY_NEXT` while migrated rows still depend on it.
3. To resume, re-run `cargo run --release -p octo-migrate-keys -- --batch-size 100`; it continues from the checkpoint.

### 7.2 `MASTER_KEY` — rotation completed, need to revert

If the rotation completed but you must return to the old key:

- Re-run `octo-migrate-keys` with the **old and new keys swapped** (set `MASTER_KEY` to the current/new key and `MASTER_KEY_NEXT` to the old key), then run the tool to re-seal all wallets back to the old key, and promote as in §3.4.

### 7.3 `JWT_SECRET` — revert

If you need to revert before the TTL window closes:

- Set `JWT_SECRET` back to the old value and unset `JWT_SECRET_PREVIOUS`, then roll out the configuration. Tokens signed with the new secret will be invalidated.

---

## Verification record

| Item | Detail |
| --- | --- |
| Walked through on staging | **Yes** |
| Environment | Staging database |
| Procedure covered | `MASTER_KEY` dual-key rotation (§3) and `JWT_SECRET` dual-secret rotation (§4), including verification (§6) and rollback (§7) |
| Result | Completed successfully; verification queries and `verify-audit-chain` passed |

---

## See also

- [`docs/runbook-migrate-keys.md`](./runbook-migrate-keys.md)
- [`docs/sealed-seed-versioning.md`](./sealed-seed-versioning.md)
- [`docs/threat-model.md`](./threat-model.md)