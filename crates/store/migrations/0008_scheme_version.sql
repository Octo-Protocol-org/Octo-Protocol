-- Migration 0008: add an explicit scheme version tag to the wallets table.
--
-- The `sealed_scheme` column identifies which cipher/KDF combination was used to produce the
-- `sealed_ciphertext` for each wallet. This enables zero-downtime key/cipher rotation: the
-- server can open records under either the old or new scheme during a rotation window, and the
-- backfill job (`bin/migrate-keys`) walks all wallets and re-seals them under the new key +
-- scheme without any maintenance window.
--
-- Scheme values (must stay in sync with `SCHEME_V1` in crates/crypto/src/lib.rs):
--   1 = AES-256-GCM, HKDF-SHA256 per-record subkey, context-bound AAD (current)
--
-- Existing rows are set to 1 because they were already sealed under the scheme-v1 algorithm
-- (which existed before this column existed — the column is purely a tag, not a format change).
ALTER TABLE wallets
    ADD COLUMN IF NOT EXISTS sealed_scheme SMALLINT NOT NULL DEFAULT 1;

-- Backfill existing rows to scheme 1. The DEFAULT clause above handles rows inserted after this
-- migration runs, but any rows already in the table need the explicit UPDATE.
UPDATE wallets SET sealed_scheme = 1 WHERE sealed_scheme IS DISTINCT FROM 1;

-- Index for the migration job: allows a fast "find all wallets not yet on the target scheme"
-- scan without a full table seq-scan as the table grows.
CREATE INDEX IF NOT EXISTS idx_wallets_scheme ON wallets (sealed_scheme);

COMMENT ON COLUMN wallets.sealed_scheme IS
    'Cipher/KDF scheme used to seal this wallet''s HD seed. '
    '1 = AES-256-GCM + HKDF-SHA256 (current). '
    'See crates/crypto/src/lib.rs SCHEME_V1.';
