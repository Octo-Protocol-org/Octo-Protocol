-- 0008_token_denylist.sql
--
-- Token deny-list for JWT session revocation.
--
-- Design (see docs/threat-model.md and PR for #127):
--  * Revoked tokens are stored by their full token string (or a hash — we store the raw token
--    here for simplicity; a SHA-256 hash would reduce storage but requires the caller to hash
--    before inserting. The token is already a signed opaque string with no plaintext secret in it,
--    so storing it verbatim is safe).
--  * expires_at mirrors the token's own `exp` claim so a scheduled job (or a simple WHERE clause)
--    can purge rows that are past their natural expiry — a token past `exp` would be rejected by
--    verify_token() anyway, so its deny-list row serves no purpose after that point.
--  * The PRIMARY KEY on token ensures O(1) lookup and deduplication (revoking an already-revoked
--    token is a no-op).

CREATE TABLE IF NOT EXISTS token_denylist (
    -- The full JWT string. Already a compact, non-secret opaque value.
    token       TEXT PRIMARY KEY,
    -- UTC timestamp when the token's `exp` claim fires. Used to prune stale rows.
    expires_at  TIMESTAMPTZ NOT NULL,
    -- When the revocation was recorded (audit trail).
    revoked_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Partial index to make the periodic purge query efficient.
CREATE INDEX IF NOT EXISTS idx_denylist_expires ON token_denylist (expires_at);
