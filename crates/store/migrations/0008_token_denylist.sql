-- Token deny-list: server-side JWT revocation for logout.
--
-- JWTs are stateless by design, but a captured token would otherwise remain valid for up to 7 days
-- after the user logs out. This table provides a bounded deny-list keyed on a SHA-256 hash of the
-- token (the raw token is never stored). Entries expire naturally: a background job or a periodic
-- DELETE can prune rows where expires_at < now(), keeping the table small.
--
-- Security note: only the hash is stored, so a database breach does not expose tokens that could
-- be replayed against the API.

CREATE TABLE token_denylist (
    -- SHA-256 hex of the raw JWT — the lookup key.
    token_hash  TEXT        PRIMARY KEY,
    -- Mirrors the token's own `exp` claim so pruning is safe and deterministic.
    expires_at  TIMESTAMPTZ NOT NULL,
    -- Informational: which user revoked this token (CASCADE so old user rows don't block pruning).
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Fast expiry-based pruning: DELETE FROM token_denylist WHERE expires_at < now()
CREATE INDEX idx_token_denylist_expires ON token_denylist(expires_at);
