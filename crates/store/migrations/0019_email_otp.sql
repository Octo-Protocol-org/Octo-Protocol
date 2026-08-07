-- Email OTP codes for signup verification and withdrawal confirmation.
CREATE TABLE email_otps (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose       TEXT NOT NULL CHECK (purpose IN ('signup', 'withdrawal')),
    code_hash     TEXT NOT NULL, -- SHA-256 hex of the 6-digit code, never the raw code
    tx_hash_bound TEXT, -- binds a withdrawal OTP to one exact transaction; null for signup
    attempts      SMALLINT NOT NULL DEFAULT 0,
    consumed_at   TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_email_otps_user_purpose ON email_otps(user_id, purpose, created_at DESC);

-- Null means never verified; existing users are left null so their next login re-triggers OTP.
ALTER TABLE users ADD COLUMN email_verified_at TIMESTAMPTZ;
