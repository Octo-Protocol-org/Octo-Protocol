-- Non-custodial migration: user wallets are created from a client-generated public key, so the
-- server never holds the USER's seed.
--
-- custody:
--   'server' — legacy: the sealed seed on this row is the user account's seed (pre-cutover).
--   'client' — the user's private key exists only client-side. If sealed_* are set on such a
--              row, they hold the seed of a separate GAS-TANK fee account (never the user key):
--              a server-held account that only ever carries fee float for gas sponsorship, so
--              the funds at risk are bounded by the gas budget — never customer balances.
--
-- encrypted_backup: an opaque blob the CLIENT encrypted under the user's password
-- (PBKDF2-SHA256 → AES-256-GCM, done in the browser/SDK). The server cannot decrypt it — it is
-- stored purely so the user can recover on a new device with their password.

ALTER TABLE wallets ALTER COLUMN sealed_ciphertext DROP NOT NULL;
ALTER TABLE wallets ALTER COLUMN sealed_nonce DROP NOT NULL;
ALTER TABLE wallets ALTER COLUMN sealed_salt DROP NOT NULL;

ALTER TABLE wallets ADD COLUMN custody TEXT NOT NULL DEFAULT 'server';
ALTER TABLE wallets ADD COLUMN encrypted_backup TEXT;
-- The gas tank's public account (G...). Set when a tank is provisioned for a client wallet;
-- its seed then lives in sealed_* (account index 0).
ALTER TABLE wallets ADD COLUMN gas_tank_account_g TEXT;

-- A server-custody row must always carry its seed.
ALTER TABLE wallets ADD CONSTRAINT wallets_server_custody_has_seed CHECK (
    custody <> 'server'
    OR (sealed_ciphertext IS NOT NULL AND sealed_nonce IS NOT NULL AND sealed_salt IS NOT NULL)
);

-- A gas tank is only meaningful with its seed present.
ALTER TABLE wallets ADD CONSTRAINT wallets_gas_tank_has_seed CHECK (
    gas_tank_account_g IS NULL
    OR (sealed_ciphertext IS NOT NULL AND sealed_nonce IS NOT NULL AND sealed_salt IS NOT NULL)
);
