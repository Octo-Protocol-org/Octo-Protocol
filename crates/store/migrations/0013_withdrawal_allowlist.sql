-- Withdrawal address allowlist: an anti-fraud control letting a wallet restrict outbound
-- payments to a set of pre-approved destination accounts.
--
-- withdrawal_allowlist_configs — per-wallet toggle. `enabled = false` by default so existing
--   wallets are never suddenly locked out of sending to new destinations; a wallet must opt in.
-- whitelisted_addresses — the approved destination accounts for a wallet, when enabled.
--
-- Enforcement lives in the API (submit.rs), not the database: it is checked against the inner
-- Payment/PathPayment destination BEFORE the client-signed transaction is submitted to Horizon,
-- so a non-whitelisted send is rejected without ever touching the network.

CREATE TABLE withdrawal_allowlist_configs (
    wallet_id  UUID PRIMARY KEY REFERENCES wallets(id) ON DELETE CASCADE,
    enabled    BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE whitelisted_addresses (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id   UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    -- The approved destination (G... or M...). Stored as given; muxed addresses are decoded to
    -- their base G... at enforcement time (see wallet-core::address::decode_muxed), so an entry
    -- here matches both the muxed form and the underlying base account.
    address     TEXT NOT NULL,
    -- Optional human label ("Coinbase hot wallet", "CFO's Ledger", ...).
    label       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A wallet cannot whitelist the same address twice.
CREATE UNIQUE INDEX idx_whitelisted_addresses_wallet_addr
    ON whitelisted_addresses(wallet_id, address);

-- Fast lookup for the enforcement check and for listing a wallet's whitelist.
CREATE INDEX idx_whitelisted_addresses_wallet ON whitelisted_addresses(wallet_id);
