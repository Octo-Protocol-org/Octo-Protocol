-- EVM per-customer deposit addresses via HD derivation (see docs/deposit-model.md).
--
-- Stellar muxed addresses cost nothing on-chain: a customer address is just (base account, id),
-- so `next_muxed_id` + `addresses.muxed_id`/`muxed_address` was the whole model. EVM has no
-- muxed-account equivalent — each customer needs a real, distinct, HD-derived EOA at
-- m/44'/60'/0'/0/{index}. This migration generalises `wallets`/`addresses` just enough to support
-- that second allocation strategy, side by side with the unchanged Stellar one.
--
-- This is intentionally NOT the full multi-chain schema (a `chains` registry table, chain-scoped
-- transaction dedup, generalised network/network naming) — that is a separate, larger migration.
-- Scope here is exactly what EVM deposit-address allocation needs.

-- ---------------------------------------------------------------------------
-- wallets: which chain kind a wallet belongs to, and the EVM allocation counter.
-- ---------------------------------------------------------------------------

ALTER TABLE wallets ADD COLUMN chain_kind TEXT NOT NULL DEFAULT 'stellar'
    CHECK (chain_kind IN ('stellar', 'evm'));

-- CAIP-2 chain id (e.g. 'eip155:11155111'). NULL for Stellar wallets (identified by `network`
-- alone); required for EVM wallets so a future adapter/RPC lookup has something to key on, and so
-- the sealed seed's AAD context (bound to this id — see octo-evm-core) is recoverable from the row.
ALTER TABLE wallets ADD COLUMN chain_id TEXT;
ALTER TABLE wallets ADD CONSTRAINT wallets_evm_has_chain_id
    CHECK (chain_kind <> 'evm' OR chain_id IS NOT NULL);

-- Deriving (and, later, sweeping) an EVM deposit address requires the sealed HD seed to live on
-- this row, so an EVM wallet must be server-custody. Combined with the pre-existing
-- wallets_server_custody_has_seed CHECK, this guarantees every EVM wallet carries a sealed seed.
ALTER TABLE wallets ADD CONSTRAINT wallets_evm_is_server_custody
    CHECK (chain_kind <> 'evm' OR custody = 'server');

-- Next non-hardened BIP-44 index to hand out at m/44'/60'/0'/0/{index}. The column is BIGINT so
-- overflow is caught long before the 2^31-1 non-hardened ceiling (enforced below on
-- addresses.derivation_index) could ever wrap it.
ALTER TABLE wallets ADD COLUMN next_derivation_index BIGINT NOT NULL DEFAULT 0
    CHECK (next_derivation_index >= 0);

-- ---------------------------------------------------------------------------
-- addresses: relax the muxed-only shape and add the EVM shape.
-- ---------------------------------------------------------------------------

-- EVM rows have neither a muxed id nor a muxed address.
ALTER TABLE addresses ALTER COLUMN muxed_id DROP NOT NULL;
ALTER TABLE addresses ALTER COLUMN muxed_address DROP NOT NULL;

-- BIP-44 non-hardened index, 0..=2^31-1 (2147483647).
ALTER TABLE addresses ADD COLUMN derivation_index BIGINT
    CHECK (derivation_index IS NULL OR derivation_index BETWEEN 0 AND 2147483647);

-- EIP-55 checksummed form, stored for display.
ALTER TABLE addresses ADD COLUMN evm_address TEXT;

-- Lowercased form, generated so it can never drift from evm_address. Lookups and the uniqueness
-- constraint key off THIS column, not evm_address, so a client sending an all-lowercase or
-- all-uppercase address still matches the checksummed row (case is a checksum, not part of the
-- address's identity) — see docs/deposit-model.md.
ALTER TABLE addresses ADD COLUMN evm_address_lower TEXT
    GENERATED ALWAYS AS (lower(evm_address)) STORED;

-- A row is either fully Stellar-shaped or fully EVM-shaped, never a mix and never neither.
ALTER TABLE addresses ADD CONSTRAINT addresses_chain_shape CHECK (
    (muxed_id IS NOT NULL AND muxed_address IS NOT NULL
        AND evm_address IS NULL AND derivation_index IS NULL)
    OR
    (evm_address IS NOT NULL AND derivation_index IS NOT NULL
        AND muxed_id IS NULL AND muxed_address IS NULL)
);

-- Case-insensitive global uniqueness (NULLs — i.e. Stellar rows — are distinct from each other in
-- a standard Postgres UNIQUE index, so this constrains only EVM rows).
ALTER TABLE addresses ADD CONSTRAINT uq_addresses_evm_address_lower UNIQUE (evm_address_lower);

-- Per-wallet index uniqueness is redundant with the row-lock in Store::allocate_evm_address (two
-- concurrent allocations can never observe the same next_derivation_index), but is cheap
-- defense-in-depth against a future caller that bypasses that path.
ALTER TABLE addresses ADD CONSTRAINT uq_addresses_wallet_derivation_index
    UNIQUE (wallet_id, derivation_index);

CREATE INDEX idx_addresses_evm_address_lower ON addresses(evm_address_lower)
    WHERE evm_address_lower IS NOT NULL;
