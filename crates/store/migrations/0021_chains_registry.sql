-- Multi-chain schema, phase 1: the `chains` registry.
--
-- See docs/architecture.md ("Data model: multi-chain") for the full migration plan and the
-- backward-compatibility strategy (Refs #214).
--
-- `chain_id` is a CAIP-2-shaped slug ("namespace:reference"), e.g. `eip155:1` for Ethereum
-- mainnet (real CAIP-2) or `stellar:pubnet` / `stellar:testnet` for Stellar (CAIP-2 has no
-- registered Stellar namespace yet, so we mint an internal slug in the same shape — it only has
-- to be stable and unique within this registry).
CREATE TABLE chains (
    chain_id            TEXT PRIMARY KEY,
    kind                TEXT NOT NULL CHECK (kind IN ('stellar', 'evm')),
    native_symbol       TEXT NOT NULL,
    native_decimals     SMALLINT NOT NULL,
    -- Ledgers/blocks to wait before treating a deposit as final. Stellar has no reorgs (closed
    -- finality), so 1 is a formality; EVM chains will set this to something real per chain.
    confirmation_depth  INTEGER NOT NULL DEFAULT 1,
    enabled             BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed the two chains that already have live data. `wallets.network` continues to be the source
-- of truth for these values until 0028_chain_id_set_not_null.sql lands and every caller has
-- migrated to `chain_id` directly (see the bridge helper in store/src/lib.rs).
INSERT INTO chains (chain_id, kind, native_symbol, native_decimals, confirmation_depth, enabled)
VALUES
    ('stellar:pubnet',  'stellar', 'XLM', 7, 1, true),
    ('stellar:testnet', 'stellar', 'XLM', 7, 1, true);
