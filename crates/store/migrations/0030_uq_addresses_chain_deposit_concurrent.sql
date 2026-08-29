-- no-transaction
-- Multi-chain schema, phase 5b: `UNIQUE (muxed_address)` -> `UNIQUE (chain_id, deposit_address)`.
--
-- 0002_horizon_op_id.sql already dropped the old global `UNIQUE(muxed_address)` (it was redundant
-- with `UNIQUE(wallet_id, muxed_id)` at the time), so there is no legacy constraint to retire here
-- — this purely *adds* the correct chain-scoped invariant: a deposit address must be unique within
-- its chain (not globally), which is the wrong assumption for EVM where addresses are only unique
-- per chain. Partial (`WHERE deposit_address IS NOT NULL`) so it stays valid mid-backfill; by the
-- time this runs (phase 5, after phase 4's NOT NULL enforcement) the predicate is always true, but
-- keeping it costs nothing and documents the column's history.
CREATE UNIQUE INDEX CONCURRENTLY uq_addresses_chain_deposit
    ON addresses (chain_id, deposit_address)
    WHERE deposit_address IS NOT NULL;
