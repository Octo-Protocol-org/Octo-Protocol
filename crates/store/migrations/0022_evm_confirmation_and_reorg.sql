-- Confirmation depth + reorg handling for EVM deposits (see docs/deposit-model.md,
-- docs/threat-model.md). Stellar deposits credit on sight because Stellar finality is instant
-- (crates/ingest/src/lib.rs's top-of-file guarantees); EVM blocks reorg, so crediting on sight
-- would let an attacker deposit, get credited, force/exploit a reorg, and withdraw against a
-- balance that no longer exists.
--
-- Deposits move through: detected -> confirming -> confirmed (spendable). A reorg can move a row
-- from confirming/confirmed to a terminal `orphaned` state instead. Rows are NEVER deleted; the
-- ledger is append-only and reversals must stay visible for audit.

-- ---------------------------------------------------------------------------
-- wallets: per-wallet (== per-EVM-chain-instance, in this schema) confirmation policy. "Do not
-- hard-code a number" (issue requirement) -- these are operator-set at wallet-provisioning time,
-- not baked into application code. A sensible starting point (documented in docs/deposit-model.md,
-- not enforced here): ~12 for Ethereum L1, deeper for L2s with sequencer-failover risk.
-- ---------------------------------------------------------------------------
ALTER TABLE wallets ADD COLUMN confirmation_depth INTEGER;
ALTER TABLE wallets ADD COLUMN reorg_rewind_bound INTEGER;
ALTER TABLE wallets ADD CONSTRAINT wallets_evm_has_confirmation_policy CHECK (
    chain_kind <> 'evm'
    OR (confirmation_depth IS NOT NULL AND confirmation_depth > 0
        AND reorg_rewind_bound IS NOT NULL AND reorg_rewind_bound >= confirmation_depth)
);

-- ---------------------------------------------------------------------------
-- transactions: confirmation progress + EVM on-chain identity (mirrors the existing
-- stellar_tx_hash/operation_index pair).
-- ---------------------------------------------------------------------------
ALTER TABLE transactions ADD COLUMN confirmation_state TEXT
    CHECK (confirmation_state IN ('detected', 'confirming', 'confirmed', 'orphaned'));
ALTER TABLE transactions ADD COLUMN evm_tx_hash TEXT;
ALTER TABLE transactions ADD COLUMN log_index INTEGER;
ALTER TABLE transactions ADD COLUMN block_number BIGINT;
ALTER TABLE transactions ADD COLUMN block_hash TEXT;
ALTER TABLE transactions ADD COLUMN confirmations INTEGER;
ALTER TABLE transactions ADD COLUMN orphaned_at TIMESTAMPTZ;

ALTER TABLE transactions ADD CONSTRAINT transactions_orphaned_at_matches_state CHECK (
    (orphaned_at IS NOT NULL) = (confirmation_state = 'orphaned')
);

-- A reorg-reversed row is a distinct terminal state from a plain relay/processing failure --
-- code that reads status = 'confirmed' as "spendable" must not be able to confuse an orphaned
-- row (funds existed, then a reorg took them away) with a merely-failed one (never existed).
ALTER TABLE transactions DROP CONSTRAINT transactions_status_check;
ALTER TABLE transactions ADD CONSTRAINT transactions_status_check
    CHECK (status IN ('pending', 'confirmed', 'failed', 'orphaned'));

-- Anti-double-credit for EVM, mirroring uq_tx_horizon_op_id: dedup on (evm_tx_hash, log_index).
-- A re-scan after a reorg re-detecting a survivor must not double-credit it.
CREATE UNIQUE INDEX uq_tx_evm_onchain
    ON transactions (evm_tx_hash, log_index)
    WHERE evm_tx_hash IS NOT NULL;

-- Hot query: "which of my rows are still accumulating confirmations" -- scanned every tracker
-- tick, so this is a partial index over exactly (and only) that working set.
CREATE INDEX idx_tx_confirming
    ON transactions (wallet_id, block_number)
    WHERE confirmation_state IN ('detected', 'confirming');

-- ---------------------------------------------------------------------------
-- evm_block_headers: a trailing window of (block_number -> hash, parent_hash) per wallet, so the
-- confirmation tracker can detect "same height, different hash" -- a reorg a number-only cursor
-- cannot see -- and walk back to the last common ancestor. Pruned to the rewind-bound window each
-- tick, so an unbounded rewind against a malicious/misbehaving RPC cannot grow this table without
-- bound (see wallets.reorg_rewind_bound).
-- ---------------------------------------------------------------------------
CREATE TABLE evm_block_headers (
    wallet_id     UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    block_number  BIGINT NOT NULL,
    block_hash    TEXT NOT NULL,
    parent_hash   TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (wallet_id, block_number)
);

-- ingest_cursor: the EVM analogue of paging_token -- the last block this wallet's tracker
-- verified as chained (number + hash), so the next tick can check the new tip's ancestry against
-- it.
ALTER TABLE ingest_cursor ADD COLUMN evm_last_block_number BIGINT;
ALTER TABLE ingest_cursor ADD COLUMN evm_last_block_hash TEXT;
