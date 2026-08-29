-- no-transaction
-- Multi-chain schema, phase 5d: the chain-scoped anti-double-credit guard.
--
-- This is the core fix in #214: the old `uq_tx_onchain` was UNIQUE(stellar_tx_hash,
-- operation_index) with no chain dimension, so it silently assumed a tx hash is globally unique —
-- true for a single Stellar network, false in general (the same signed transaction, or simply the
-- same hash value, is not guaranteed unique across two independent chains). Left alone, that old
-- index would eventually reject a legitimate deposit on chain B because chain A already used the
-- same (tx_hash, operation_index) pair — a dropped-deposit bug, not a double-credit one, but still
-- a fund-safety bug (see the regression test `same_tx_hash_different_chain_is_accepted` in
-- store_tests.rs for the corresponding double-credit-must-still-be-rejected-within-a-chain case).
--
-- Built CONCURRENTLY so it does not block writes to `transactions` while it scans; the old index
-- is only dropped in 0033, once this one is confirmed built and valid.
CREATE UNIQUE INDEX CONCURRENTLY uq_tx_onchain_chain
    ON transactions (chain_id, tx_hash, operation_index)
    WHERE tx_hash IS NOT NULL;
