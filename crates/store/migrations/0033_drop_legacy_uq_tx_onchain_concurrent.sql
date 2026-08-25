-- no-transaction
-- Multi-chain schema, phase 5e: retire the old, non-chain-scoped anti-double-credit index now
-- that `uq_tx_onchain_chain` (0032) is built and live.
--
-- sqlx applies migrations strictly in version order and stops at the first failure, so this file
-- cannot run unless 0032 already committed successfully — the ordering guarantee the "only dropped
-- after the new one is live" requirement in #214 asks for. DROP INDEX CONCURRENTLY (rather than a
-- plain DROP INDEX) avoids even the brief ACCESS EXCLUSIVE a normal drop would take.
DROP INDEX CONCURRENTLY IF EXISTS uq_tx_onchain;
