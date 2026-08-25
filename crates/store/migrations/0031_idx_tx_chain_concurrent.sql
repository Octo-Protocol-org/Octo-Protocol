-- no-transaction
-- Multi-chain schema, phase 5c: supporting index for per-chain transaction lookups.
CREATE INDEX CONCURRENTLY idx_tx_chain ON transactions(chain_id);
