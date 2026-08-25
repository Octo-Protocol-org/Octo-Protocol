-- no-transaction
-- Multi-chain schema, phase 5a: supporting index for per-chain address lookups.
-- CONCURRENTLY avoids the SHARE lock a plain CREATE INDEX would take (which blocks writes for the
-- duration of the build). Must be the only statement in this file — see 0024's header for why.
CREATE INDEX CONCURRENTLY idx_addresses_chain ON addresses(chain_id);
