-- Composite index for the actual query shape of sponsored_transactions.
--
-- Every hot query (sum_sponsored_fees_today, sum_sponsored_fees_reserved_today,
-- try_reserve_sponsored_transaction's budget CTE, list_sponsored_transactions)
-- filters on wallet_id AND status before touching created_at.  The existing
-- idx_sponsored_wallet_time only covered (wallet_id, created_at), forcing Postgres
-- to scan all rows for a wallet and filter status in memory.
--
-- The new index matches the real filter order: (wallet_id, status, created_at DESC).
-- DROP idx_sponsored_wallet_time — no remaining query benefits from the narrower
-- index that omits status.

DROP INDEX IF EXISTS idx_sponsored_wallet_time;
CREATE INDEX idx_sponsored_wallet_status_time
    ON sponsored_transactions(wallet_id, status, created_at DESC);
