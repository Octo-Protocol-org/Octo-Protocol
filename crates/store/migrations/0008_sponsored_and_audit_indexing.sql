-- Indexing overhaul for sponsored_transactions and audit_logs (issue: hard/store/indexing-overhaul).
--
-- PROPOSAL STATUS: these indices are derived from static analysis of the query shapes in
-- crates/store/src/lib.rs (see the "sponsored transactions" and "audit logs" sections), not yet
-- confirmed against EXPLAIN ANALYZE on a realistically-sized seeded dataset. Run
-- scripts/bench_store_indexes.sh in `explain` mode before and after this migration and paste both
-- outputs into the PR description before merging; adjust the indices below if the evidence
-- disagrees with the reasoning here.
--
-- sponsored_transactions
-- -----------------------
-- list_sponsored_transactions (read): WHERE wallet_id = $1 [AND status = $2] [AND cursor]
--   ORDER BY created_at DESC, id DESC LIMIT $4.
--   The existing idx_sponsored_wallet_time(wallet_id, created_at) index does not carry the `id`
--   tie-break the cursor pagination compares on, and only matches DESC order via a backward scan.
--   Replacing it with (wallet_id, created_at DESC, id DESC) serves the exact ORDER BY (no sort
--   node) and the cursor's tuple comparison, whether or not `status` is filtered. A backward scan
--   over this index also serves any future ASC-order need, so the old index is redundant once this
--   one exists.
--
-- sum_sponsored_fees_reserved_today / sum_sponsored_fees_today / try_reserve_sponsored_transaction
--   (read, but embedded in the hottest WRITE path — try_reserve runs on every sponsor request):
--   WHERE wallet_id = $1 AND status IN ('pending','confirmed') AND created_at >= today.
--   (wallet_id, created_at) alone still has to filter status per row within today's range. Adding
--   `status` as the second key — (wallet_id, status, created_at) — lets Postgres seek directly to
--   the (wallet_id, status) prefix and range-scan created_at from there, rather than scanning every
--   status for the wallet within the date range.
--
-- WRITE-PATH COST: sponsored_transactions is inserted on every sponsor request
--   (try_reserve_sponsored_transaction / record_sponsored_tx). Each additional index here adds one
--   more B-tree entry to maintain per INSERT and per status UPDATE (finalize_sponsored_transaction
--   changes `status`, which moves the row's entry in idx_sponsored_wallet_status_created). Going
--   from 1 index (excluding the PK and the UNIQUE dedup index) to 2 roughly doubles the non-PK
--   index-maintenance cost of that hot insert. This must be weighed against the read win in the
--   "before/after" evidence — if the real EXPLAIN ANALYZE numbers show the wallet+status+time index
--   doesn't meaningfully beat a plain (wallet_id, created_at) scan at production row counts (because
--   e.g. "today" already prunes the range enough), drop it and keep only the reordered pagination
--   index.
DROP INDEX IF EXISTS idx_sponsored_wallet_time;

CREATE INDEX idx_sponsored_wallet_created_id
    ON sponsored_transactions (wallet_id, created_at DESC, id DESC);

CREATE INDEX idx_sponsored_wallet_status_created
    ON sponsored_transactions (wallet_id, status, created_at);

-- audit_logs
-- ----------
-- list_audit_logs (read, dashboard-facing, not on a hot write path): WHERE user_id = $1
--   [AND category = $2] [AND (action ILIKE '%term%' OR target ILIKE '%term%')] ORDER BY created_at
--   DESC LIMIT $4.
--   `ILIKE '%term%'` (a leading wildcard) cannot use a plain B-tree index at all — Postgres falls
--   back to a full scan of every row already matched by user_id/category. A trigram GIN index lets
--   Postgres use a bitmap index scan for the substring search itself, which the planner can combine
--   (BitmapAnd) with the existing idx_audit_user_time / idx_audit_category B-tree indices instead of
--   scanning all of a hot user's history row-by-row.
--
-- WRITE-PATH COST: record_audit inserts one row per notable account action (sign-in, wallet
-- creation, credential change, etc.) — frequent, but nowhere near as hot as the sponsored-tx
-- reservation path. GIN indices are still meaningfully more expensive to maintain per INSERT than a
-- B-tree of the same cardinality (pending-list buffering aside, each trigram of the indexed text
-- becomes its own posting-list entry), so this is not "free" — call out the real INSERT-latency
-- delta from the before/after benchmark in the PR description.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX idx_audit_action_target_trgm
    ON audit_logs USING gin ((action || ' ' || coalesce(target, '')) gin_trgm_ops);
