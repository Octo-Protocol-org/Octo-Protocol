-- Multi-chain schema, phase 3a: backfill `wallets.chain_id` from the legacy `network` column.
--
-- `wallets` is a low-cardinality operational table (one row per master/custody wallet, not per
-- customer), so a single UPDATE is safe here — unlike `addresses`/`transactions`, it does not need
-- batching. This mirrors the precedent in 0008_scheme_version.sql (a plain backfill UPDATE for
-- this same table).
UPDATE wallets
SET chain_id = CASE network
                   WHEN 'mainnet' THEN 'stellar:pubnet'
                   WHEN 'testnet' THEN 'stellar:testnet'
               END
WHERE chain_id IS NULL;
