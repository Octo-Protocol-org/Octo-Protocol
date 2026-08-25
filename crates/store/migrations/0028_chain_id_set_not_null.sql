-- Multi-chain schema, phase 4c: promote the validated CHECK constraints to real column-level
-- NOT NULL, then drop the now-redundant CHECK.
--
-- On Postgres 12+, `SET NOT NULL` can use an already-validated `CHECK (col IS NOT NULL)`
-- constraint as proof and skip its own table scan — so despite looking like a heavyweight
-- operation, this is metadata-only and fast, even on a production-sized `transactions` table.
ALTER TABLE wallets ALTER COLUMN chain_id SET NOT NULL;
ALTER TABLE wallets DROP CONSTRAINT chk_wallets_chain_id_not_null;

ALTER TABLE addresses ALTER COLUMN chain_id SET NOT NULL;
ALTER TABLE addresses DROP CONSTRAINT chk_addresses_chain_id_not_null;
ALTER TABLE addresses ALTER COLUMN deposit_address SET NOT NULL;
ALTER TABLE addresses DROP CONSTRAINT chk_addresses_deposit_address_not_null;

ALTER TABLE transactions ALTER COLUMN chain_id SET NOT NULL;
ALTER TABLE transactions DROP CONSTRAINT chk_transactions_chain_id_not_null;
