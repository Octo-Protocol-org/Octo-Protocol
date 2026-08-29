-- Multi-chain schema, phase 4b: validate the NOT VALID constraints added in
-- 0026_chain_id_not_null_check.sql.
--
-- VALIDATE CONSTRAINT takes SHARE UPDATE EXCLUSIVE, which conflicts only with other DDL (and
-- VACUUM FULL) — ordinary reads and writes proceed throughout the scan. This is deliberately a
-- separate migration file from 0026: sqlx runs each migration in its own transaction, and running
-- the NOT VALID add and the VALIDATE in the same transaction would hold the ADD's ACCESS EXCLUSIVE
-- lock for the whole scan (locks are held for the transaction's duration, not the statement's),
-- defeating the point of NOT VALID entirely.
ALTER TABLE wallets VALIDATE CONSTRAINT chk_wallets_chain_id_not_null;
ALTER TABLE addresses VALIDATE CONSTRAINT chk_addresses_chain_id_not_null;
ALTER TABLE addresses VALIDATE CONSTRAINT chk_addresses_deposit_address_not_null;
ALTER TABLE transactions VALIDATE CONSTRAINT chk_transactions_chain_id_not_null;
