-- Multi-chain schema, phase 4a: add the NOT NULL guarantee as a `NOT VALID` CHECK constraint.
--
-- `ADD CONSTRAINT ... CHECK (col IS NOT NULL) NOT VALID` takes ACCESS EXCLUSIVE but only for the
-- instant it takes to register the constraint in the catalog — it does not scan existing rows, so
-- it is safe on a production-sized table. The scan happens next, in
-- 0027_validate_chain_id_not_null.sql, under a much weaker lock that does not block reads/writes.
--
-- These four columns are exactly the ones with no NULL producer left after phase 3: every existing
-- row was backfilled, and every new row (via octo_store::Store) is written with chain_id /
-- deposit_address populated already. `transactions.tx_hash` stays nullable — it mirrors
-- `stellar_tx_hash`, which is legitimately NULL for pending/withdrawal rows with no on-chain hash
-- yet, and the anti-double-credit index already accounts for that with a partial `WHERE tx_hash IS
-- NOT NULL` (see 0032_uq_tx_onchain_chain_concurrent.sql).
ALTER TABLE wallets
    ADD CONSTRAINT chk_wallets_chain_id_not_null CHECK (chain_id IS NOT NULL) NOT VALID;
ALTER TABLE addresses
    ADD CONSTRAINT chk_addresses_chain_id_not_null CHECK (chain_id IS NOT NULL) NOT VALID;
ALTER TABLE addresses
    ADD CONSTRAINT chk_addresses_deposit_address_not_null CHECK (deposit_address IS NOT NULL) NOT VALID;
ALTER TABLE transactions
    ADD CONSTRAINT chk_transactions_chain_id_not_null CHECK (chain_id IS NOT NULL) NOT VALID;
