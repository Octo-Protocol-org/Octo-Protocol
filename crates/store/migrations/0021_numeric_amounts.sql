-- Arbitrary-precision amounts (issue #215): `amount_stroops BIGINT` encodes two Stellar-specific
-- assumptions -- 7 decimal places and values that fit in 64 bits -- that don't hold on EVM chains
-- (18-decimal ETH/ERC-20, uint256 balances up to ~1.16e77). Add a NUMERIC(78,0) column able to
-- hold the full uint256 range as an exact integer count of base units, with decimals owned by the
-- token registry (a future issue), never inferred from the value itself.
--
-- Additive and online-safe: no column is renamed or dropped, so a running old binary mid-deploy
-- keeps working against `amount_stroops` unchanged. `amount_stroops` stays in place for at least
-- one release (rollback path); a follow-up migration can drop it once nothing reads it anymore.
-- The `> 0` check is added NOT VALID + VALIDATE CONSTRAINT so it never takes a long-lived
-- ACCESS EXCLUSIVE lock on these tables, mirroring the online-migration approach used for the
-- multi-chain schema work (issue #214).

ALTER TABLE transactions ADD COLUMN amount_base_units NUMERIC(78,0);
ALTER TABLE withdrawals ADD COLUMN amount_base_units NUMERIC(78,0);

UPDATE transactions SET amount_base_units = amount_stroops::numeric(78,0)
    WHERE amount_base_units IS NULL;
UPDATE withdrawals SET amount_base_units = amount_stroops::numeric(78,0)
    WHERE amount_base_units IS NULL;

ALTER TABLE transactions ADD CONSTRAINT transactions_amount_base_units_positive
    CHECK (amount_base_units > 0) NOT VALID;
ALTER TABLE withdrawals ADD CONSTRAINT withdrawals_amount_base_units_positive
    CHECK (amount_base_units > 0) NOT VALID;

ALTER TABLE transactions VALIDATE CONSTRAINT transactions_amount_base_units_positive;
ALTER TABLE withdrawals VALIDATE CONSTRAINT withdrawals_amount_base_units_positive;
