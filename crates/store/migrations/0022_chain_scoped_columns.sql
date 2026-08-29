-- Multi-chain schema, phase 2: additive columns only.
--
-- Every column added here is NULLABLE with no DEFAULT, so each ADD COLUMN is a fast, metadata-only
-- change on Postgres 11+ (no table rewrite, no long lock) even on a production-sized
-- `transactions` table. `chain_id REFERENCES chains(chain_id)` is safe to add inline (not
-- NOT VALID) for the same reason: every existing row gets chain_id = NULL, and a NULL always
-- satisfies a foreign key, so there is nothing to validate against existing data yet.
--
-- Backward-compatibility strategy (the "renaming a column breaks the running old binary" question
-- from #214): we keep every legacy column (`network`, `stellar_tx_hash`, `muxed_address`, ...) and
-- add generic ones alongside (`chain_id`, `tx_hash`, `deposit_address`, ...), backfilled from the
-- legacy columns. This avoids a two-release rename dance (view / generated column indirection) at
-- the cost of some duplicated data — see docs/architecture.md for the full rationale.

ALTER TABLE wallets ADD COLUMN chain_id TEXT REFERENCES chains(chain_id);
CREATE INDEX idx_wallets_chain ON wallets(chain_id);

ALTER TABLE addresses ADD COLUMN chain_id TEXT REFERENCES chains(chain_id);
-- Generic deposit-address column. For Stellar this mirrors `muxed_address`; for a future EVM
-- adapter it is the actual HD-derived `0x...` address.
ALTER TABLE addresses ADD COLUMN deposit_address TEXT;
-- HD derivation index for EVM addresses (e.g. BIP-44 address_index). Stellar keeps using
-- `muxed_id`, which is not a key-derivation index at all (it's an off-chain routing id), so it is
-- deliberately not reused for this.
ALTER TABLE addresses ADD COLUMN derivation_index BIGINT;

ALTER TABLE transactions ADD COLUMN chain_id TEXT REFERENCES chains(chain_id);
-- Generic on-chain tx hash column, mirroring `stellar_tx_hash`. `operation_index` is already
-- chain-agnostic in shape (it doubles as the EVM log index) and needs no new column, only the
-- re-scoped uniqueness added in later phases of this migration set.
ALTER TABLE transactions ADD COLUMN tx_hash TEXT;
