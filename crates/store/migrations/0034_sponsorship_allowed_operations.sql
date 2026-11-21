-- Per-wallet sponsorship operation allowlist (#462). NULL = inherit the global allowlist.
-- The API only accepts a subset of the global list, and validation intersects with it again.
ALTER TABLE gas_sponsorship_configs ADD COLUMN allowed_operations TEXT[];
