-- Bound wallet label/description length in the database too (the API enforces the same limits).
-- NOT VALID: enforced on every new write without failing on any legacy row that predates the limit.
ALTER TABLE wallets
    ADD CONSTRAINT wallets_label_length CHECK (label IS NULL OR char_length(label) <= 64) NOT VALID;
ALTER TABLE wallets
    ADD CONSTRAINT wallets_description_length
        CHECK (description IS NULL OR char_length(description) <= 500) NOT VALID;
