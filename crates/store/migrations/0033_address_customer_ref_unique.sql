-- customer_ref is unique per wallet and indexed for lookup-by-reference (#460).
-- Partial: addresses without a reference stay unconstrained. Fails loudly if legacy duplicates exist.
CREATE UNIQUE INDEX idx_addresses_wallet_customer_ref
    ON addresses (wallet_id, customer_ref)
    WHERE customer_ref IS NOT NULL;
