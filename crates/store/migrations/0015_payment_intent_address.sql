-- Per-intent deposit address, so a landing deposit maps to exactly one payment.
--
-- Previously ingest confirmed the oldest pending payment on the link's shared address, so two
-- concurrent payers could be cross-matched (B's money confirming A's intent).

ALTER TABLE payment_link_payments
    ADD COLUMN address_id UUID REFERENCES addresses(id) ON DELETE SET NULL;

-- Ingest's exact-match lookup: one pending intent per address.
CREATE INDEX idx_payment_link_payments_address
    ON payment_link_payments(address_id)
    WHERE status = 'pending';
