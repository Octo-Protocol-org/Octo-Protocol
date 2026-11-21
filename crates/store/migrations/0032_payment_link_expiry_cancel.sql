-- Issue #454: merchant-controlled payment link lifecycle.
--   expires_at   — optional deadline; past it the link is not payable and late deposits are not matched
--   cancelled_at — set once by the cancel route; a cancelled link can never be reactivated
-- Cancelling flips the link's pending intents to the new 'cancelled' payment status.
ALTER TABLE payment_links
    ADD COLUMN expires_at   TIMESTAMPTZ,
    ADD COLUMN cancelled_at TIMESTAMPTZ;

ALTER TABLE payment_link_payments DROP CONSTRAINT payment_link_payments_status_check;
ALTER TABLE payment_link_payments ADD CONSTRAINT payment_link_payments_status_check
    CHECK (status IN ('pending', 'confirmed', 'expired', 'underpaid', 'overpaid', 'cancelled'));

-- The expiry sweep looks up links whose deadline has passed.
CREATE INDEX idx_payment_links_expires_at
    ON payment_links(expires_at)
    WHERE expires_at IS NOT NULL AND cancelled_at IS NULL;
