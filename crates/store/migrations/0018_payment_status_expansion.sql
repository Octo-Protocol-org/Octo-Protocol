-- Widen payment_link_payments.status beyond pending/confirmed:
--   expired    — pending past its deadline, swept by the ingest supervisor (see Supervisor::tick)
--   underpaid  — a deposit landed but for less than the intent's amount
--   overpaid   — a deposit landed but for more than the intent's amount
-- underpaid/overpaid still record the transaction (so the merchant/payer can see what actually
-- arrived) but are deliberately NOT 'confirmed' — the merchant decides how to handle the
-- mismatch (refund, top-up request, manual reconciliation), Octo doesn't silently treat it as
-- paid-in-full.
ALTER TABLE payment_link_payments DROP CONSTRAINT payment_link_payments_status_check;
ALTER TABLE payment_link_payments ADD CONSTRAINT payment_link_payments_status_check
    CHECK (status IN ('pending', 'confirmed', 'expired', 'underpaid', 'overpaid'));
