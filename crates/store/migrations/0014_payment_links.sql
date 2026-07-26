-- Payment links: shareable public URLs that accept a USDC deposit to a dedicated address.

CREATE TABLE payment_links (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id           UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    address_id          UUID NOT NULL REFERENCES addresses(id) ON DELETE CASCADE,
    slug                TEXT NOT NULL UNIQUE,
    name                TEXT NOT NULL,
    description         TEXT,
    image_url           TEXT,
    amount_usdc_stroops BIGINT, -- NULL means flexible: the payer chooses the amount
    active              BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_payment_links_wallet ON payment_links(wallet_id);

CREATE TABLE payment_link_payments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payment_link_id     UUID NOT NULL REFERENCES payment_links(id) ON DELETE CASCADE,
    transaction_id      UUID REFERENCES transactions(id) ON DELETE SET NULL,
    payer_name          TEXT,
    payer_email         TEXT,
    amount_usdc_stroops BIGINT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_payment_link_payments_link ON payment_link_payments(payment_link_id);

-- Ingest matches a confirmed deposit to the oldest pending payment on the link's address.
CREATE INDEX idx_payment_link_payments_pending
    ON payment_link_payments(payment_link_id, created_at)
    WHERE status = 'pending';
