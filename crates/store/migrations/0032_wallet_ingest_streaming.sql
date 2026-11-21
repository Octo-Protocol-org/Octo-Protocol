-- Opt-in Horizon SSE ingest per wallet (issue #446); cursor polling remains the fallback.
ALTER TABLE wallets ADD COLUMN ingest_streaming BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX idx_wallets_ingest_streaming ON wallets (network, id) WHERE ingest_streaming;
