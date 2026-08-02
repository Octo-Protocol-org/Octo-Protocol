-- Track when a wallet was last *looked at*, separately from when it last saw activity.
--
-- `updated_at` only advances when a record is actually processed, so it answers "when did this
-- wallet last receive money". Activity-based ingest backoff also needs "when did we last poll it"
-- to decide whether a dormant wallet is due again yet.

ALTER TABLE ingest_cursor
    ADD COLUMN last_polled_at TIMESTAMPTZ;

-- The supervisor's due-for-poll scan filters on this every tick.
CREATE INDEX idx_ingest_cursor_last_polled ON ingest_cursor(last_polled_at);
