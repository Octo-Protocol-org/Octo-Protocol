-- no-transaction
-- Multi-chain schema, phase 3c: backfill `transactions.chain_id` and `transactions.tx_hash`.
--
-- Same batched, resumable, single-statement pattern as 0024_backfill_addresses_chain_id.sql —
-- see that file's header for the full rationale (including why batch boundaries are tracked via
-- `array_agg` instead of `max(id)`). `transactions` is the table explicitly called out in #214 as
-- needing a production-scale-safe backfill (append-only ledger, unbounded growth), so this is the
-- one most worth batching correctly.
DO $$
DECLARE
    batch_size CONSTANT INT := 5000;
    last_id UUID := '00000000-0000-0000-0000-000000000000';
    batch_ids UUID[];
    rows_in_batch INT;
BEGIN
    LOOP
        SELECT array_agg(id ORDER BY id) INTO batch_ids
        FROM (
            SELECT id FROM transactions
            WHERE id > last_id AND chain_id IS NULL
            ORDER BY id
            LIMIT batch_size
        ) s;

        rows_in_batch := coalesce(array_length(batch_ids, 1), 0);
        EXIT WHEN rows_in_batch = 0;

        UPDATE transactions t
        SET chain_id = w.chain_id,
            tx_hash = t.stellar_tx_hash
        FROM wallets w
        WHERE t.id = ANY(batch_ids) AND t.wallet_id = w.id;

        last_id := batch_ids[array_upper(batch_ids, 1)];
        COMMIT;
    END LOOP;
END $$;
