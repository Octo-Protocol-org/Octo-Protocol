-- no-transaction
-- Multi-chain schema, phase 3b: backfill `addresses.chain_id` and `addresses.deposit_address`.
--
-- `addresses` is per-customer and can be large in production, so — unlike the wallets backfill —
-- this runs in small committed batches instead of one long UPDATE. Each batch commits
-- independently (this file is `-- no-transaction`, so it is not wrapped in sqlx's usual
-- per-migration transaction, which is what allows a bare COMMIT inside the DO block below): no
-- single transaction holds row locks or accumulates WAL for the whole table, and the loop is
-- resumable — if the process is interrupted, restarting `store.migrate()` just continues from the
-- first still-NULL row instead of redoing already-migrated batches.
--
-- Must be the only statement in this file: bundling more statements alongside it would make
-- Postgres wrap them all in one implicit transaction, and COMMIT is not allowed inside a DO block
-- that isn't already the sole, top-level statement of its transaction.
--
-- Batch boundaries are tracked as a UUID array rather than `max(id)`: Postgres has no built-in
-- MAX/MIN aggregate for uuid (it's comparable via operators for ORDER BY/WHERE, just not
-- aggregatable), so the last id in each ordered batch is read off the end of an explicitly
-- ordered `array_agg` instead.
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
            SELECT id FROM addresses
            WHERE id > last_id AND chain_id IS NULL
            ORDER BY id
            LIMIT batch_size
        ) s;

        rows_in_batch := coalesce(array_length(batch_ids, 1), 0);
        EXIT WHEN rows_in_batch = 0;

        UPDATE addresses a
        SET chain_id = w.chain_id,
            deposit_address = a.muxed_address
        FROM wallets w
        WHERE a.id = ANY(batch_ids) AND a.wallet_id = w.id;

        last_id := batch_ids[array_upper(batch_ids, 1)];
        COMMIT;
    END LOOP;
END $$;
