# 0003. Polling-based ingest with durable cursor

## Status

Accepted

## Context

The ingest service needs to pull payment records from Horizon and feed them into
the rest of the pipeline. Horizon offers two broad integration styles:

- **Streaming** via Server-Sent Events (`/payments` with `cursor=now`), which
  pushes new records as they are created.
- **Polling** via the paginated `/payments` endpoint, where the client asks for
  records after a known cursor and advances that cursor as it consumes pages.

Streaming is attractive for latency, but it couples the ingest process to a
long-lived HTTP connection. Any network blip, deploy, or Horizon restart drops
the stream, and the client must reconnect and reconcile what it may have missed.
It also makes backfill and replay awkward: there is no natural "start from
here" primitive beyond the cursor, and the connection lifecycle becomes part of
the service's failure model.

Polling, by contrast, is stateless per request. The only state the service must
own is the cursor — the last payment ID it has successfully processed. As long
as that cursor is durable, the service can crash, restart, or be scaled without
losing its place. Backfill is just "start from an older cursor." Rate limiting
and backoff are straightforward to apply per request.

The trade-off is latency (bounded by the poll interval) and the need to handle
duplicates, since a poll may overlap with records already seen. See
`docs/ingest-integration.md` for the endpoint contract and pagination details.

## Decision

We will poll Horizon's `/payments` endpoint rather than stream.

- **Durable cursor.** The last successfully processed payment ID (the paging
  token) is persisted before the batch is acknowledged. On startup the service
  resumes from the stored cursor; if none exists it starts from a configured
  genesis cursor.
- **Two-layer dedup.** Because a poll window can overlap with already-processed
  records (e.g. a crash after processing but before cursor persistence, or
  concurrent workers), we deduplicate in two layers:
  1. An in-process/seen-set keyed by payment ID to drop duplicates within a
     batch and across recent pages.
  2. A durable uniqueness constraint on payment ID at the storage layer, so
     re-delivery after a restart is idempotent.
- **Bounded pages and backoff.** Each poll fetches a bounded page, advances the
  cursor only after the page is fully processed, and applies exponential backoff
  on errors.

## Consequences

- The service is resilient to restarts and deploys: state lives in the cursor,
  not in a connection.
- Backfill and replay are first-class: point the cursor at an older ID and let
  the poller catch up.
- Latency is bounded by the poll interval rather than being push-based. This is
  acceptable for our use case; the interval is configurable.
- We accept some duplicate delivery and pay for it with the two-layer dedup
  described above. Correctness depends on the storage-layer uniqueness
  constraint, not on the in-process set alone.
- **Known limitation: reorgs.** Polling `/payments` gives us a linear view of
  ledger history, but Stellar can reorg (a ledger can be rolled back and
  re-applied). A cursor that has advanced past a payment that is later rolled
  back will not automatically re-fetch the corrected history. We do not attempt
  to detect or reconcile reorgs here; downstream consumers that require
  finalized history must reconcile against ledger close / checkpoint data. This
  limitation is documented in `docs/ingest-integration.md` and is a candidate
  for a follow-up decision.