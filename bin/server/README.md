# octo-server

The deployable binary. Composes `octo-api` + `octo-ingest` into one process (splittable
later to scale ingest independently). Wired in Step 11.

Safe to run as several replicas on one database: API rate limits are shared through Postgres,
and an advisory lock makes exactly one replica per network run ingest. See
[`docs/ha-topology.md`](../../docs/ha-topology.md) for the topology, failover behaviour, and the
`DB_*`, `RATE_LIMIT_BACKEND` and `INGEST_LOCK_RETRY_SECS` settings.

## Commands

| Invocation | What it does |
|---|---|
| `octo-server` | Serve the API and run ingest. |
| `octo-server --check-config` | Load the full config as `serve` would, connect to the database, count pending migrations, print a redacted summary and exit `0` if every check passes, `1` otherwise. Secrets show only as `set`/`unset`; URLs lose credentials and query strings. Run it in CI or as a deploy pre-flight. |
| `octo-server --migrate-only` | Apply migrations (needs only `DATABASE_URL`) and exit. |
| `octo-server verify-audit-chain [--user <uuid>]` | Verify the audit hash chain; non-zero on any break. |

Optional observability: Prometheus metrics on a separate listener
([`docs/metrics.md`](../../docs/metrics.md)) and OTLP trace export behind `--features otel`
([`docs/tracing.md`](../../docs/tracing.md)).
