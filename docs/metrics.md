# Metrics

`octo-server` can expose Prometheus metrics at `GET /metrics` (text format 0.0.4). The registry
lives in `crates/metrics` and has no third-party dependencies.

## Enabling it

| Variable | Default | Meaning |
|---|---|---|
| `METRICS_BIND_ADDR` | unset (disabled) | `ip:port` for a **separate** listener. `/metrics` is never served on `BIND_ADDR`. |
| `METRICS_TOKEN` | unset | Bearer token scrapers must send. **Required** (≥ 32 bytes) unless the bind address is loopback; the server refuses to start otherwise. |

So by default nothing is exposed, and a misconfigured public bind fails at startup instead of
leaking. Prometheus scrape config with a token:

```yaml
scrape_configs:
  - job_name: octo
    authorization: { credentials_file: /etc/prometheus/octo-metrics-token }
    static_configs: [{ targets: ["octo:9898"] }]
```

## Series

| Metric | Type | Labels |
|---|---|---|
| `octo_http_request_duration_seconds` | histogram | `method`, `route` (matched template, e.g. `/v1/wallets/:id`, or `unmatched`), `status_class` (`2xx`…) |
| `octo_circuit_breaker_state` | gauge | `breaker` (`horizon_api`, `horizon_ingest`); 0 closed, 1 half-open, 2 open |
| `octo_webhook_deliveries_total` | counter | `kind` (`event`, `ping`), `outcome` (`delivered`, `failed`, `dead`) |
| `octo_ingest_tick_duration_seconds` | histogram | `outcome` (`ok`, `error`) |
| `octo_ingest_last_success_timestamp_seconds` | gauge | — |
| `octo_ingest_leader` | gauge | — (1 while this replica holds the ingest lock) |
| `octo_ingest_deposits_total` | counter | `attributed` (`true`, `false`) |

Useful expressions: error ratio
`sum(rate(octo_http_request_duration_seconds_count{status_class="5xx"}[5m])) / sum(rate(octo_http_request_duration_seconds_count[5m]))`;
ingest lag `time() - max(octo_ingest_last_success_timestamp_seconds)`.

## Cardinality

Labels are never raw paths, ids, emails or other client-controlled values: routes use the
template axum matched, methods outside the standard set read `other`, and statuses are bucketed
by class. As a backstop, each metric holds at most 500 label combinations; further ones collapse
into a single series labelled `overflow`.
