# Trace export (OpenTelemetry)

`octo-server` always logs spans and events to stdout. Exporting spans to an OpenTelemetry
collector is **off by default, twice over**:

1. It is compiled in only with `cargo build -p octo-server --features otel`.
2. Even then, nothing is exported until `OTEL_EXPORTER_OTLP_ENDPOINT` is set.

The exporter (`bin/server/src/otlp.rs`) speaks OTLP/HTTP with JSON bodies to
`$OTEL_EXPORTER_OTLP_ENDPOINT/v1/traces`. It is written against crates already in the tree, so
the feature adds no new dependencies.

| Variable | Default | Meaning |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset (off) | Collector base URL, e.g. `http://otel-collector:4318`. Must be `http(s)`. |
| `OTEL_EXPORTER_OTLP_HEADERS` | unset | `key=value,key2=value2` sent with every export. Treated as a secret: zeroized, removed from the process environment at startup, marked sensitive, never logged. |
| `OTEL_SERVICE_NAME` | `octo-server` | `service.name` resource attribute. |
| `OTEL_TRACES_SAMPLE_RATIO` | `1.0` | Fraction of new traces kept (`0.0`–`1.0`), decided per trace id. |

## What is exported

- **Spans only**, and only those from `octo*` targets (the request span, Horizon client spans,
  ingest spans). Log events are never sent, so nothing a log line carries can reach the
  collector.
- Span **fields** become attributes. As a backstop to keeping secrets out of span fields in the
  first place, any field whose name contains `password`, `secret`, `token`, `key`, `auth`,
  `cookie`, `otp`, `code`, `seed`, `mnemonic`, `xdr`, `signature`, `email`, `backup` or `sealed`
  is dropped, values are capped at 256 characters, and a span keeps at most 32 attributes.
- Spans are queued (4096 max) and sent in batches every 5 s; when the queue is full or the
  collector is down, spans are dropped. Tracing never slows a request.

## Propagation to Horizon

Every Horizon call (API and ingest) carries a W3C `traceparent` header for its client span, so a
collector that also receives Horizon's spans can join them. Only the trace id, span id and
sampled flag are sent: no `tracestate`, no baggage, no attributes. Inbound `traceparent` headers
from API clients are ignored, so the public can't choose our trace ids.
