# metrics

Bounded-cardinality Prometheus metrics for the workspace.

This crate exposes counters, gauges and histograms that are safe to use in
hot paths: every metric is registered against a fixed label set and the
number of distinct series is capped by `MAX_SERIES`. Once the cap is
reached, new label combinations are dropped instead of growing memory
without bound, so a misbehaving caller cannot exhaust the process.

## What is here

- **Counters** — monotonically increasing values (requests, errors).
- **Gauges** — values that go up and down (queue depth, in-flight work).
- **Histograms** — bucketed observations (latency, payload size).

All three share the same bounded-cardinality registry and honour
`MAX_SERIES`.

## Usage

```rust
use metrics::{counter, gauge, histogram};

counter("requests_total", &[("route", "/health")]).inc();
gauge("queue_depth", &[]).set(3.0);
histogram("request_seconds", &[]).observe(0.042);
```

## Security

No secrets, tokens or personal data belong in metric names or labels.
See [`docs/threat-model.md`](../../docs/threat-model.md) for the rules
this crate follows.
