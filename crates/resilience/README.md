# resilience

Shared retry, circuit-breaking and timeout primitives for workspace services.

## What's inside

- **`RetryPolicy`** — bounded exponential backoff with jitter for transient failures.
- **`CircuitBreaker`** — trips after repeated failures and fails fast until the cooldown elapses.
- **`execute`** — runs an async operation through the configured retry and breaker policy.
- **`ResilienceConfig`** — loads tunables from the environment (see below).

## Configuration

`ResilienceConfig` reads the following environment variables:

| Variable | Purpose |
| --- | --- |
| `RESILIENCE_MAX_ATTEMPTS` | Maximum attempts per operation |
| `RESILIENCE_BASE_DELAY_MS` | Initial backoff delay in milliseconds |
| `RESILIENCE_MAX_DELAY_MS` | Upper bound for backoff delay |
| `RESILIENCE_BREAKER_THRESHOLD` | Consecutive failures before the breaker opens |
| `RESILIENCE_BREAKER_COOLDOWN_MS` | Time the breaker stays open before probing |

## Usage

```rust
let config = ResilienceConfig::from_env()?;
let result = execute(&config, || client.fetch()).await?;
```

## Security

See [`docs/threat-model.md`](../../docs/threat-model.md) for the threat model this crate is expected to uphold.
