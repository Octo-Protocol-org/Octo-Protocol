# horizon-mock

Offline Horizon mock used by the test suite and local development.

## What it serves

A minimal in-process stand-in for Stellar Horizon. It answers the subset of
endpoints octo relies on (accounts, transactions, payments/operations, fee-bump
submission) from static fixtures, so tests and local runs never touch the
network.

## Running it

```sh
# Bind address for the mock server (default: 127.0.0.1:8000)
export HORIZON_MOCK_ADDR=127.0.0.1:8000

# Directory of JSON fixtures the mock serves (default: ./fixtures)
export HORIZON_MOCK_FIXTURES=./fixtures

cargo run -p horizon-mock
```

- `HORIZON_MOCK_ADDR` — `host:port` the mock listens on.
- `HORIZON_MOCK_FIXTURES` — path to the fixture directory; each file maps to a
  canned Horizon response.

## Security

Fixtures must contain only public test vectors — no secrets, tokens or personal
data. See [docs/threat-model.md](../../docs/threat-model.md).
