# email

Email transport and one-time-password (OTP) generation for the workspace.

## Overview

This crate provides the `EmailTransport` trait and a set of implementations so
callers can send transactional email without depending on a specific provider.

### Transports

- **Resend** — sends real email through the Resend API.
- **Capture** — records messages in memory for tests and local development.
- **Log-only** — writes messages to the log without delivering them.
- **Failing** — always returns an error, for exercising failure paths.

### OTP

One-time passwords are generated with a cryptographically secure random source
and stored only as a hash; the plaintext code is never persisted or logged.

## Security

See [`docs/threat-model.md`](../../docs/threat-model.md) for the threat model
this crate follows. Never commit secrets, tokens or personal data.

## Testing

```
just fmt-check
just lint
just test
```
