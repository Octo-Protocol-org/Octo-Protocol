# Environment Variables

This document is the authoritative reference for every environment variable read by the server. It is derived directly from the parsing code across the codebase: `bin/server/src/main.rs`, `crates/store/src/config.rs`, and every non-test source file under `crates/*/src/**/*.rs`. If you add or change a variable in code, update this table — CI enforces that every variable read by the server is documented here (see [Keeping this document in sync](#keeping-this-document-in-sync)).

## Reference table

| Variable | Purpose | Default | Required | Secret |
| --- | --- | --- | --- | --- |
| `NETWORK` | Selects the Stellar network the server targets (`testnet` or `mainnet`). Controls which network passphrase and default endpoints are used, and enables the mainnet startup guard. | `testnet` | always | no |
| `HORIZON_URL` | Base URL of the Horizon API used to read ledger and account data. | `https://horizon-testnet.stellar.org` (testnet) / `https://horizon.stellar.org` (mainnet) | always | no |
| `HORIZON_MAX_ATTEMPTS` | Maximum number of attempts (including the first) for read-only Horizon calls before the request fails. | `3` | optional | no |
| `HORIZON_BASE_DELAY_MS` | Base delay in milliseconds for exponential backoff between Horizon retry attempts. | `200` | optional | no |
| `HORIZON_MAX_DELAY_MS` | Upper bound in milliseconds on the backoff delay between Horizon retry attempts. | `5000` | optional | no |
| `HORIZON_CB_FAILURE_THRESHOLD` | Number of consecutive Horizon failures before the circuit breaker opens. | `5` | optional | no |
| `HORIZON_CB_RESET_TIMEOUT_SECS` | Seconds the circuit breaker stays open before allowing a probe request. | `30` | optional | no |
| `FRIENDBOT_URL` | Base URL of the Friendbot service used to fund accounts in non-production environments. | `https://friendbot.stellar.org` | optional | no |
| `DATABASE_URL` | PostgreSQL connection string (host, port, database, user, password). | none | always | yes |
| `RUN_MIGRATIONS` | Whether the server runs database migrations on startup. See [postgres-roles.md](postgres-roles.md) for the roles required to run migrations. | `false` | optional | no |
| `DB_MAX_CONNECTIONS` | Maximum number of connections in the database pool. See [ha-topology.md](ha-topology.md) for sizing guidance. | `10` | optional | no |
| `DB_ACQUIRE_TIMEOUT_SECS` | Seconds to wait for a pooled database connection before failing. See [ha-topology.md](ha-topology.md). | `30` | optional | no |
| `DB_IDLE_TIMEOUT_SECS` | Seconds after which an idle pooled connection is closed. See [ha-topology.md](ha-topology.md). | `600` | optional | no |
| `DB_STATEMENT_TIMEOUT_SECS` | Per-statement timeout in seconds applied to database queries. See [ha-topology.md](ha-topology.md). | `30` | optional | no |
| `RATE_LIMIT_BACKEND` | Selects the rate-limiting backend (`memory` or `postgres`). See [ha-topology.md](ha-topology.md) for multi-instance deployments. | `memory` | optional | no |
| `MASTER_KEY` | Primary key material used to encrypt sensitive data at rest. Must be high-entropy; rejected on mainnet if it looks like a placeholder. | none | always | yes |
| `MASTER_KEY_NEXT` | Next master key, set during key rotation so data can be re-encrypted before switching `MASTER_KEY`. | none | optional | yes |
| `AUDIT_CHAIN_KEY` | Key used to compute the tamper-evident audit log hash chain. | none | always | yes |
| `JWT_SECRET` | Secret used to sign and verify JWTs. Must be at least 32 bytes on mainnet. | none | always | yes |
| `JWT_SECRET_PREVIOUS` | Previous JWT signing secret, accepted during rotation so existing tokens remain valid. | none | optional | yes |
| `JWT_ISSUER` | `iss` claim value written into and validated on JWTs. | `stellar-...` (server default) | optional | no |
| `JWT_AUDIENCE` | `aud` claim value written into and validated on JWTs. | `stellar-...` (server default) | optional | no |
| `ARGON2_MEMORY_KIB` | Argon2id memory cost in KiB used for password hashing. Must be a valid integer when set; malformed values abort startup. | `19456` | optional | no |
| `ARGON2_ITERATIONS` | Argon2id iteration (time) cost used for password hashing. Must be a valid integer when set; malformed values abort startup. | `2` | optional | no |
| `ARGON2_PARALLELISM` | Argon2id parallelism (lanes) used for password hashing. Must be a valid integer when set; malformed values abort startup. | `1` | optional | no |
| `BIND_ADDR` | Address and port the HTTP server listens on. | `0.0.0.0:8080` | optional | no |
| `RUST_LOG` | `tracing`/`env_logger` filter directive controlling log verbosity. | `info` | optional | no |
| `PUBLIC_APP_URL` | Public base URL of the web application, used to build links in emails and redirects. | none | optional | no |
| `PUBLIC_API_URL` | Public base URL of the API, used when constructing absolute URLs. | none | optional | no |
| `RESEND_API_KEY` | API key for the Resend email provider. | none | optional | yes |
| `EMAIL_FROM_ADDRESS` | From address used for outgoing email. | none | optional | no |
| `INGEST_INTERVAL_SECS` | Seconds between ingestion polling cycles. Must be an integer `>= 1`; malformed or out-of-range values abort startup. | `5` | optional | no |
| `INGEST_PAGE_LIMIT` | Maximum number of records fetched per ingestion page. Must be an integer in `1..=200`; malformed or out-of-range values abort startup. | `200` | optional | no |
| `INGEST_LOCK_RETRY_SECS` | Seconds to wait before retrying acquisition of the ingestion advisory lock. See [ha-topology.md](ha-topology.md). | `10` | optional | no |
| `SHUTDOWN_DRAIN_TIMEOUT_SECS` | Seconds to allow in-flight requests to drain during graceful shutdown. Must be an integer `>= 1`; malformed or out-of-range values abort startup. | `30` | optional | no |
| `ALLOWED_ORIGINS` | Comma-separated list of origins permitted by CORS. | none (CORS disabled) | optional | no |
| `TRUSTED_PROXY_CIDRS` | Comma-separated list of CIDR ranges of trusted reverse proxies, used to resolve client IPs from forwarding headers. | none | optional | no |
| `HORIZON_TIMEOUT_SECS` | Timeout in seconds for requests to the Horizon API. | `30` | optional | no |
| `HORIZON_MAX_RETRIES` | Maximum number of retry attempts for failed Horizon API requests. | `3` | optional | no |
| `CLOUDINARY_CLOUD_NAME` | Cloudinary cloud name used for image uploads and delivery. | none | optional | no |
| `CLOUDINARY_API_KEY` | Cloudinary API key used to authenticate upload requests. | none | optional | yes |
| `CLOUDINARY_API_SECRET` | Cloudinary API secret used to sign upload requests. | none | optional | yes |
| `OCTO_API_KEY` | API key for the Octo SMS provider. | none | optional | yes |
| `OCTO_SENDER_ID` | Sender ID (originator) used for outgoing SMS via Octo. | none | optional | no |

### Required column values

- **always** — the server refuses to start without a valid value.
- **mainnet** — required only when `NETWORK=mainnet`; the mainnet startup guard enforces it.
- **optional** — has a default or is only needed for the corresponding feature (e.g. email, CORS).

### Argon2 tuning variables

`ARGON2_MEMORY_KIB`, `ARGON2_ITERATIONS` and `ARGON2_PARALLELISM` are parsed once at startup. When a variable is unset the documented default applies; when it is set it must be a valid integer, otherwise the server refuses to start with an error naming the offending variable. The parsed values are shared by password hashing and the password-hash upgrade check, so a misconfiguration can never be silently replaced by a default.

### Horizon tuning variables

`HORIZON_MAX_ATTEMPTS`, `HORIZON_BASE_DELAY_MS` and `HORIZON_MAX_DELAY_MS` are parsed once at startup. When a variable is unset the documented default applies; when it is set it must be a valid integer within the accepted range, otherwise the server refuses to start with an error naming the offending variable. `HORIZON_MAX_ATTEMPTS` must be at least `1`, both delays must be non-zero, and `HORIZON_BASE_DELAY_MS` must not exceed `HORIZON_MAX_DELAY_MS`. A misconfiguration is never silently replaced by a default.

### Secret column values

Variables marked **yes** carry credentials or key material. Never commit them, log them, or expose them in error messages. Supply them via your secret manager or environment injection.

## Webhooks

| Variable | Values | Scope |
|---|---|---|
| `OCTO_ALLOW_LOCAL_WEBHOOKS` | `1` | Development and tests only. Allows webhook delivery to localhost and other otherwise-blocked local targets. |

Do not set `OCTO_ALLOW_LOCAL_WEBHOOKS=1` on mainnet. Server startup rejects this configuration when `NETWORK` is `mainnet` or `public`.

## Mainnet startup guard

When `NETWORK=mainnet`, the server runs additional validation at startup and refuses to boot if any check fails:

- **HTTPS URLs** — `HORIZON_URL` (and other configured public URLs) must use `https://`.
- **JWT secret length** — `JWT_SECRET` must be at least 32 bytes.
- **High-entropy master key** — `MASTER_KEY` must be high-entropy and must not be a known placeholder or example value.
- **No placeholders** — any secret still set to a documented example/placeholder value causes startup to abort.

These checks exist to prevent accidentally running production with development defaults. Fix the offending variable rather than disabling the guard.

## Related documentation

- [postgres-roles.md](postgres-roles.md) — database roles and privileges, including what is needed for `RUN_MIGRATIONS`.
- [ha-topology.md](ha-topology.md) — multi-instance deployment guidance covering `DB_MAX_CONNECTIONS`, `DB_ACQUIRE_TIMEOUT_SECS`, `DB_IDLE_TIMEOUT_SECS`, `DB_STATEMENT_TIMEOUT_SECS`, `RATE_LIMIT_BACKEND`, and `INGEST_LOCK_RETRY_SECS`.

## Keeping this document in sync

Every environment variable read by the server must appear in the table above. A CI check (`scripts/check-env-docs.sh`, run via `just check-env-docs`) scans `bin/server/src/main.rs`, `crates/store/src/config.rs`, and every non-test source file under `crates/*/src/**/*.rs` for `env::var("NAME")` reads, then compares those names against the variables documented here and against `.env.example`. The build fails when a variable is read in code but undocumented, documented but no longer read, or documented but missing from `.env.example`. Test-only variables are exempted via a small allowlist in the script. When adding a variable, add its row here and to `.env.example` in the same change.
