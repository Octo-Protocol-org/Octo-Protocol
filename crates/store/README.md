# octo-store

Postgres models + migrations (sqlx).

Tables: `wallets`, `addresses`, `transactions`, `withdrawals`, `webhook_endpoints`,
`webhook_deliveries`, `ingest_cursor`, `users`, `sessions`, `api_keys`, `audit_logs`,
`payment_links`, `payment_link_payments`, `gas_sponsorship_configs`, `sponsored_transactions`,
`withdrawal_allowlist_configs`, `whitelisted_addresses`, `email_otps`, `rate_limit_buckets`,
`idempotency_keys`.

See [docs/migrations.md](../../docs/migrations.md) for the append-only migration rules.