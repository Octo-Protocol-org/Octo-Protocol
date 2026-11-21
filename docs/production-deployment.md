# Production Deployment Guide

This guide describes how to deploy the application in a production environment. It covers TLS termination and reverse-proxy configuration, trusted proxy headers, environment variables and secrets, PostgreSQL setup with least-privilege roles, database migrations, and the caveats of running a single instance versus multiple instances.

> **Note:** This guide is intended to be reviewed against the actual environment variables defined in `.env.example` and the configuration code. If you add or rename a variable, update both this guide and `.env.example`.

## Table of Contents

- [Related Documentation](#related-documentation)
- [Architecture Overview](#architecture-overview)
- [TLS Termination and Reverse Proxy](#tls-termination-and-reverse-proxy)
- [Trusted Proxy Headers](#trusted-proxy-headers)
- [Environment Variables and Secrets](#environment-variables-and-secrets)
- [PostgreSQL Setup](#postgresql-setup)
- [Database Migrations](#database-migrations)
- [Single- vs Multi-Instance Deployment](#single--vs-multi-instance-deployment)
- [Health Checks and Observability](#health-checks-and-observability)
- [Deployment Checklist](#deployment-checklist)

## Related Documentation

- [Database Migrations](./migrations.md) — migration tooling, ordering, and rollback guidance.
- [High-Availability Topology](./ha-topology.md) — running multiple instances behind a load balancer.
- [PostgreSQL Roles](./postgres-roles.md) — detailed role and privilege model.

## Architecture Overview

A typical production deployment looks like this:

```
        ┌──────────────┐
Client ─▶│  TLS terminator │  (load balancer / reverse proxy)
        │  (nginx, etc.)  │
        └──────┬───────┘
               │ HTTP (private network)
        ┌──────▼───────┐
        │  App instance │  (one or more)
        └──────┬───────┘
               │
        ┌──────▼───────┐
        │  PostgreSQL   │
        └──────────────┘
```

TLS is terminated at the edge (load balancer or reverse proxy). The application itself speaks plain HTTP on a private interface and relies on trusted proxy headers to learn the original client scheme and address.

## TLS Termination and Reverse Proxy

Terminate TLS at your load balancer or reverse proxy and forward plain HTTP to the application over a private network. Do **not** expose the application port directly to the public internet.

### Reverse Proxy Requirements

Your reverse proxy must:

1. **Terminate TLS** with a valid certificate for your public hostname.
2. **Forward the original scheme** via `X-Forwarded-Proto` (or `Forwarded`).
3. **Forward the original client address** via `X-Forwarded-For` (or `Forwarded`).
4. **Forward the original host** via `X-Forwarded-Host` / `Host`.
5. **Set a request ID** header if your proxy supports it (optional but recommended for tracing).
6. **Pass through** the `Authorization` and `Content-Type` headers unchanged.
7. **Not buffer** streaming or long-lived responses if you use them.

### Example: nginx

```nginx
upstream app_backend {
    server 10.0.0.10:8080;
    # Add more servers for multi-instance deployments.
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name app.example.com;

    ssl_certificate     /etc/ssl/certs/app.example.com.crt;
    ssl_certificate_key /etc/ssl/private/app.example.com.key;

    # Modern TLS only.
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    # Security headers.
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://app_backend;
        proxy_http_version 1.1;

        # Preserve the original request information.
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;

        # Timeouts — tune to your workload.
        proxy_connect_timeout 5s;
        proxy_read_timeout    60s;
        proxy_send_timeout    60s;
    }
}

# Redirect HTTP to HTTPS.
server {
    listen 80;
    server_name app.example.com;
    return 301 https://$host$request_uri;
}
```

### Example: Caddy

```caddy
app.example.com {
    reverse_proxy 10.0.0.10:8080 {
        header_up X-Forwarded-Proto {scheme}
        header_up X-Forwarded-Host  {host}
    }
}
```

Caddy sets `X-Forwarded-For` and `X-Forwarded-Proto` automatically; the explicit `header_up` lines above make the behavior obvious.

### Example: AWS ALB

- Create an HTTPS listener on port 443 with your ACM certificate.
- Forward to a target group pointing at the application port.
- Enable `X-Forwarded-For` and `X-Forwarded-Proto` (ALB adds these by default).
- Ensure the target group health check points at your health endpoint.

## Trusted Proxy Headers

The application only honors `X-Forwarded-*` headers from proxies it trusts. This prevents clients from spoofing their source address or scheme by sending forged headers directly.

Trusted proxies are configured with the `TRUSTED_PROXY_CIDRS` environment variable, a comma-separated list of CIDR ranges:

```bash
# Trust a single proxy host.
TRUSTED_PROXY_CIDRS=10.0.0.10/32

# Trust a private subnet (e.g., a load balancer fleet).
TRUSTED_PROXY_CIDRS=10.0.0.0/24,192.168.1.0/24
```

Guidelines:

- **Set this to the exact addresses** of your load balancer or reverse proxy. Do not use `0.0.0.0/0` — that would trust every client and defeat the purpose.
- If the application is reached directly (no proxy), leave `TRUSTED_PROXY_CIDRS` empty so forwarded headers are ignored.
- When running multiple instances behind a load balancer, every instance must trust the load balancer's CIDR range.
- If your proxy adds multiple hops, list every hop's CIDR range.

When a request arrives from a trusted proxy, the application uses `X-Forwarded-Proto` to determine the request scheme and `X-Forwarded-For` to determine the client address. Requests from untrusted sources have these headers ignored.

## Environment Variables and Secrets

Configuration is provided via environment variables. The canonical list lives in `.env.example`; the table below summarizes the variables relevant to production. Always cross-check against `.env.example` before deploying — it is the source of truth.

### Core

| Variable | Required | Description |
| --- | --- | --- |
| `APP_ENV` | Yes | Set to `production`. |
| `APP_HOST` | No | Bind address. Defaults to `0.0.0.0`. |
| `APP_PORT` | No | Listen port. Defaults to `8080`. |
| `LOG_LEVEL` | No | Log verbosity (`info` in production). |

### Database

| Variable | Required | Description |
| --- | --- | --- |
| `DATABASE_URL` | Yes | PostgreSQL connection string, e.g. `postgres://app_user:secret@db.internal:5432/appdb?sslmode=require`. |
| `DATABASE_MAX_CONNECTIONS` | No | Maximum connections per instance. See [connection budget](#connection-budget). |
| `DATABASE_MIN_CONNECTIONS` | No | Minimum idle connections per instance. |
| `DATABASE_CONNECT_TIMEOUT` | No | Connection timeout in seconds. |

### Migrations

| Variable | Required | Description |
| --- | --- | --- |
| `RUN_MIGRATIONS` | No | When `true`, the application runs pending migrations on startup. Defaults to `false` in production. See [Database Migrations](#database-migrations). |

### Proxy and Networking

| Variable | Required | Description |
| --- | --- | --- |
| `TRUSTED_PROXY_CIDRS` | No | Comma-separated CIDR ranges of trusted proxies. See [Trusted Proxy Headers](#trusted-proxy-headers). |

### Secrets

| Variable | Required | Description |
| --- | --- | --- |
| `SECRET_KEY` | Yes | Signing/encryption key. Generate with `openssl rand -hex 32`. Rotate carefully. |

> **Note:** The table above reflects the variables documented in `.env.example`. If your deployment uses additional variables (e.g., for rate limiting or the ingest leader lock), confirm their names and defaults against `.env.example` and the configuration code before relying on them.

### Handling Secrets

- **Never commit secrets** to version control. Keep `.env` files out of the repository.
- Use your platform's secret manager (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault, Kubernetes Secrets, etc.) to inject secrets at runtime.
- Restrict read access to secrets to the application's service account only.
- Rotate `SECRET_KEY` and database credentials on a regular schedule. Plan for a rotation procedure that does not invalidate active sessions abruptly.
- Prefer `sslmode=require` (or `verify-full` with a CA) in `DATABASE_URL` for connections that cross untrusted networks.

## PostgreSQL Setup

Use a dedicated PostgreSQL instance (or managed service) for production. See [PostgreSQL Roles](./postgres-roles.md) for the full role model.

### Least-Privilege Roles

Create separate roles for migrations and runtime:

```sql
-- Database and schema owner (used only for migrations).
CREATE ROLE app_owner LOGIN PASSWORD '...';
CREATE DATABASE appdb OWNER app_owner;

-- Runtime role with limited privileges.
CREATE ROLE app_user LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE appdb TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;

-- Ensure future tables are also accessible to the runtime role.
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO app_user;
```

- The **runtime role** (`app_user`) should not own tables and should not have `CREATE` privileges on the schema.
- The **migration role** (`app_owner`) owns the schema and is used only during migrations.
- Do not use the PostgreSQL superuser for the application.

### Connection Budget

Each application instance opens up to `DATABASE_MAX_CONNECTIONS` connections. PostgreSQL's `max_connections` is a hard limit shared across all instances and clients.

```
total_connections = instances × DATABASE_MAX_CONNECTIONS + admin/reserved
```

Keep `total_connections` comfortably below PostgreSQL's `max_connections`, leaving headroom for administrative connections and failover. If you need more instances than the connection budget allows, put a connection pooler (e.g., PgBouncer) in front of PostgreSQL.

### Backups and Maintenance

- Enable automated backups with point-in-time recovery.
- Schedule `VACUUM`/`ANALYZE` (autovacuum is enabled by default; verify it is not disabled).
- Monitor replication lag if you run replicas.

## Database Migrations

Migrations are managed by the migration tooling described in [Database Migrations](./migrations.md).

### Recommended Procedure

Run migrations as a **separate step** before rolling out new application instances, using the migration role:

1. **Back up** the database (or confirm a recent backup exists).
2. **Run migrations** with the migration-only flag:

   ```bash
   DATABASE_URL="postgres://app_owner:...@db.internal:5432/appdb?sslmode=require" \
     ./app --migrate-only
   ```

   The `--migrate-only` flag applies pending migrations and exits without starting the server. This is the safest way to run migrations in production because it decouples schema changes from application startup.

3. **Verify** the migration completed successfully (check exit code and logs).
4. **Deploy** the new application instances.

### Disabling Startup Migrations

By default, production deployments should **not** run migrations on application startup. Set:

```bash
RUN_MIGRATIONS=false
```

This ensures that:

- Multiple instances starting simultaneously do not race to apply migrations.
- Schema changes are applied deliberately, in a controlled step, rather than as a side effect of a restart.
- A failed migration does not prevent the application from starting (and failing loudly) in an unexpected way.

If you run a single instance and prefer startup migrations, you may set `RUN_MIGRATIONS=true`, but the explicit `--migrate-only` step is still recommended for auditability.

### Migration Safety

- Migrations should be **backward compatible** with the currently running version so that rolling deployments do not break in-flight requests. Use expand/contract patterns for breaking schema changes.
- Test migrations against a production-like dataset before applying them.
- Never edit an already-applied migration; add a new one instead.

## Single- vs Multi-Instance Deployment

The application can run as a single instance or as multiple instances behind a load balancer. The choice affects several subsystems.

### Ingest Leader Lock

Ingest processing uses a **leader lock** so that only one instance performs ingest work at a time. This prevents duplicate processing when multiple instances are running.

- In a **single-instance** deployment, the sole instance holds the lock.
- In a **multi-instance** deployment, one instance is elected leader; the others stand by and take over if the leader fails.
- The lock requires a shared backend (PostgreSQL). Ensure all instances connect to the same database.
- Do not disable the leader lock when running multiple instances — doing so can cause duplicate ingest.

### Rate-Limit Backend

Rate limiting must use a **shared backend** when running multiple instances. An in-memory rate limiter on each instance would allow clients to exceed the intended limit by spreading requests across instances.

- In a **single-instance** deployment, an in-memory limiter is acceptable.
- In a **multi-instance** deployment, configure a shared rate-limit backend (e.g., PostgreSQL or Redis, depending on what your build supports) so limits are enforced globally.
- Confirm the rate-limit backend configuration against `.env.example` and the configuration code for your version.

### Connection Budget

As described in [Connection Budget](#connection-budget), each instance consumes database connections. Multi-instance deployments multiply this consumption:

```
instances × DATABASE_MAX_CONNECTIONS ≤ max_connections − reserved
```

Size `DATABASE_MAX_CONNECTIONS` accordingly, or introduce a connection pooler.

### Other Multi-Instance Considerations

- **Sticky sessions:** If your application uses server-side sessions, either use a shared session store or enable sticky sessions at the load balancer.
- **Scheduled jobs:** Any periodic jobs should be guarded by a lock (like the ingest leader lock) so they run on only one instance.
- **Local caches:** In-memory caches are per-instance; ensure correctness does not depend on a globally consistent cache.
- **Logging:** Aggregate logs from all instances into a central system for troubleshooting.

See [High-Availability Topology](./ha-topology.md) for a detailed multi-instance reference architecture.

## Health Checks and Observability

- Configure your load balancer's health check to hit the application's health endpoint. Ensure the check reflects database connectivity if the application depends on it.
- Emit structured logs to stdout/stderr and ship them to your log aggregator.
- Export metrics (if supported) to your monitoring system and alert on error rates, latency, and database connection saturation.
- Set up alerts for migration failures and leader-lock contention.

## Deployment Checklist

Before going live, confirm:

- [ ] TLS is terminated at the edge with a valid certificate.
- [ ] The reverse proxy forwards `X-Forwarded-Proto`, `X-Forwarded-For`, and `X-Forwarded-Host`.
- [ ] `TRUSTED_PROXY_CIDRS` is set to the exact proxy CIDR ranges (not `0.0.0.0/0`).
- [ ] `APP_ENV=production` and `LOG_LEVEL` is appropriate.
- [ ] `DATABASE_URL` uses a least-privilege runtime role and `sslmode=require` (or stronger).
- [ ] `SECRET_KEY` is generated securely and stored in a secret manager.
- [ ] `RUN_MIGRATIONS=false` and migrations are applied via `--migrate-only` before rollout.
- [ ] Database roles follow the least-privilege model in [postgres-roles.md](./postgres-roles.md).
- [ ] Connection budget accounts for the number of instances.
- [ ] Multi-instance deployments use a shared rate-limit backend and rely on the ingest leader lock.
- [ ] Health checks, logging, and monitoring are configured.
- [ ] Backups and point-in-time recovery are enabled and tested.
- [ ] All variables are cross-checked against `.env.example`.