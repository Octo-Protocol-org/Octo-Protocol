//! `octo-server --check-config` (issue #469): load the full configuration exactly as `serve` would,
//! connect to the database, print a redacted summary and exit — 0 when every check passes, 1
//! otherwise. Nothing is served and nothing is written (migrations are only counted).
//!
//! Secrets are reported only as `set` / `unset`. URLs are shown without credentials, query string
//! or fragment, since providers often embed keys there.

use crate::telemetry::TelemetryConfig;
use crate::Config;
use anyhow::Result;
use octo_store::Store;

/// The printable summary, built before the telemetry config is consumed.
pub struct Summary(Vec<(&'static str, String)>);

impl Summary {
    pub fn new(cfg: &Config, telemetry: &TelemetryConfig) -> Summary {
        let set = |present: bool| String::from(if present { "set" } else { "unset" });
        let db = &cfg.store;
        let metrics = cfg.metrics.as_ref();
        Summary(vec![
            ("NETWORK", cfg.network.as_str().to_string()),
            ("BIND_ADDR", cfg.bind_addr.clone()),
            ("DATABASE_URL", redact_url(&cfg.database_url)),
            (
                "DB pool",
                format!(
                    "max={} acquire={}s idle={}s statement={}s",
                    db.max_connections,
                    db.acquire_timeout.as_secs(),
                    db.idle_timeout.as_secs(),
                    db.statement_timeout.as_secs()
                ),
            ),
            ("RUN_MIGRATIONS", cfg.run_migrations.to_string()),
            ("RATE_LIMIT_BACKEND", cfg.rate_limit_backend.as_str().to_string()),
            ("HORIZON_URL", redact_url(&cfg.horizon_url)),
            ("FRIENDBOT_URL", cfg.friendbot_url.as_deref().map_or("unset".into(), redact_url)),
            ("PUBLIC_APP_URL", redact_url(&cfg.public_app_url)),
            ("PUBLIC_API_URL", cfg.public_api_url.as_deref().map_or("unset".into(), redact_url)),
            ("EMAIL_FROM_ADDRESS", cfg.email_from_address.clone()),
            ("RESEND_API_KEY", set(!cfg.resend_api_key.is_empty())),
            ("MASTER_KEY", set(true)),
            ("MASTER_KEY_NEXT", set(cfg.master_key_next.is_some())),
            ("JWT_SECRET", set(!cfg.jwt_secret.is_empty())),
            ("AUDIT_CHAIN_KEY", set(true)),
            (
                "Ingest",
                format!(
                    "interval={}s page_limit={} lock_retry={}s",
                    cfg.ingest_interval_secs,
                    cfg.ingest_page_limit,
                    cfg.ingest_lock_retry.as_secs()
                ),
            ),
            ("SHUTDOWN_DRAIN_TIMEOUT_SECS", cfg.shutdown_drain_timeout.as_secs().to_string()),
            (
                "Horizon resilience",
                format!(
                    "attempts={} delay={}..{}ms breaker={} failures/{}s",
                    cfg.resilience.max_attempts,
                    cfg.resilience.base_delay_ms,
                    cfg.resilience.max_delay_ms,
                    cfg.resilience.cb_failure_threshold,
                    cfg.resilience.cb_reset_timeout_secs
                ),
            ),
            (
                "METRICS_BIND_ADDR",
                metrics.map_or("unset (disabled)".into(), |m| m.bind_addr.to_string()),
            ),
            ("METRICS_TOKEN", set(metrics.is_some_and(|m| m.token.is_some()))),
            (
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                telemetry
                    .endpoint
                    .as_deref()
                    .map_or("unset (disabled)".into(), redact_url),
            ),
            ("OTEL_EXPORTER_OTLP_HEADERS", format!("{} set", telemetry.headers.len())),
        ])
    }
}

/// Print the summary, then run every check; errors if any failed.
pub async fn run(cfg: Config, summary: Summary) -> Result<()> {
    println!("octo-server configuration (secrets redacted)");
    for (name, value) in &summary.0 {
        println!("  {name:<28} {value}");
    }
    println!();

    let mut failed = 0usize;
    let mut report = |check: &str, outcome: Result<String, String>| match outcome {
        Ok(detail) => println!("  ok    {check:<20} {detail}"),
        Err(detail) => {
            failed += 1;
            println!("  FAIL  {check:<20} {detail}");
        }
    };

    // Messages name variables only, never values (see mainnet_guard).
    report(
        "network safety",
        cfg.ensure_safe_for_network()
            .map(|()| format!("safe for {}", cfg.network.as_str()))
            .map_err(|e| e.to_string()),
    );

    match Store::connect_with(&cfg.database_url, &cfg.store).await {
        Err(e) => report("database", Err(format!("cannot connect: {:#}", anyhow::Error::new(e)))),
        Ok(store) => {
            report(
                "database",
                store
                    .ping()
                    .await
                    .map(|()| "connected".to_string())
                    .map_err(|e| format!("{:#}", anyhow::Error::new(e))),
            );
            let migrations = match store.pending_migrations().await {
                Ok(0) => Ok("up to date".to_string()),
                // Applied on startup anyway; only a problem when the server won't apply them.
                Ok(n) if cfg.run_migrations => Ok(format!("{n} pending (applied on startup)")),
                Ok(n) => Err(format!("{n} pending and RUN_MIGRATIONS=false")),
                Err(e) => Err(format!("cannot read: {:#}", anyhow::Error::new(e))),
            };
            report("migrations", migrations);
        }
    }

    if failed > 0 {
        anyhow::bail!("{failed} configuration check(s) failed");
    }
    println!("\nconfiguration is valid");
    Ok(())
}

/// `scheme://host[:port]/path` with any userinfo masked and the query/fragment dropped.
fn redact_url(raw: &str) -> String {
    let Some((scheme, rest)) = raw.split_once("://") else {
        return "[not a URL]".to_string();
    };
    let rest = rest.split(|c| c == '?' || c == '#').next().unwrap_or("");
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (creds, host) = match authority.rsplit_once('@') {
        Some((_, host)) => ("***@", host),
        None => ("", authority),
    };
    let path = if path.is_empty() {
        String::new()
    } else {
        format!("/{path}")
    };
    format!("{scheme}://{creds}{host}{path}")
}

#[cfg(test)]
mod tests {
    use super::redact_url;

    #[test]
    fn urls_lose_credentials_and_query() {
        assert_eq!(
            redact_url("postgres://octo:hunter2@db:5432/octo?sslmode=require&password=x"),
            "postgres://***@db:5432/octo"
        );
        assert_eq!(
            redact_url("https://horizon.example/?api_key=secret#frag"),
            "https://horizon.example"
        );
        assert_eq!(redact_url("http://localhost:3000"), "http://localhost:3000");
        assert_eq!(redact_url("not a url"), "[not a URL]");
    }
}
