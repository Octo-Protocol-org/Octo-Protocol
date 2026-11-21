//! Tracing setup (issue #468). Logs always go to stdout; spans are exported over OTLP only when
//! the binary is built with `--features otel` **and** `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
//!
//! Variables (see also `docs/tracing.md`):
//! - `OTEL_EXPORTER_OTLP_ENDPOINT`: OTLP/HTTP collector base URL (`http://otel:4318`); unset = off.
//! - `OTEL_EXPORTER_OTLP_HEADERS`: `k=v,k2=v2` sent with every export (e.g. a collector key).
//! - `OTEL_SERVICE_NAME`: `service.name` resource attribute (default `octo-server`).
//! - `OTEL_TRACES_SAMPLE_RATIO`: fraction of new traces kept, `0.0`–`1.0` (default `1.0`).

use anyhow::{Context, Result};
use std::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

/// Trace-export settings. Read before the runtime starts, since it scrubs secrets from the env.
pub struct TelemetryConfig {
    pub endpoint: Option<String>,
    pub service_name: String,
    /// Export headers often carry a collector credential: zeroized and redacted in `Debug`.
    pub headers: Vec<(String, Zeroizing<String>)>,
    pub sample_ratio: f64,
}

impl fmt::Debug for TelemetryConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_names: Vec<&str> = self.headers.iter().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("TelemetryConfig")
            .field("endpoint", &self.endpoint.as_ref().map(|_| "[set]"))
            .field("service_name", &self.service_name)
            .field("headers", &header_names)
            .field("sample_ratio", &self.sample_ratio)
            .finish()
    }
}

impl TelemetryConfig {
    pub fn from_env() -> Result<Self> {
        let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .ok()
            .map(|v| v.trim().trim_end_matches('/').to_string())
            .filter(|v| !v.is_empty());
        if let Some(url) = &endpoint {
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                anyhow::bail!("OTEL_EXPORTER_OTLP_ENDPOINT must be an http(s) URL");
            }
        }
        let service_name = std::env::var("OTEL_SERVICE_NAME")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "octo-server".to_string());

        let raw_headers =
            Zeroizing::new(std::env::var("OTEL_EXPORTER_OTLP_HEADERS").unwrap_or_default());
        std::env::remove_var("OTEL_EXPORTER_OTLP_HEADERS");
        let headers = parse_headers(&raw_headers)?;

        let sample_ratio = match std::env::var("OTEL_TRACES_SAMPLE_RATIO") {
            Ok(raw) => raw
                .trim()
                .parse::<f64>()
                .ok()
                .filter(|r| (0.0..=1.0).contains(r))
                .with_context(|| format!("OTEL_TRACES_SAMPLE_RATIO must be 0.0-1.0, got {raw:?}"))?,
            Err(_) => 1.0,
        };
        Ok(Self {
            endpoint,
            service_name,
            headers,
            sample_ratio,
        })
    }
}

/// Parse `k=v,k2=v2`. Errors never echo a value, since values are usually credentials.
fn parse_headers(raw: &str) -> Result<Vec<(String, Zeroizing<String>)>> {
    raw.split(',')
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (k, v) = pair
                .split_once('=')
                .context("OTEL_EXPORTER_OTLP_HEADERS entries must be key=value")?;
            Ok((k.trim().to_string(), Zeroizing::new(v.trim().to_string())))
        })
        .collect()
}

fn env_filter() -> EnvFilter {
    EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(|_| "info,octo=debug".to_string()))
}

/// Log-only subscriber for the pre-runtime phase (install with `with_default`, not globally).
pub fn boot_subscriber() -> impl tracing::Subscriber + Send + Sync {
    tracing_subscriber::fmt().with_env_filter(env_filter()).finish()
}

/// Running telemetry; call [`Telemetry::shutdown`] before exit to flush queued spans.
#[derive(Default)]
pub struct Telemetry {
    #[cfg(feature = "otel")]
    exporter: Option<crate::otlp::Exporter>,
}

impl Telemetry {
    #[cfg(feature = "otel")]
    pub async fn shutdown(self) {
        if let Some(exporter) = self.exporter {
            exporter.shutdown().await;
        }
    }

    #[cfg(not(feature = "otel"))]
    pub async fn shutdown(self) {}
}

/// Install the global subscriber. Must run inside the Tokio runtime (the exporter spawns a task).
#[cfg(feature = "otel")]
pub fn init(cfg: TelemetryConfig) -> Result<Telemetry> {
    let started = cfg
        .endpoint
        .clone()
        .map(|endpoint| crate::otlp::start(endpoint, &cfg))
        .transpose()?;
    let (layer, exporter) = match started {
        Some((layer, exporter)) => (Some(layer), Some(exporter)),
        None => (None, None),
    };
    tracing_subscriber::registry()
        .with(env_filter())
        .with(tracing_subscriber::fmt::layer())
        .with(layer)
        .try_init()
        .context("install tracing subscriber")?;
    if exporter.is_some() {
        octo_resilience::set_trace_injector(crate::otlp::trace_headers);
        tracing::info!(
            service = %cfg.service_name,
            sample_ratio = cfg.sample_ratio,
            "OTLP trace export enabled"
        );
    }
    Ok(Telemetry { exporter })
}

/// Install the global subscriber (this build has no exporter).
#[cfg(not(feature = "otel"))]
pub fn init(cfg: TelemetryConfig) -> Result<Telemetry> {
    tracing_subscriber::registry()
        .with(env_filter())
        .with(tracing_subscriber::fmt::layer())
        .try_init()
        .context("install tracing subscriber")?;
    if cfg.endpoint.is_some() {
        tracing::warn!("OTEL_EXPORTER_OTLP_ENDPOINT is set, but this build has no `otel` feature");
    }
    Ok(Telemetry::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_parse_and_reject_malformed_pairs() {
        let parsed = parse_headers("x-api-key=abc, other = d=e").unwrap();
        assert_eq!(parsed[0].0, "x-api-key");
        assert_eq!(parsed[0].1.as_str(), "abc");
        assert_eq!(parsed[1].1.as_str(), "d=e");
        assert!(parse_headers("novalue").is_err());
        assert!(parse_headers("").unwrap().is_empty());
    }

    #[test]
    fn debug_never_prints_header_values_or_endpoint() {
        let cfg = TelemetryConfig {
            endpoint: Some("https://user:pass@collector".into()),
            service_name: "octo-server".into(),
            headers: vec![("x-api-key".into(), Zeroizing::new("hunter2".into()))],
            sample_ratio: 1.0,
        };
        let shown = format!("{cfg:?}");
        assert!(!shown.contains("hunter2"));
        assert!(!shown.contains("pass"));
    }
}
