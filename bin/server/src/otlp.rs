//! Minimal OTLP/HTTP (JSON) span exporter, built only with `--features otel` (issue #468).
//!
//! Std + crates already in the tree, so enabling tracing adds no supply-chain surface. Only
//! spans from `octo*` targets are exported, and only their fields: log events are never sent.
//! Field names that look sensitive are dropped and values are length-capped, so a secret can't
//! reach the collector as a span attribute even if a span is later given such a field.

use crate::telemetry::TelemetryConfig;
use anyhow::{Context as _, Result};
use serde_json::{json, Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::Subscriber;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::{LookupSpan, SpanRef};
use uuid::Uuid;

/// Finished spans waiting for export; when full, new spans are dropped rather than block requests.
const QUEUE_CAPACITY: usize = 4096;
const BATCH_SIZE: usize = 512;
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ATTRIBUTES: usize = 32;
const MAX_VALUE_CHARS: usize = 256;
/// A field whose (lowercased) name contains any of these is never exported.
const SENSITIVE_FIELDS: &[&str] = &[
    "password", "secret", "token", "key", "auth", "cookie", "otp", "code", "seed", "mnemonic",
    "xdr", "signature", "email", "backup", "sealed",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SpanContext {
    trace_id: u128,
    span_id: u64,
    sampled: bool,
}

enum AttrValue {
    Str(String),
    Int(i64),
    Bool(bool),
    Double(f64),
}

/// Per-span state, kept in the span's registry extensions until it closes.
struct SpanData {
    ctx: SpanContext,
    parent_span_id: Option<u64>,
    name: &'static str,
    target: &'static str,
    start: SystemTime,
    attributes: Vec<(&'static str, AttrValue)>,
}

struct FinishedSpan {
    data: SpanData,
    end: SystemTime,
}

/// The tracing layer that records `octo*` spans and queues them for export.
pub struct OtlpLayer {
    queue: mpsc::Sender<FinishedSpan>,
    sample_ratio: f64,
}

/// Handle to the background export task.
pub struct Exporter {
    stop: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl Exporter {
    /// Flush what's queued (bounded by [`SHUTDOWN_TIMEOUT`]) and stop.
    pub async fn shutdown(self) {
        self.stop.cancel();
        if tokio::time::timeout(SHUTDOWN_TIMEOUT, self.task).await.is_err() {
            tracing::warn!("OTLP exporter did not flush before the shutdown timeout");
        }
    }
}

/// Build the layer and spawn its exporter. Must be called inside the Tokio runtime.
pub fn start(endpoint: String, cfg: &TelemetryConfig) -> Result<(OtlpLayer, Exporter)> {
    let mut headers = reqwest::header::HeaderMap::new();
    for (k, v) in &cfg.headers {
        let name = reqwest::header::HeaderName::from_bytes(k.as_bytes())
            .context("invalid OTEL_EXPORTER_OTLP_HEADERS header name")?;
        let mut value = reqwest::header::HeaderValue::from_str(v)
            .context("invalid OTEL_EXPORTER_OTLP_HEADERS header value")?;
        value.set_sensitive(true);
        headers.insert(name, value);
    }
    let client = reqwest::Client::builder()
        .timeout(EXPORT_TIMEOUT)
        .default_headers(headers)
        .build()
        .context("build OTLP HTTP client")?;

    let (queue, spans) = mpsc::channel(QUEUE_CAPACITY);
    let stop = CancellationToken::new();
    let url = format!("{endpoint}/v1/traces");
    let service = cfg.service_name.clone();
    let task = tokio::spawn(export_loop(client, url, service, spans, stop.clone()));
    let layer = OtlpLayer {
        queue,
        sample_ratio: cfg.sample_ratio,
    };
    Ok((layer, Exporter { stop, task }))
}

impl<S> Layer<S> for OtlpLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let meta = attrs.metadata();
        // Third-party spans (and the exporter's own HTTP client) are never exported.
        if !meta.target().starts_with("octo") {
            return;
        }
        let Some(span) = ctx.span(id) else { return };
        let parent = span.parent().and_then(|p| nearest_context(&p));
        let span_ctx = match parent {
            Some(p) => SpanContext {
                trace_id: p.trace_id,
                span_id: random_span_id(),
                sampled: p.sampled,
            },
            None => {
                let trace_id = random_trace_id();
                SpanContext {
                    trace_id,
                    span_id: random_span_id(),
                    sampled: is_sampled(trace_id, self.sample_ratio),
                }
            }
        };
        let mut data = SpanData {
            ctx: span_ctx,
            parent_span_id: parent.map(|p| p.span_id),
            name: meta.name(),
            target: meta.target(),
            start: SystemTime::now(),
            attributes: Vec::new(),
        };
        attrs.record(&mut AttrVisitor(&mut data.attributes));
        span.extensions_mut().insert(data);
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut extensions = span.extensions_mut();
        if let Some(data) = extensions.get_mut::<SpanData>() {
            values.record(&mut AttrVisitor(&mut data.attributes));
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        let Some(data) = span.extensions_mut().remove::<SpanData>() else {
            return;
        };
        if data.ctx.sampled {
            let end = SystemTime::now();
            // Full queue: drop the span; tracing must never apply backpressure to requests.
            let _ = self.queue.try_send(FinishedSpan { data, end });
        }
    }
}

/// Context of `span` or its nearest exported ancestor.
fn nearest_context<S>(span: &SpanRef<'_, S>) -> Option<SpanContext>
where
    S: for<'a> LookupSpan<'a>,
{
    span.scope()
        .find_map(|s| s.extensions().get::<SpanData>().map(|d| d.ctx))
}

/// W3C `traceparent` for the current span, for [`octo_resilience::set_trace_injector`].
pub fn trace_headers() -> Vec<(String, String)> {
    let ctx = tracing::Span::current()
        .with_subscriber(|(id, dispatch)| {
            let registry = dispatch.downcast_ref::<tracing_subscriber::Registry>()?;
            nearest_context(&registry.span(id)?)
        })
        .flatten();
    ctx.map(|c| vec![("traceparent".to_string(), traceparent(c))])
        .unwrap_or_default()
}

fn traceparent(c: SpanContext) -> String {
    let flags = if c.sampled { "01" } else { "00" };
    format!("00-{:032x}-{:016x}-{flags}", c.trace_id, c.span_id)
}

fn random_trace_id() -> u128 {
    Uuid::new_v4().as_u128().max(1)
}

fn random_span_id() -> u64 {
    let b = Uuid::new_v4().into_bytes();
    u64::from_be_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]).max(1)
}

/// Deterministic per trace id, so every service sampling the same trace agrees.
fn is_sampled(trace_id: u128, ratio: f64) -> bool {
    if ratio >= 1.0 {
        return true;
    }
    let low = u64::try_from(trace_id & u128::from(u64::MAX)).unwrap_or(u64::MAX);
    (low as f64) < ratio * (u64::MAX as f64)
}

/// Records span fields as attributes, dropping sensitive names and capping size.
struct AttrVisitor<'a>(&'a mut Vec<(&'static str, AttrValue)>);

impl AttrVisitor<'_> {
    fn put(&mut self, field: &Field, value: AttrValue) {
        let name = field.name();
        let lower = name.to_ascii_lowercase();
        if SENSITIVE_FIELDS.iter().any(|s| lower.contains(s)) {
            return;
        }
        if let Some(slot) = self.0.iter_mut().find(|(k, _)| *k == name) {
            slot.1 = value;
        } else if self.0.len() < MAX_ATTRIBUTES {
            self.0.push((name, value));
        }
    }
}

impl Visit for AttrVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, AttrValue::Str(value.chars().take(MAX_VALUE_CHARS).collect()));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, AttrValue::Int(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, AttrValue::Int(i64::try_from(value).unwrap_or(i64::MAX)));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, AttrValue::Bool(value));
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.put(field, AttrValue::Double(value));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let text: String = format!("{value:?}").chars().take(MAX_VALUE_CHARS).collect();
        self.put(field, AttrValue::Str(text));
    }
}

/// Batch queued spans and POST them every [`FLUSH_INTERVAL`] or [`BATCH_SIZE`] spans.
async fn export_loop(
    client: reqwest::Client,
    url: String,
    service: String,
    mut spans: mpsc::Receiver<FinishedSpan>,
    stop: CancellationToken,
) {
    let mut batch = Vec::with_capacity(BATCH_SIZE);
    let mut ticker = tokio::time::interval(FLUSH_INTERVAL);
    loop {
        tokio::select! {
            received = spans.recv() => match received {
                Some(span) => {
                    batch.push(span);
                    if batch.len() >= BATCH_SIZE {
                        send(&client, &url, &service, &mut batch).await;
                    }
                }
                None => break,
            },
            _ = ticker.tick() => send(&client, &url, &service, &mut batch).await,
            () = stop.cancelled() => break,
        }
    }
    while let Ok(span) = spans.try_recv() {
        batch.push(span);
    }
    send(&client, &url, &service, &mut batch).await;
}

async fn send(client: &reqwest::Client, url: &str, service: &str, batch: &mut Vec<FinishedSpan>) {
    if batch.is_empty() {
        return;
    }
    let body = encode(service, batch);
    batch.clear();
    // Never log the URL or headers: either may embed collector credentials.
    match client.post(url).json(&body).send().await {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => tracing::warn!(status = resp.status().as_u16(), "OTLP export rejected"),
        Err(_) => tracing::warn!("OTLP export failed (collector unreachable)"),
    }
}

/// OTLP/JSON `ExportTraceServiceRequest`; ids are lowercase hex, times nanosecond strings.
fn encode(service: &str, spans: &[FinishedSpan]) -> Value {
    let spans: Vec<Value> = spans.iter().map(encode_span).collect();
    json!({
        "resourceSpans": [{
            "resource": { "attributes": [attr("service.name", &AttrValue::Str(service.into()))] },
            "scopeSpans": [{ "scope": { "name": "octo-server" }, "spans": spans }],
        }],
    })
}

fn encode_span(span: &FinishedSpan) -> Value {
    let d = &span.data;
    let mut attributes: Vec<Value> = d.attributes.iter().map(|(k, v)| attr(k, v)).collect();
    attributes.push(attr("code.namespace", &AttrValue::Str(d.target.into())));
    json!({
        "traceId": format!("{:032x}", d.ctx.trace_id),
        "spanId": format!("{:016x}", d.ctx.span_id),
        "parentSpanId": d.parent_span_id.map(|p| format!("{p:016x}")).unwrap_or_default(),
        "name": d.name,
        "kind": 1,
        "startTimeUnixNano": unix_nanos(d.start).to_string(),
        "endTimeUnixNano": unix_nanos(span.end).to_string(),
        "attributes": attributes,
    })
}

fn attr(key: &str, value: &AttrValue) -> Value {
    let value = match value {
        AttrValue::Str(s) => json!({ "stringValue": s }),
        AttrValue::Int(i) => json!({ "intValue": i.to_string() }),
        AttrValue::Bool(b) => json!({ "boolValue": b }),
        AttrValue::Double(f) => json!({ "doubleValue": f }),
    };
    json!({ "key": key, "value": value })
}

fn unix_nanos(t: SystemTime) -> u128 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    fn collect_attrs(span: impl FnOnce()) -> Vec<String> {
        let (queue, mut rx) = mpsc::channel(16);
        let layer = OtlpLayer {
            queue,
            sample_ratio: 1.0,
        };
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, span);
        let finished = rx.try_recv().expect("span exported");
        finished.data.attributes.iter().map(|(k, _)| k.to_string()).collect()
    }

    #[test]
    fn sensitive_fields_never_become_attributes() {
        let names = collect_attrs(|| {
            let _s = tracing::info_span!(
                target: "octo_test",
                "op",
                password = "hunter2",
                api_key = "octo_sk_x",
                jwt_token = "a.b.c",
                otp_code = "123456",
                account_g = "GABC"
            )
            .entered();
        });
        assert_eq!(names, vec!["account_g"]);
    }

    #[test]
    fn traceparent_is_w3c_formatted() {
        let c = SpanContext {
            trace_id: 0xabc,
            span_id: 0x12,
            sampled: true,
        };
        assert_eq!(traceparent(c), format!("00-{:032x}-{:016x}-01", 0xabc, 0x12));
    }

    #[test]
    fn sampling_extremes() {
        assert!(is_sampled(42, 1.0));
        assert!(!is_sampled(42, 0.0));
    }
}
