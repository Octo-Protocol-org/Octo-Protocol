//! Process-wide Prometheus metrics in the text exposition format (issue #467).
//!
//! Std-only on purpose: a scrape endpoint shouldn't widen the dependency tree of a service that
//! moves money. Cardinality is bounded twice over: label *names* are fixed per metric, and each
//! metric keeps at most [`MAX_SERIES`] label combinations. Anything beyond collapses into one
//! series whose labels all read `overflow`, so a caller bug can't grow memory without limit.
//!
//! Never pass user-controlled strings (raw paths, ids, emails) as label values; use route
//! templates, enums and status classes.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Mutex, MutexGuard};

/// Most label combinations one metric may hold before new ones collapse into `overflow`.
pub const MAX_SERIES: usize = 500;
const OVERFLOW: &str = "overflow";

/// Latency buckets in seconds, sized for API calls under a 10 s outbound ceiling.
pub const LATENCY_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Ingest-tick buckets in seconds: a tick fans out over every due wallet, so it runs longer.
pub const TICK_BUCKETS: &[f64] = &[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0];

// --- the metrics -----------------------------------------------------------------------------

/// API request latency by method, matched route template and status class.
pub static HTTP_REQUEST_DURATION: Histogram = Histogram::new(
    "octo_http_request_duration_seconds",
    "HTTP request latency by method, route template and status class.",
    &["method", "route", "status_class"],
    LATENCY_BUCKETS,
);

/// Final webhook delivery outcomes (after retries).
pub static WEBHOOK_DELIVERIES: Counter = Counter::new(
    "octo_webhook_deliveries_total",
    "Webhook deliveries by kind (event, ping) and final outcome (delivered, failed, dead).",
    &["kind", "outcome"],
);

/// Duration of each ingest supervisor tick.
pub static INGEST_TICK_DURATION: Histogram = Histogram::new(
    "octo_ingest_tick_duration_seconds",
    "Ingest supervisor tick duration by outcome (ok, error).",
    &["outcome"],
    TICK_BUCKETS,
);

/// Unix time of the last successful ingest tick; lag is `time() - this`.
pub static INGEST_LAST_SUCCESS: Gauge = Gauge::new(
    "octo_ingest_last_success_timestamp_seconds",
    "Unix time of the last successful ingest tick on this instance.",
    &[],
);

/// 1 while this instance holds the ingest leader lock.
pub static INGEST_LEADER: Gauge = Gauge::new(
    "octo_ingest_leader",
    "1 while this instance holds the ingest leader lock, else 0.",
    &[],
);

/// New deposits recorded by ingest.
pub static INGEST_DEPOSITS: Counter = Counter::new(
    "octo_ingest_deposits_total",
    "Deposits recorded by ingest, by whether they were attributed to a customer address.",
    &["attributed"],
);

/// Gauges computed at scrape time (e.g. circuit-breaker state), registered by the binary.
static GAUGE_FNS: Mutex<Vec<GaugeFn>> = Mutex::new(Vec::new());

struct GaugeFn {
    name: &'static str,
    help: &'static str,
    labels: Vec<(&'static str, &'static str)>,
    read: Box<dyn Fn() -> f64 + Send + Sync>,
}

/// Register a gauge whose value is read on every scrape. Labels are static, so this can't add
/// cardinality at runtime; register each `(name, labels)` pair once at startup.
pub fn register_gauge_fn(
    name: &'static str,
    help: &'static str,
    labels: &[(&'static str, &'static str)],
    read: impl Fn() -> f64 + Send + Sync + 'static,
) {
    lock(&GAUGE_FNS).push(GaugeFn {
        name,
        help,
        labels: labels.to_vec(),
        read: Box::new(read),
    });
}

/// Render every metric in the Prometheus text exposition format (version 0.0.4).
pub fn render() -> String {
    let mut out = String::new();
    HTTP_REQUEST_DURATION.render(&mut out);
    WEBHOOK_DELIVERIES.render(&mut out);
    INGEST_TICK_DURATION.render(&mut out);
    INGEST_LAST_SUCCESS.render(&mut out);
    INGEST_LEADER.render(&mut out);
    INGEST_DEPOSITS.render(&mut out);

    let gauges = lock(&GAUGE_FNS);
    let mut last_name = "";
    for g in gauges.iter() {
        // Same-name gauges (one per label set) share a single HELP/TYPE header.
        if g.name != last_name {
            header(&mut out, g.name, g.help, "gauge");
            last_name = g.name;
        }
        let names: Vec<&str> = g.labels.iter().map(|(k, _)| *k).collect();
        let values: Vec<String> = g.labels.iter().map(|(_, v)| (*v).to_string()).collect();
        sample(&mut out, g.name, &names, &values, None, (g.read)());
    }
    out
}

/// Content type for [`render`]'s output.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

// --- metric types ------------------------------------------------------------------------------

/// A monotonically increasing counter.
pub struct Counter {
    name: &'static str,
    help: &'static str,
    labels: &'static [&'static str],
    series: Mutex<BTreeMap<Vec<String>, f64>>,
}

impl Counter {
    pub const fn new(
        name: &'static str,
        help: &'static str,
        labels: &'static [&'static str],
    ) -> Self {
        Self {
            name,
            help,
            labels,
            series: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn inc(&self, values: &[&str]) {
        let mut map = lock(&self.series);
        let key = bounded_key(&map, self.labels, values);
        *map.entry(key).or_insert(0.0) += 1.0;
    }

    fn render(&self, out: &mut String) {
        header(out, self.name, self.help, "counter");
        for (values, v) in lock(&self.series).iter() {
            sample(out, self.name, self.labels, values, None, *v);
        }
    }
}

/// A value that can go up and down.
pub struct Gauge {
    name: &'static str,
    help: &'static str,
    labels: &'static [&'static str],
    series: Mutex<BTreeMap<Vec<String>, f64>>,
}

impl Gauge {
    pub const fn new(
        name: &'static str,
        help: &'static str,
        labels: &'static [&'static str],
    ) -> Self {
        Self {
            name,
            help,
            labels,
            series: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn set(&self, values: &[&str], v: f64) {
        let mut map = lock(&self.series);
        let key = bounded_key(&map, self.labels, values);
        map.insert(key, v);
    }

    fn render(&self, out: &mut String) {
        header(out, self.name, self.help, "gauge");
        for (values, v) in lock(&self.series).iter() {
            sample(out, self.name, self.labels, values, None, *v);
        }
    }
}

/// A cumulative histogram over fixed buckets.
pub struct Histogram {
    name: &'static str,
    help: &'static str,
    labels: &'static [&'static str],
    buckets: &'static [f64],
    series: Mutex<BTreeMap<Vec<String>, HistogramState>>,
}

struct HistogramState {
    /// Per-bucket (non-cumulative) counts; one extra slot for +Inf.
    counts: Vec<u64>,
    sum: f64,
}

impl Histogram {
    pub const fn new(
        name: &'static str,
        help: &'static str,
        labels: &'static [&'static str],
        buckets: &'static [f64],
    ) -> Self {
        Self {
            name,
            help,
            labels,
            buckets,
            series: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn observe(&self, values: &[&str], v: f64) {
        let mut map = lock(&self.series);
        let key = bounded_key(&map, self.labels, values);
        let state = map.entry(key).or_insert_with(|| HistogramState {
            counts: vec![0; self.buckets.len() + 1],
            sum: 0.0,
        });
        let slot = self
            .buckets
            .iter()
            .position(|b| v <= *b)
            .unwrap_or(self.buckets.len());
        state.counts[slot] += 1;
        state.sum += v;
    }

    fn render(&self, out: &mut String) {
        header(out, self.name, self.help, "histogram");
        let bucket_name = format!("{}_bucket", self.name);
        for (values, state) in lock(&self.series).iter() {
            let mut cumulative = 0u64;
            for (i, count) in state.counts.iter().enumerate() {
                cumulative += count;
                let le = self
                    .buckets
                    .get(i)
                    .map_or_else(|| "+Inf".to_string(), |b| fmt_f64(*b));
                let le = Some(le.as_str());
                sample(out, &bucket_name, self.labels, values, le, cumulative as f64);
            }
            let sum_name = format!("{}_sum", self.name);
            sample(out, &sum_name, self.labels, values, None, state.sum);
            let count_name = format!("{}_count", self.name);
            sample(out, &count_name, self.labels, values, None, cumulative as f64);
        }
    }
}

// --- helpers -----------------------------------------------------------------------------------

/// A poisoned lock only means a panic mid-update of a number; keep serving the metrics.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The series key for `values`, collapsed to `overflow` once the metric is full.
fn bounded_key<T>(
    map: &BTreeMap<Vec<String>, T>,
    labels: &[&str],
    values: &[&str],
) -> Vec<String> {
    let key: Vec<String> = (0..labels.len())
        .map(|i| values.get(i).copied().unwrap_or("").to_string())
        .collect();
    if map.contains_key(&key) || map.len() < MAX_SERIES {
        return key;
    }
    vec![OVERFLOW.to_string(); labels.len()]
}

fn header(out: &mut String, name: &str, help: &str, kind: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

fn sample(
    out: &mut String,
    name: &str,
    labels: &[&str],
    values: &[String],
    le: Option<&str>,
    v: f64,
) {
    out.push_str(name);
    let mut pairs: Vec<(&str, &str)> = labels
        .iter()
        .copied()
        .zip(values.iter().map(String::as_str))
        .collect();
    if let Some(le) = le {
        pairs.push(("le", le));
    }
    if !pairs.is_empty() {
        out.push('{');
        for (i, (k, val)) in pairs.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(out, "{k}=\"{}\"", escape(val));
        }
        out.push('}');
    }
    let _ = writeln!(out, " {}", fmt_f64(v));
}

fn escape(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

fn fmt_f64(v: f64) -> String {
    if v == f64::INFINITY {
        "+Inf".to_string()
    } else if v == f64::NEG_INFINITY {
        "-Inf".to_string()
    } else {
        v.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_renders_cumulative_buckets() {
        static H: Histogram = Histogram::new("t_seconds", "test", &["route"], &[0.1, 1.0]);
        H.observe(&["/a"], 0.05);
        H.observe(&["/a"], 0.5);
        H.observe(&["/a"], 5.0);
        let mut out = String::new();
        H.render(&mut out);
        assert!(out.contains("t_seconds_bucket{route=\"/a\",le=\"0.1\"} 1\n"));
        assert!(out.contains("t_seconds_bucket{route=\"/a\",le=\"1\"} 2\n"));
        assert!(out.contains("t_seconds_bucket{route=\"/a\",le=\"+Inf\"} 3\n"));
        assert!(out.contains("t_seconds_count{route=\"/a\"} 3\n"));
    }

    #[test]
    fn series_count_is_capped() {
        static C: Counter = Counter::new("t_total", "test", &["id"]);
        for i in 0..(MAX_SERIES + 50) {
            C.inc(&[&i.to_string()]);
        }
        assert_eq!(lock(&C.series).len(), MAX_SERIES + 1);
        assert_eq!(lock(&C.series)[&vec![OVERFLOW.to_string()]], 50.0);
    }

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
