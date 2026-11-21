//! Horizon payments client for the ingest worker.
//!
//! Polls an account's `/operations` endpoint (with `join=transactions` so we get the memo) using a
//! saved paging-token cursor. `/operations` rather than `/payments` because only it carries
//! `claim_claimable_balance` (issue #448); paging tokens are the same operation TOIDs in both, so
//! cursors stored before the switch remain valid. Cursor polling keeps the worker simple, restart-safe, and trivially
//! horizontally scalable (one worker per account); the cursor is the durable resume point.
//!
//! Wallets opted into streaming (issue #446) additionally hold an SSE connection via
//! [`HorizonPayments::open_payment_stream`], resumed from the same cursor; polling is the fallback.
//!
//! # Resilience
//!
//! `payments_after` is a **read-only** call and is therefore wrapped with retry-with-backoff and
//! a circuit breaker from [`octo_resilience`]. Transient Horizon failures (connection errors,
//! timeouts, 5xx) are retried up to `max_attempts` times with exponential backoff. After
//! `failure_threshold` consecutive failures the circuit opens, short-circuiting further calls
//! until the cool-down elapses.
//!
//! There is no equivalent of `submit_transaction` in this crate, so the submit-asymmetry rule
//! does not apply here.

use octo_resilience::{execute, CallKind, CircuitBreaker, ResilienceError, RetryPolicy};
use serde::{Deserialize, Serialize};

/// Errors talking to Horizon.
#[derive(Debug, thiserror::Error)]
pub enum HorizonError {
    #[error("horizon request failed")]
    Request,
    #[error("horizon returned an unexpected response")]
    Decode,
    #[error("horizon circuit breaker open")]
    CircuitOpen,
}

/// One payment record from Horizon (the fields octo needs).
///
/// `Serialize` is derived so tests can round-trip these through a mock Horizon server that
/// returns Horizon-shaped JSON; production only ever deserializes them.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PaymentRecord {
    /// The operation TOID — globally unique; used as the idempotent dedup key.
    pub id: String,
    /// Cursor token for resuming after this record.
    pub paging_token: String,
    /// Horizon operation type; only the crediting types in `lib.rs` are ever recorded.
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub transaction_hash: Option<String>,
    #[serde(default)]
    pub transaction_successful: bool,
    #[serde(default)]
    pub from: Option<String>,
    /// Destination base account (`G...`).
    #[serde(default)]
    pub to: Option<String>,
    /// Present when the payment was sent to a muxed (`M...`) address.
    #[serde(default)]
    pub to_muxed: Option<String>,
    /// The muxed id (customer id) when `to_muxed` is set. Horizon returns it as a string.
    #[serde(default)]
    pub to_muxed_id: Option<String>,
    #[serde(default)]
    pub asset_type: Option<String>,
    #[serde(default)]
    pub asset_code: Option<String>,
    #[serde(default)]
    pub asset_issuer: Option<String>,
    /// Decimal amount string, e.g. "10.0000000".
    #[serde(default)]
    pub amount: Option<String>,
    /// createAccount uses `starting_balance` instead of `amount`.
    #[serde(default)]
    pub starting_balance: Option<String>,
    /// Joined parent transaction (for memo + ledger).
    #[serde(default)]
    pub transaction: Option<TransactionRecord>,
    /// `claim_claimable_balance` only: the claimed balance's id (hex).
    #[serde(default)]
    pub balance_id: Option<String>,
    /// `claim_claimable_balance` only: the account that claimed, and so received, the funds.
    #[serde(default)]
    pub claimant: Option<String>,
}

/// The joined transaction fields we use.
///
/// `Serialize` is derived for the same test-only reason as [`PaymentRecord`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransactionRecord {
    #[serde(default)]
    pub memo_type: Option<String>,
    #[serde(default)]
    pub memo: Option<String>,
    #[serde(default)]
    pub ledger: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct Embedded<T> {
    records: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct Page<T> {
    _embedded: Embedded<T>,
}

/// The fields of an operation effect used to read what a claim actually credited.
#[derive(Debug, Deserialize)]
struct EffectRecord {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    amount: Option<String>,
    #[serde(default)]
    asset_type: Option<String>,
    #[serde(default)]
    asset_code: Option<String>,
    #[serde(default)]
    asset_issuer: Option<String>,
}

/// What a `claim_claimable_balance` operation credited to the claimant (its `account_credited` effect).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimCredit {
    pub amount: String,
    pub asset_type: Option<String>,
    pub asset_code: Option<String>,
    pub asset_issuer: Option<String>,
}

/// Who created a claimable balance, and the memo of the transaction that created it.
#[derive(Debug, Clone, Deserialize)]
pub struct ClaimOrigin {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub source_account: Option<String>,
    #[serde(default)]
    pub transaction: Option<TransactionRecord>,
}

/// A thin Horizon payments client with retry-with-backoff and circuit-breaker protection.
///
/// Clones share the same circuit-breaker state (via `Arc` inside [`CircuitBreaker`]).
#[derive(Clone)]
pub struct HorizonPayments {
    http: reqwest::Client,
    base_url: String,
    circuit: CircuitBreaker,
    retry: RetryPolicy,
}

impl HorizonPayments {
    /// Create a new client with default resilience settings.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_resilience(
            base_url,
            RetryPolicy::default(),
            CircuitBreaker::new(5, std::time::Duration::from_secs(30)),
        )
    }

    /// Create a client with explicit resilience configuration.
    /// Used by `bin/server` (to wire env-var config) and tests (to inject tight thresholds).
    pub fn with_resilience(
        base_url: impl Into<String>,
        retry: RetryPolicy,
        circuit: CircuitBreaker,
    ) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into(),
            circuit,
            retry,
        }
    }

    /// Fetch up to `limit` operations for `account_g`, oldest-first, starting after `cursor`.
    ///
    /// Oldest-first (`order=asc`) so we process and advance the cursor monotonically. Transient
    /// failures are retried with exponential backoff; the circuit breaker opens after repeated
    /// failures so the ingest loop doesn't pile up independent timeouts.
    #[tracing::instrument(
        name = "horizon_payments_after",
        skip(self),
        fields(
            call_type = "payments_after",
            account_g = %account_g,
            cursor = ?cursor,
            limit = limit,
            outcome = tracing::field::Empty
        )
    )]
    pub async fn payments_after(
        &self,
        account_g: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Vec<PaymentRecord>, HorizonError> {
        let span = tracing::Span::current();
        let mut url = format!(
            "{}/accounts/{}/operations?order=asc&limit={}&join=transactions",
            self.base_url.trim_end_matches('/'),
            account_g,
            limit
        );
        if let Some(c) = cursor {
            url.push_str("&cursor=");
            url.push_str(c);
        }

        let result = self.fetch_records::<PaymentRecord>(url).await;

        match &result {
            Ok(_) => span.record("outcome", "success"),
            Err(ResilienceError::Circuit) => span.record("outcome", "circuit_open"),
            Err(ResilienceError::Exhausted(IngestFetchError::Decode)) => {
                span.record("outcome", "decode_error")
            }
            Err(ResilienceError::Exhausted(_)) => span.record("outcome", "failure"),
        };

        result.map_err(map_resilience)
    }

    /// What claim operation `op_id` credited to `account_g`, or `None` if it credited nothing to it.
    pub async fn claim_credit(
        &self,
        op_id: &str,
        account_g: &str,
    ) -> Result<Option<ClaimCredit>, HorizonError> {
        let url = format!(
            "{}/operations/{}/effects?limit=200",
            self.base_url.trim_end_matches('/'),
            op_id
        );
        let effects = self
            .fetch_records::<EffectRecord>(url)
            .await
            .map_err(map_resilience)?;
        Ok(effects
            .into_iter()
            .find(|e| e.kind == "account_credited" && e.account.as_deref() == Some(account_g))
            .and_then(|e| {
                Some(ClaimCredit {
                    amount: e.amount?,
                    asset_type: e.asset_type,
                    asset_code: e.asset_code,
                    asset_issuer: e.asset_issuer,
                })
            }))
    }

    /// The operation that created claimable balance `balance_id`, or `None` if Horizon has no record.
    pub async fn claimable_balance_origin(
        &self,
        balance_id: &str,
    ) -> Result<Option<ClaimOrigin>, HorizonError> {
        let url = format!(
            "{}/claimable_balances/{}/operations?order=asc&limit=1&join=transactions",
            self.base_url.trim_end_matches('/'),
            balance_id
        );
        let ops = self
            .fetch_records::<ClaimOrigin>(url)
            .await
            .map_err(map_resilience)?;
        Ok(ops
            .into_iter()
            .next()
            .filter(|op| op.kind == "create_claimable_balance"))
    }

    /// GET one Horizon collection page with retry + circuit breaker; a 404 is an empty page.
    async fn fetch_records<T: serde::de::DeserializeOwned>(
        &self,
        url: String,
    ) -> Result<Vec<T>, ResilienceError<IngestFetchError>> {
        let http = self.http.clone();
        let trace = trace_headers();
        execute(&self.circuit, &self.retry, CallKind::ReadOnly, || {
            let url = url.clone();
            let http = http.clone();
            let trace = trace.clone();
            async move {
                let resp = http
                    .get(&url)
                    .headers(trace)
                    .send()
                    .await
                    .map_err(|_| IngestFetchError::Transport)?;

                // 404 means the resource does not exist on-chain (yet) — not a retriable error.
                if resp.status() == reqwest::StatusCode::NOT_FOUND {
                    return Ok(Vec::new());
                }
                if resp.status().is_server_error() {
                    return Err(IngestFetchError::Transport); // retriable
                }
                if !resp.status().is_success() {
                    return Err(IngestFetchError::Permanent);
                }
                let page: Page<T> = resp.json().await.map_err(|_| IngestFetchError::Decode)?;
                Ok(page._embedded.records)
            }
        })
        .await
    }

    /// Open Horizon's `/operations` SSE stream for `account_g`, resuming after `cursor`.
    ///
    /// Gated by the same circuit breaker as [`Self::payments_after`], so an outage stops both
    /// paths. There is no internal retry: the caller owns reconnect backoff (see `stream.rs`).
    #[tracing::instrument(name = "horizon_open_payment_stream", skip(self))]
    pub async fn open_payment_stream(
        &self,
        account_g: &str,
        cursor: &str,
    ) -> Result<PaymentStream, HorizonError> {
        self.circuit.check().map_err(|_| HorizonError::CircuitOpen)?;
        let url = format!(
            "{}/accounts/{}/operations",
            self.base_url.trim_end_matches('/'),
            account_g
        );
        // Headers arrive immediately on a live stream; a hung connect must not pin the task.
        let sent = tokio::time::timeout(
            STREAM_CONNECT_TIMEOUT,
            self.http
                .get(&url)
                .query(&[("cursor", cursor), ("join", "transactions")])
                .header(reqwest::header::ACCEPT, "text/event-stream")
                .send(),
        )
        .await;
        let resp = match sent {
            Ok(Ok(resp)) => resp,
            _ => {
                self.circuit.on_failure();
                return Err(HorizonError::Request);
            }
        };
        if resp.status().is_server_error() {
            self.circuit.on_failure();
            return Err(HorizonError::Request);
        }
        // Any non-5xx answer proves Horizon is reachable, so it closes a half-open breaker.
        self.circuit.on_success();
        if !resp.status().is_success() {
            return Err(HorizonError::Request);
        }
        Ok(PaymentStream {
            resp,
            decoder: SseDecoder::default(),
        })
    }
}

/// How long opening a stream may take before it counts as a failed connect.
const STREAM_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Upper bound on one buffered SSE line or event, so a hostile upstream cannot exhaust memory.
const MAX_SSE_EVENT_BYTES: usize = 1024 * 1024;

/// An open Horizon `/operations` SSE stream (issue #446).
pub struct PaymentStream {
    resp: reqwest::Response,
    decoder: SseDecoder,
}

impl PaymentStream {
    /// The next payment record, or `Ok(None)` once Horizon closes the stream.
    pub async fn next_record(&mut self) -> Result<Option<PaymentRecord>, HorizonError> {
        loop {
            if let Some(rec) = self.decoder.next_record()? {
                return Ok(Some(rec));
            }
            match self.resp.chunk().await {
                Ok(Some(bytes)) => self.decoder.feed(&bytes)?,
                Ok(None) => return Ok(None),
                Err(_) => return Err(HorizonError::Request),
            }
        }
    }
}

/// Incremental `text/event-stream` decoder that yields Horizon payment records.
#[derive(Debug, Default)]
pub struct SseDecoder {
    buf: Vec<u8>,
    data: String,
}

impl SseDecoder {
    /// Append raw bytes from the wire.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), HorizonError> {
        self.buf.extend_from_slice(bytes);
        // A line this long without a newline is never a legitimate Horizon event.
        if self.buf.len() > MAX_SSE_EVENT_BYTES && !self.buf.contains(&b'\n') {
            return Err(HorizonError::Decode);
        }
        Ok(())
    }

    /// The next complete payment record already buffered, if any.
    ///
    /// Horizon's `"hello"`/`"byebye"` string events are ignored; an object that is not a valid
    /// record is an error, so the caller reconnects and the record is never silently skipped.
    pub fn next_record(&mut self) -> Result<Option<PaymentRecord>, HorizonError> {
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let raw: Vec<u8> = self.buf.drain(..=pos).collect();
            let line = std::str::from_utf8(&raw).map_err(|_| HorizonError::Decode)?;
            let line = line.trim_end_matches(['\n', '\r']);
            if line.is_empty() {
                let data = std::mem::take(&mut self.data);
                if let Some(rec) = parse_sse_data(&data)? {
                    return Ok(Some(rec));
                }
            } else if let Some(value) = line.strip_prefix("data:") {
                if !self.data.is_empty() {
                    self.data.push('\n');
                }
                self.data.push_str(value.strip_prefix(' ').unwrap_or(value));
                if self.data.len() > MAX_SSE_EVENT_BYTES {
                    return Err(HorizonError::Decode);
                }
            }
            // `event:`, `id:`, `retry:` and `:` comment lines carry nothing octo needs.
        }
        Ok(None)
    }
}

/// Decode one SSE event payload: a JSON object is a record, anything else is a control event.
fn parse_sse_data(data: &str) -> Result<Option<PaymentRecord>, HorizonError> {
    if !data.trim_start().starts_with('{') {
        return Ok(None);
    }
    serde_json::from_str(data)
        .map(Some)
        .map_err(|_| HorizonError::Decode)
}

/// Collapse a resilience outcome into the public error type.
fn map_resilience(e: ResilienceError<IngestFetchError>) -> HorizonError {
    match e {
        ResilienceError::Circuit => HorizonError::CircuitOpen,
        ResilienceError::Exhausted(IngestFetchError::Decode) => HorizonError::Decode,
        ResilienceError::Exhausted(_) => HorizonError::Request,
    }
}

// ---------------------------------------------------------------------------
// Internal error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum IngestFetchError {
    Transport,
    Decode,
    Permanent,
}

impl octo_resilience::Retriable for IngestFetchError {
    fn is_retriable(&self) -> bool {
        // Only transport failures are transient. A decode failure or a permanent status will
        // repeat identically on a retry, and retrying them would also count toward opening the
        // circuit breaker.
        matches!(self, IngestFetchError::Transport)
    }
}

impl std::fmt::Display for IngestFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport => write!(f, "transport error"),
            Self::Decode => write!(f, "decode error"),
            Self::Permanent => write!(f, "permanent error"),
        }
    }
}

/// Trace-context headers for the current span; empty unless trace export is enabled.
fn trace_headers() -> reqwest::header::HeaderMap {
    octo_resilience::trace_headers()
        .into_iter()
        .filter_map(|(k, v)| {
            let name = reqwest::header::HeaderName::from_bytes(k.as_bytes()).ok()?;
            Some((name, reqwest::header::HeaderValue::from_str(&v).ok()?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt;

    // Asserts that horizon_payments_after emits its distinct named tracing span.
    #[tokio::test]
    async fn horizon_payments_after_emits_tracing_span() {
        let recorded_spans = Arc::new(Mutex::new(Vec::<String>::new()));
        let spans_clone = recorded_spans.clone();

        struct SpanRecorder(Arc<Mutex<Vec<String>>>);
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpanRecorder {
            fn on_new_span(
                &self,
                attrs: &tracing::span::Attributes<'_>,
                _id: &tracing::span::Id,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                self.0.lock().unwrap().push(attrs.metadata().name().to_string());
            }
        }

        let subscriber = tracing_subscriber::registry().with(SpanRecorder(spans_clone));
        let _guard = tracing::subscriber::set_default(subscriber);

        let client = HorizonPayments::new("http://127.0.0.1:1");
        let _ = client.payments_after("GABCDEFGHIJKLMNOPQRSTUVWXYZ", None, 10).await;

        let spans = recorded_spans.lock().unwrap().clone();
        assert!(spans.contains(&"horizon_payments_after".to_string()));
    }

    fn sse_record(id: &str) -> String {
        format!(
            r#"{{"id":"{id}","paging_token":"{id}","type":"payment","transaction_successful":true,"to":"GBASE","amount":"1.0000000","asset_type":"native"}}"#
        )
    }

    // A record split across chunks is reassembled; Horizon's string control events are ignored.
    #[test]
    fn sse_decoder_yields_records_across_chunk_boundaries() {
        let wire = format!(
            "retry: 1000\nevent: open\ndata: \"hello\"\n\nid: 1\ndata: {}\n\n: keepalive\n",
            sse_record("12884905985")
        );
        let (a, b) = wire.split_at(wire.len() / 2);
        let mut decoder = SseDecoder::default();
        decoder.feed(a.as_bytes()).unwrap();
        assert!(decoder.next_record().unwrap().is_none());
        decoder.feed(b.as_bytes()).unwrap();
        let rec = decoder.next_record().unwrap().expect("record");
        assert_eq!(rec.id, "12884905985");
        assert!(decoder.next_record().unwrap().is_none());
    }

    // A malformed record must end the session rather than be skipped past the cursor.
    #[test]
    fn sse_decoder_rejects_malformed_record_objects() {
        let mut decoder = SseDecoder::default();
        decoder.feed(b"data: {\"id\": 5}\n\n").unwrap();
        assert!(matches!(decoder.next_record(), Err(HorizonError::Decode)));
    }

    // An endless line with no newline is refused instead of buffered without bound.
    #[test]
    fn sse_decoder_bounds_unterminated_lines() {
        let mut decoder = SseDecoder::default();
        let junk = vec![b'a'; MAX_SSE_EVENT_BYTES + 1];
        assert!(matches!(decoder.feed(&junk), Err(HorizonError::Decode)));
    }
}
