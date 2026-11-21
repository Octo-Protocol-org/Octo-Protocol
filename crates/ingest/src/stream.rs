//! Opt-in Horizon SSE ingest per wallet (issue #446).
//!
//! A wallet with `ingest_streaming` set gets one long-lived task holding an SSE connection to its
//! `/operations` stream. Each record goes through the same [`Ingestor::process`] path as polling and
//! advances the same durable cursor, so a reconnect resumes exactly where it stopped.
//!
//! Fallback: while a wallet's stream is open it sits in [`LiveStreams`] and the polling tick skips
//! it; the moment the stream drops it leaves the set and the next tick polls it again. Reconnects
//! back off exponentially with per-wallet jitter, and connects are gated by the shared circuit
//! breaker, so a Horizon outage cannot turn into a reconnect storm.

use crate::{IngestError, Ingestor};
use octo_store::Wallet;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Silence longer than this may be a half-open connection, so the session reconnects.
const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// A session that stayed up this long was healthy, so the next reconnect starts from base delay.
const HEALTHY_SESSION: Duration = Duration::from_secs(30);
/// First reconnect delay; doubled per consecutive unhealthy session.
const RECONNECT_BASE: Duration = Duration::from_secs(1);
/// Ceiling on the reconnect delay, so a long outage still recovers within minutes.
const RECONNECT_MAX: Duration = Duration::from_secs(300);

/// Wallets whose SSE stream is currently open; the polling tick skips these.
#[derive(Debug, Clone, Default)]
pub struct LiveStreams(Arc<Mutex<HashSet<Uuid>>>);

impl LiveStreams {
    /// Whether `wallet_id` is currently covered by an open stream.
    pub fn contains(&self, wallet_id: Uuid) -> bool {
        self.0.lock().map(|s| s.contains(&wallet_id)).unwrap_or(false)
    }

    fn insert(&self, wallet_id: Uuid) {
        if let Ok(mut s) = self.0.lock() {
            s.insert(wallet_id);
        }
    }

    fn remove(&self, wallet_id: Uuid) {
        if let Ok(mut s) = self.0.lock() {
            s.remove(&wallet_id);
        }
    }
}

/// The stream tasks owned by one leadership term.
pub(crate) struct StreamSet {
    live: LiveStreams,
    shutdown: CancellationToken,
    tasks: HashMap<Uuid, (CancellationToken, JoinHandle<()>)>,
}

impl StreamSet {
    pub(crate) fn new(live: LiveStreams, shutdown: &CancellationToken) -> Self {
        Self {
            live,
            shutdown: shutdown.child_token(),
            tasks: HashMap::new(),
        }
    }

    /// Start streams for newly opted-in wallets and stop streams for wallets that opted out.
    pub(crate) fn sync(&mut self, wanted: &[Wallet], make: impl Fn(&Wallet) -> Ingestor) {
        let wanted_ids: HashSet<Uuid> = wanted.iter().map(|w| w.id).collect();
        self.tasks.retain(|id, (token, handle)| {
            // A finished task (panic) is dropped here and restarted below on the same pass.
            let keep = wanted_ids.contains(id) && !handle.is_finished();
            if !keep {
                token.cancel();
            }
            keep
        });
        for w in wanted {
            if self.tasks.contains_key(&w.id) {
                continue;
            }
            let token = self.shutdown.child_token();
            let handle = tokio::spawn(run_stream(make(w), self.live.clone(), token.clone()));
            self.tasks.insert(w.id, (token, handle));
        }
    }

    /// Stop every stream; each finishes the record it is processing before exiting.
    pub(crate) async fn stop(self) {
        self.shutdown.cancel();
        for (id, (_, handle)) in self.tasks {
            let _ = handle.await;
            self.live.remove(id);
        }
    }
}

/// Keep one wallet's stream open until cancelled, reconnecting with bounded backoff.
async fn run_stream(ingestor: Ingestor, live: LiveStreams, shutdown: CancellationToken) {
    let wallet_id = ingestor.wallet_id;
    let mut unhealthy: u32 = 0;
    while !shutdown.is_cancelled() {
        let started = Instant::now();
        let outcome = ingestor.stream_session(&live, &shutdown).await;
        live.remove(wallet_id);
        if let Err(e) = &outcome {
            tracing::warn!(wallet = %wallet_id, error = ?e, "payment stream ended; polling covers it");
        }
        // Only a session that stayed up resets backoff, so flapping connects still slow down.
        if outcome.is_ok() && started.elapsed() >= HEALTHY_SESSION {
            unhealthy = 0;
        } else {
            unhealthy = unhealthy.saturating_add(1);
        }
        tokio::select! {
            () = tokio::time::sleep(reconnect_delay(unhealthy, wallet_id)) => {}
            () = shutdown.cancelled() => {}
        }
    }
    live.remove(wallet_id);
}

/// Exponential reconnect delay with up to 25% per-wallet jitter, capped at [`RECONNECT_MAX`].
pub(crate) fn reconnect_delay(unhealthy: u32, wallet_id: Uuid) -> Duration {
    let factor = 1u32.checked_shl(unhealthy.min(16)).unwrap_or(u32::MAX);
    let base = RECONNECT_BASE.saturating_mul(factor).min(RECONNECT_MAX);
    // Spread wallets apart so a Horizon restart does not reconnect every stream at once.
    let jitter_pct = (wallet_id.as_u128() % 26) as u32;
    (base + base * jitter_pct / 100).min(RECONNECT_MAX)
}

impl Ingestor {
    /// One stream session from the stored cursor; returns when the stream closes or goes idle.
    async fn stream_session(
        &self,
        live: &LiveStreams,
        shutdown: &CancellationToken,
    ) -> Result<(), IngestError> {
        // No cursor yet means no history was ingested; "0" replays from the start, never "now".
        let cursor = self
            .store
            .get_cursor(self.wallet_id)
            .await?
            .unwrap_or_else(|| "0".to_string());
        let mut stream = self
            .horizon
            .open_payment_stream(&self.account_g, &cursor)
            .await
            .map_err(|_| IngestError::Horizon)?;
        live.insert(self.wallet_id);
        self.record_poll_success();

        loop {
            let next = tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                next = tokio::time::timeout(STREAM_IDLE_TIMEOUT, stream.next_record()) => next,
            };
            let Ok(next) = next else { return Ok(()) };
            let Some(rec) = next.map_err(|_| IngestError::Horizon)? else {
                return Ok(());
            };
            // Same path and cursor discipline as polling: process, then persist the cursor.
            self.process(&rec).await?;
            self.store
                .set_cursor(self.wallet_id, &rec.paging_token)
                .await?;
            self.record_poll_success();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Consecutive failures grow the delay but never past the cap, whatever the count.
    #[test]
    fn reconnect_delay_backs_off_and_is_bounded() {
        let id = Uuid::nil();
        assert_eq!(reconnect_delay(0, id), RECONNECT_BASE);
        assert!(reconnect_delay(3, id) > reconnect_delay(2, id));
        for n in [10, 16, 17, u32::MAX] {
            assert!(reconnect_delay(n, Uuid::new_v4()) <= RECONNECT_MAX);
        }
    }
}
