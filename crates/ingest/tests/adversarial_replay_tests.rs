//! Adversarial reorg/replay simulation harness for the ingest pipeline (issue #129). Requires a
//! real Postgres via `DATABASE_URL` (loaded from `.env`), same skip-if-unset convention as
//! `process_tests.rs`.
//!
//! ## Investigation: what does a "reorg" actually mean for this ingestion method?
//!
//! This was investigated first, as a deliverable in its own right, before writing any harness
//! code — the ticket explicitly asked for the finding to be documented rather than assumed away.
//!
//! **Finding: classic reorg-reversal is not observable through this ingestion method, and that is
//! not a gap in this design — it follows from how Stellar's consensus actually works.**
//!
//! Stellar does not use probabilistic-finality, longest-chain consensus (the PoW/PoS model where
//! a block can be orphaned/replaced after the fact, which is what "reorg" usually means). It uses
//! the Stellar Consensus Protocol (SCP), a federated Byzantine agreement protocol with
//! **deterministic, single-round finality**: once a ledger closes, it is final — there is no
//! notion of a competing, longer alternative history that later displaces it. A transaction's
//! operations are assigned a permanent, deterministic id (the TOID — ledger sequence + tx index +
//! operation index) at the moment the ledger that contains them closes, and that id, along with
//! the ledger's contents, never changes afterward.
//!
//! Concretely, for `crates/ingest`'s polling loop against Horizon's `/accounts/{id}/payments`:
//! - `transaction_successful` is set once, permanently, when the containing ledger closes.
//!   Horizon has no mechanism to retroactively flip a previously-`true` record to `false` for the
//!   same operation id, because that would require rewriting already-closed ledger history, which
//!   the protocol does not allow.
//! - The operation id (`rec.id`, this codebase's dedup key via `horizon_op_id`) is derived
//!   deterministically from the closed ledger and is stable forever once assigned.
//! - Horizon operators do occasionally **reingest** ledger ranges (e.g. after a Horizon software
//!   upgrade or to repair its own index), which can cause a payment to be transiently
//!   missing/reappearing from the `/payments` view during the reingest window, or cause a
//!   worker resuming from a stale cursor to see records again — but it cannot change a
//!   record's `id` or its `transaction_successful` value, because Horizon is re-deriving the same
//!   view of the same already-final ledger data, not producing a different history.
//!
//! So the only adversarial conditions actually reachable through `Ingestor::process`/`poll_once`
//! are **duplicate delivery** and **out-of-order delivery** of already-final, genuinely-identical
//! payment records — a delivery-layer problem (network retries, worker crash-restart from an
//! older cursor, manual backfill/replay), not a consensus-layer reversal. This harness simulates
//! exactly that: large randomized sequences of duplicated/reordered but internally-consistent
//! records, and proves the resulting `transactions` table is invariant to delivery pattern.
//!
//! **Is this an acceptable risk, or worth a follow-up design conversation?** Acceptable, for
//! Stellar specifically: the design's actual exposure (duplicate/out-of-order delivery of final
//! data) is exactly what's defended against today via idempotent dedup on `horizon_op_id` plus
//! cursor-based resume, and this harness now proves that defense holds under adversarial
//! delivery patterns rather than merely asserting it does. The one thing worth a **follow-up**
//! design note, not a fix here: if octo ever ingests a chain with probabilistic finality (e.g. an
//! EVM-chain sidecar) alongside Stellar, that integration would need genuine reorg-reversal
//! handling (an "unconfirm" path), which nothing in this codebase provides today — because
//! nothing here has ever needed it for Stellar.

use octo_ingest::horizon::PaymentRecord;
use octo_ingest::Ingestor;
use octo_store::{NewWallet, Store, Transaction};
use octo_wallet_core::encode_muxed;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;
use std::collections::{BTreeSet, HashMap};
use std::sync::Once;
use uuid::Uuid;

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

const BASE: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";

/// Number of randomized property-test cases to run. Each case does several real Postgres
/// round-trips, so this is kept modest by default to keep normal CI fast. Override with
/// `INGEST_FUZZ_CASES` for a larger local or manually-triggered/nightly run — there is no nightly
/// workflow in this repo yet, so this env var is the seam for one when that's set up.
fn fuzz_case_count() -> u32 {
    std::env::var("INGEST_FUZZ_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(40)
}

/// A fresh wallet + `Ingestor` targeting it, isolated per test case so cases never interact.
async fn fresh_ingestor(store: &Store) -> (Ingestor, Uuid) {
    let wallet = store
        .create_wallet(NewWallet {
            network: "testnet",
            stellar_account_g: &format!("{BASE}-{}", Uuid::new_v4().simple()),
            sealed_ciphertext: b"ct",
            sealed_nonce: b"nonce",
            sealed_salt: b"salt",
            label: None,
            user_id: None,
            description: None,
        })
        .await
        .expect("create wallet");
    let ingestor = Ingestor::new(store.clone(), "http://unused", wallet.id, BASE.to_string());
    (ingestor, wallet.id)
}

/// Build `n` genuinely-distinct payment records, each attributed to its own fresh customer
/// address, with a unique `horizon_op_id` and a distinct amount ((index+1) XLM) so a test can
/// verify not just presence but *which* record ended up recorded (catches cross-record
/// corruption, not just duplicate/missing counts).
async fn build_pool(store: &Store, wallet_id: Uuid, n: usize) -> Vec<PaymentRecord> {
    let mut pool = Vec::with_capacity(n);
    for i in 0..n {
        let addr = store
            .allocate_address(
                wallet_id,
                |id| encode_muxed(BASE, id as u64).map_err(|_| ()),
                Some(&format!("cust-{i}")),
                serde_json::json!({}),
            )
            .await
            .expect("allocate address");

        pool.push(PaymentRecord {
            id: format!("op-{wallet_id}-{i}"),
            paging_token: format!("op-{wallet_id}-{i}"),
            kind: "payment".into(),
            transaction_hash: Some(format!("hash-{wallet_id}-{i}")),
            transaction_successful: true,
            from: Some("Gsender".into()),
            to: Some(BASE.into()),
            to_muxed: Some(addr.muxed_address.clone()),
            to_muxed_id: None,
            asset_type: Some("native".into()),
            asset_code: None,
            asset_issuer: None,
            amount: Some(format!("{}.0000000", i + 1)),
            starting_balance: None,
            transaction: None,
        });
    }
    pool
}

/// The stroops amount `build_pool` assigned to `pool[i]`.
fn expected_stroops(i: usize) -> i64 {
    (i as i64 + 1) * 10_000_000
}

/// Feed `sequence` (indices into `pool`) through `ingestor.process`, one at a time, in order —
/// simulating an arbitrary duplicated/reordered delivery pattern.
async fn deliver(ingestor: &Ingestor, pool: &[PaymentRecord], sequence: &[usize]) {
    for &idx in sequence {
        ingestor
            .process(&pool[idx])
            .await
            .unwrap_or_else(|e| panic!("process must not error on a well-formed record: {e:?}"));
    }
}

/// The core invariant: after delivering `sequence` in whatever order/duplication it specifies,
/// the DB must hold **exactly one row per distinct index that appeared**, each carrying that
/// index's canonical amount. No double-credits (row count doesn't exceed distinct-index count),
/// no missing deposits (row count isn't less), no data corruption (amounts match).
async fn assert_exactly_distinct_recorded(
    store: &Store,
    wallet_id: Uuid,
    pool: &[PaymentRecord],
    sequence: &[usize],
) {
    let distinct: BTreeSet<usize> = sequence.iter().copied().collect();
    let txs = store.list_transactions(wallet_id).await.expect("list");
    assert_eq!(
        txs.len(),
        distinct.len(),
        "row count must equal the number of distinct ops delivered; sequence={sequence:?}"
    );

    let by_op_id: HashMap<&str, &Transaction> = txs
        .iter()
        .filter_map(|t| t.horizon_op_id.as_deref().map(|id| (id, t)))
        .collect();

    for &idx in &distinct {
        let op_id = pool[idx].id.as_str();
        let row = by_op_id.get(op_id).unwrap_or_else(|| {
            panic!("missing row for pool[{idx}] (op_id={op_id}); sequence={sequence:?}")
        });
        assert_eq!(
            row.amount_stroops,
            expected_stroops(idx),
            "wrong amount recorded for pool[{idx}] (op_id={op_id}) — possible cross-record data corruption"
        );
    }
}

// --- the core randomized property test ------------------------------------------------------

/// Generates `(pool_size, delivery_sequence)`: a small pool of genuinely-distinct on-chain
/// operations (2 to 6, to keep each case's DB work bounded) and a delivery sequence of indices
/// into that pool, 1 to 4x the pool size long, with arbitrary repeats and arbitrary order — i.e.
/// duplicate delivery, out-of-order delivery, or both, combined arbitrarily.
fn sequence_strategy() -> impl Strategy<Value = (usize, Vec<usize>)> {
    (2usize..=6).prop_flat_map(|pool_size| {
        proptest::collection::vec(0..pool_size, pool_size..=(pool_size * 4))
            .prop_map(move |seq| (pool_size, seq))
    })
}

#[tokio::test]
async fn randomized_delivery_sequences_never_produce_duplicate_or_missing_deposits() {
    let Some(url) = database_url() else {
        eprintln!("SKIPPED: set DATABASE_URL (start `docker compose up -d db`)");
        return;
    };
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");

    let strategy = sequence_strategy();
    let mut runner = TestRunner::default();
    let cases = fuzz_case_count();

    for case in 0..cases {
        let (pool_size, sequence) = strategy
            .new_tree(&mut runner)
            .expect("generate case")
            .current();

        let (ingestor, wallet_id) = fresh_ingestor(&store).await;
        let pool = build_pool(&store, wallet_id, pool_size).await;

        deliver(&ingestor, &pool, &sequence).await;
        // Deliver the same sequence a second time in full — an adversarial "replay the whole
        // batch again" on top of whatever duplication/reordering the sequence already contains.
        deliver(&ingestor, &pool, &sequence).await;

        assert_exactly_distinct_recorded(&store, wallet_id, &pool, &sequence).await;
        // Sanity: fail loudly (not silently) if a future change breaks case generation itself.
        assert!(
            !sequence.is_empty(),
            "case {case} generated an empty sequence — generator bug"
        );
    }
}

// --- hand-picked, previously-problematic-in-other-systems regression sequences --------------

#[tokio::test]
async fn same_event_delivered_thrice_then_again_after_ten_unrelated_events() {
    let Some(url) = database_url() else {
        return;
    };
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    let (ingestor, wallet_id) = fresh_ingestor(&store).await;

    // Index 0 is the target that gets redelivered; 1..=10 are ten unrelated operations.
    let pool = build_pool(&store, wallet_id, 11).await;
    let mut sequence = vec![0, 0, 0]; // delivered 3 times consecutively
    sequence.extend(1..=10); // ten unrelated events in between
    sequence.push(0); // delivered again after the unrelated events

    deliver(&ingestor, &pool, &sequence).await;
    assert_exactly_distinct_recorded(&store, wallet_id, &pool, &sequence).await;
}

#[tokio::test]
async fn fully_reversed_delivery_order_of_distinct_operations_still_records_each_once() {
    let Some(url) = database_url() else {
        return;
    };
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    let (ingestor, wallet_id) = fresh_ingestor(&store).await;

    let pool = build_pool(&store, wallet_id, 8).await;
    let sequence: Vec<usize> = (0..8).rev().collect();

    deliver(&ingestor, &pool, &sequence).await;
    assert_exactly_distinct_recorded(&store, wallet_id, &pool, &sequence).await;
}

#[tokio::test]
async fn interleaved_shuffle_of_two_full_page_replays_is_idempotent() {
    let Some(url) = database_url() else {
        return;
    };
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    let (ingestor, wallet_id) = fresh_ingestor(&store).await;

    // Simulates a worker crash-restarting from a stale cursor: the same "page" of 6 operations
    // delivered twice, but not as two clean back-to-back passes — interleaved, as a crash/retry
    // in the middle of a page could plausibly produce.
    let pool = build_pool(&store, wallet_id, 6).await;
    let sequence = vec![0, 1, 2, 0, 3, 1, 4, 2, 5, 3, 4, 5];

    deliver(&ingestor, &pool, &sequence).await;
    assert_exactly_distinct_recorded(&store, wallet_id, &pool, &sequence).await;
}

#[tokio::test]
async fn single_operation_delivered_twenty_times_records_once() {
    let Some(url) = database_url() else {
        return;
    };
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    let (ingestor, wallet_id) = fresh_ingestor(&store).await;

    let pool = build_pool(&store, wallet_id, 1).await;
    let sequence = vec![0usize; 20];

    deliver(&ingestor, &pool, &sequence).await;
    assert_exactly_distinct_recorded(&store, wallet_id, &pool, &sequence).await;
}
