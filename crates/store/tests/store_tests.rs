//! Integration tests for octo-store. Require a running Postgres.
//!
//! Run with: `docker compose up -d db` then `cargo test -p octo-store`.
//!
//! `DATABASE_URL` is read from the workspace `.env` automatically (via dotenvy), so the plain
//! `cargo test -p octo-store` works without exporting anything. If no URL can be found, the tests
//! print a clear SKIPPED message and pass (so a DB-less `cargo test` of the whole workspace is
//! green). If a URL is found but the DB is unreachable, the test fails loudly with the reason.

use octo_store::{NewDeposit, NewSponsoredTx, NewWallet, NewWithdrawal, Store, StoreError};
use std::sync::Once;
use uuid::Uuid;

static LOAD_ENV: Once = Once::new();

/// Resolve `DATABASE_URL`, loading the workspace `.env` first. Returns `None` only if no URL is
/// configured anywhere (in which case tests skip with a message).
fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        // Search upward from the crate dir for a .env (workspace root holds it).
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

async fn store() -> Option<Store> {
    let Some(url) = database_url() else {
        eprintln!(
            "SKIPPED: DATABASE_URL is not set (no .env found). \
             Run `docker compose up -d db` and ensure .env exists to run store tests."
        );
        return None;
    };
    let store = Store::connect(&url)
        .await
        .unwrap_or_else(|e| panic!("could not connect to {url}: {e}"));
    store.migrate().await.expect("migrate");
    Some(store)
}

/// Create a throwaway wallet with a unique account id (so tests don't collide).
async fn fresh_wallet(store: &Store) -> Uuid {
    let acct = format!("G{}", Uuid::new_v4().simple()); // unique, not a real strkey (fine for store tests)
    let w = store
        .create_wallet(NewWallet {
            network: "testnet",
            stellar_account_g: &acct,
            sealed_ciphertext: b"ciphertext",
            sealed_nonce: b"nonce12bytes",
            sealed_salt: b"saltsaltsaltsalt",
            sealed_scheme: 1,
            label: Some("test"),
            user_id: None,
            description: None,
        })
        .await
        .expect("create wallet");
    w.id
}

#[tokio::test]
async fn create_and_get_wallet() {
    let Some(store) = store().await else { return };
    let id = fresh_wallet(&store).await;
    let w = store.get_wallet(id).await.expect("get");
    assert_eq!(w.network, "testnet");
    assert_eq!(w.next_muxed_id, 1);
}

#[tokio::test]
async fn allocate_address_increments_atomically() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_wallet(&store).await;

    // muxed_address is globally unique in the schema (real ones encode the base account), so make
    // the test value unique per wallet too.
    let wid = wallet_id.simple();
    let a = store
        .allocate_address(
            wallet_id,
            |id| Ok(format!("M{wid}-{id}")),
            Some("user-a"),
            serde_json::json!({}),
        )
        .await
        .expect("alloc a");
    let b = store
        .allocate_address(
            wallet_id,
            |id| Ok(format!("M{wid}-{id}")),
            Some("user-b"),
            serde_json::json!({}),
        )
        .await
        .expect("alloc b");

    assert_eq!(a.muxed_id, 1);
    assert_eq!(b.muxed_id, 2);
    assert_ne!(a.muxed_address, b.muxed_address);

    let list = store.list_addresses(wallet_id).await.expect("list");
    assert_eq!(list.len(), 2);
}

#[tokio::test]
async fn record_deposit_is_idempotent() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_wallet(&store).await;
    let tx_hash = Uuid::new_v4().to_string();

    let dep = NewDeposit {
        wallet_id,
        address_id: None,
        asset_code: "native".into(),
        asset_issuer: None,
        amount_stroops: 10_000_000,
        source_account: Some("Gsender".into()),
        destination_account: Some("Gmaster".into()),
        stellar_tx_hash: tx_hash.clone(),
        operation_index: 0,
        horizon_op_id: format!("{tx_hash}-0"),
        ledger: Some(123),
        memo_id: None,
    };

    // First insert credits.
    let first = store.record_deposit(&dep).await.expect("first");
    assert!(first.is_some(), "first deposit must be recorded");

    // Replaying the SAME horizon_op_id must NOT double-credit.
    let second = store.record_deposit(&dep).await.expect("second");
    assert!(
        second.is_none(),
        "duplicate deposit must be a no-op (anti double-credit)"
    );

    let txs = store.list_transactions(wallet_id).await.expect("list");
    assert_eq!(txs.len(), 1, "exactly one ledger entry for one on-chain op");
}

#[tokio::test]
async fn different_op_index_same_tx_is_distinct() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_wallet(&store).await;
    let tx_hash = Uuid::new_v4().to_string();

    let base = NewDeposit {
        wallet_id,
        address_id: None,
        asset_code: "native".into(),
        asset_issuer: None,
        amount_stroops: 5,
        source_account: None,
        destination_account: None,
        stellar_tx_hash: tx_hash.clone(),
        operation_index: 0,
        horizon_op_id: format!("{tx_hash}-0"),
        ledger: None,
        memo_id: None,
    };
    let op1 = NewDeposit {
        operation_index: 1,
        horizon_op_id: format!("{tx_hash}-1"),
        ..base.clone()
    };

    assert!(store.record_deposit(&base).await.expect("op0").is_some());
    assert!(store.record_deposit(&op1).await.expect("op1").is_some());
    assert_eq!(store.list_transactions(wallet_id).await.unwrap().len(), 2);
}

#[tokio::test]
async fn withdrawal_idempotency_key_blocks_double_spend() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_wallet(&store).await;

    let mk = |key: &'static str| NewWithdrawal {
        wallet_id,
        idempotency_key: key,
        destination_account: "Gdest",
        asset_code: "native",
        asset_issuer: None,
        amount_stroops: 1_000,
        memo_id: None,
    };

    let first = store.create_withdrawal(mk("key-1")).await;
    assert!(first.is_ok(), "first withdrawal accepted");

    // Same idempotency key => conflict, not a second payout.
    let second = store.create_withdrawal(mk("key-1")).await;
    assert!(
        matches!(second, Err(StoreError::Conflict)),
        "retry must conflict"
    );

    // A different key is a different withdrawal.
    let third = store.create_withdrawal(mk("key-2")).await;
    assert!(third.is_ok());
}

/// Insert a minimal gas_sponsorship_configs row (no limits) for `wallet_id`.
async fn insert_sponsorship_config(store: &Store, wallet_id: Uuid) {
    sqlx::query("INSERT INTO gas_sponsorship_configs (wallet_id, enabled) VALUES ($1, true)")
        .bind(wallet_id)
        .execute(store.pool())
        .await
        .expect("insert gas_sponsorship_configs");
}

#[tokio::test]
async fn record_and_update_sponsored_tx() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_wallet(&store).await;
    insert_sponsorship_config(&store, wallet_id).await;

    let hash = format!("inner-{}", Uuid::new_v4().simple());
    let row = store
        .record_sponsored_tx(NewSponsoredTx {
            wallet_id,
            inner_tx_hash: &hash,
            fee_stroops: 500,
        })
        .await
        .expect("record");

    assert_eq!(row.wallet_id, wallet_id);
    assert_eq!(row.inner_tx_hash, hash);
    assert_eq!(row.fee_stroops, 500);
    assert_eq!(row.status, "pending");
    assert!(row.fee_bump_tx_hash.is_none());

    // Update to confirmed.
    let bump_hash = format!("bump-{}", Uuid::new_v4().simple());
    store
        .update_sponsored_tx_status(row.id, "confirmed", Some(&bump_hash), None)
        .await
        .expect("update");

    // Verify via pool (the store has no get_sponsored_tx yet; query directly).
    let updated: (String, Option<String>) =
        sqlx::query_as("SELECT status, fee_bump_tx_hash FROM sponsored_transactions WHERE id = $1")
            .bind(row.id)
            .fetch_one(store.pool())
            .await
            .expect("fetch updated");

    assert_eq!(updated.0, "confirmed");
    assert_eq!(updated.1.as_deref(), Some(bump_hash.as_str()));
}

#[tokio::test]
async fn sum_fees_today_counts_only_confirmed() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_wallet(&store).await;
    insert_sponsorship_config(&store, wallet_id).await;

    // No rows → 0.
    let initial = store
        .sum_sponsored_fees_today(wallet_id)
        .await
        .expect("sum");
    assert_eq!(initial, 0);

    // Insert a pending tx (fee 200): should not count.
    let pending = store
        .record_sponsored_tx(NewSponsoredTx {
            wallet_id,
            inner_tx_hash: &format!("pending-{}", Uuid::new_v4().simple()),
            fee_stroops: 200,
        })
        .await
        .expect("pending record");
    // Still 0 — pending doesn't count.
    assert_eq!(store.sum_sponsored_fees_today(wallet_id).await.unwrap(), 0);

    // Confirm the tx → now it counts.
    store
        .update_sponsored_tx_status(pending.id, "confirmed", None, None)
        .await
        .expect("update to confirmed");
    assert_eq!(
        store.sum_sponsored_fees_today(wallet_id).await.unwrap(),
        200
    );

    // A second confirmed tx adds to the total.
    let second = store
        .record_sponsored_tx(NewSponsoredTx {
            wallet_id,
            inner_tx_hash: &format!("second-{}", Uuid::new_v4().simple()),
            fee_stroops: 300,
        })
        .await
        .expect("second record");
    store
        .update_sponsored_tx_status(second.id, "confirmed", None, None)
        .await
        .unwrap();
    assert_eq!(
        store.sum_sponsored_fees_today(wallet_id).await.unwrap(),
        500
    );
}

#[tokio::test]
async fn duplicate_inner_tx_hash_is_conflict() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_wallet(&store).await;
    insert_sponsorship_config(&store, wallet_id).await;

    let hash = format!("dup-{}", Uuid::new_v4().simple());

    let first = store
        .record_sponsored_tx(NewSponsoredTx {
            wallet_id,
            inner_tx_hash: &hash,
            fee_stroops: 100,
        })
        .await;
    assert!(first.is_ok(), "first record must succeed");

    // Same inner_tx_hash → UNIQUE violation → Conflict.
    let second = store
        .record_sponsored_tx(NewSponsoredTx {
            wallet_id,
            inner_tx_hash: &hash,
            fee_stroops: 100,
        })
        .await;
    assert!(
        matches!(second, Err(StoreError::Conflict)),
        "duplicate inner_tx_hash must conflict, got: {second:?}"
    );
}

#[tokio::test]
async fn cursor_roundtrip() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_wallet(&store).await;

    assert_eq!(store.get_cursor(wallet_id).await.unwrap(), None);
    store.set_cursor(wallet_id, "token-1").await.unwrap();
    assert_eq!(
        store.get_cursor(wallet_id).await.unwrap().as_deref(),
        Some("token-1")
    );
    // Upsert overwrites.
    store.set_cursor(wallet_id, "token-2").await.unwrap();
    assert_eq!(
        store.get_cursor(wallet_id).await.unwrap().as_deref(),
        Some("token-2")
    );
}

#[tokio::test]
async fn migrate_is_idempotent_when_run_twice() {
    let Some(store) = store().await else { return };
    // `store()` already ran migrate() once during setup; running it again against the same
    // already-migrated database mirrors a server restart (bin/server/src/main.rs calls
    // store.migrate().await on every boot) and must be a safe no-op, not an error.
    store
        .migrate()
        .await
        .expect("second migrate() call must succeed with no error");
}

#[tokio::test]
async fn migrate_applies_exactly_the_expected_version_set() {
    let Some(store) = store().await else { return };

    let mut versions: Vec<i64> = sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE success = true ORDER BY version",
    )
    .fetch_all(store.pool())
    .await
    .expect("query _sqlx_migrations");
    versions.sort_unstable();

    // One version per file under crates/store/migrations/ (0001_init.sql .. 0007_gas_sponsorship.sql).
    assert_eq!(
        versions,
        vec![1, 2, 3, 4, 5, 6, 7],
        "expected exactly the seven known migrations to be recorded as applied"
    );
}

#[tokio::test]
async fn upsert_gas_sponsorship_config_works() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_wallet(&store).await;
    let cfg = store
        .upsert_gas_sponsorship_config(wallet_id, true, Some(500_000), Some(10_000_000))
        .await
        .expect("upsert");
    assert!(cfg.enabled);
    let spent = store
        .sum_sponsored_fees_reserved_today(wallet_id)
        .await
        .expect("sum");
    assert_eq!(spent, 0);
}

// ---------------------------------------------------------------------------
// reseal_wallet / list_wallets_needing_reseal — batch migration (#132)
// ---------------------------------------------------------------------------

/// Helper: insert a wallet row whose scheme is set to a specific value directly via raw SQL
/// so we can simulate pre-migration rows (scheme = 0) without going through `create_wallet`
/// (which always writes scheme = 1).
async fn insert_wallet_with_scheme(store: &Store, scheme: i16) -> Uuid {
    let acct = format!("G{}", Uuid::new_v4().simple());
    let id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO wallets
            (network, stellar_account_g, sealed_ciphertext, sealed_nonce, sealed_salt,
             sealed_scheme, label)
        VALUES ('testnet', $1, $2, $3, $4, $5, 'migration-test')
        RETURNING id
        "#,
    )
    .bind(&acct)
    .bind(b"ciphertext".as_ref())
    .bind(b"nonce12bytes".as_ref())
    .bind(b"saltsaltsaltsalt".as_ref())
    .bind(scheme)
    .fetch_one(store.pool())
    .await
    .expect("insert wallet with scheme");
    id
}

/// `list_wallets_needing_reseal` returns only wallets whose scheme differs from the target,
/// and is correctly filtered by the `after_id` cursor for resumable iteration.
#[tokio::test]
async fn list_wallets_needing_reseal_returns_only_non_target_scheme() {
    let Some(store) = store().await else { return };

    // Insert 3 wallets: two at scheme 0 (legacy sentinel) and one at scheme 1 (already migrated).
    let id_a = insert_wallet_with_scheme(&store, 0).await;
    let id_b = insert_wallet_with_scheme(&store, 0).await;
    let _id_c = insert_wallet_with_scheme(&store, 1).await;

    // list_wallets_needing_reseal(target=1) should only return a and b.
    let needs_migration = store
        .list_wallets_needing_reseal(1, 100, None)
        .await
        .expect("list_wallets_needing_reseal");

    let ids: Vec<Uuid> = needs_migration.iter().map(|w| w.id).collect();
    assert!(ids.contains(&id_a), "wallet with scheme 0 must appear");
    assert!(ids.contains(&id_b), "wallet with scheme 0 must appear");
    for w in &needs_migration {
        assert_ne!(w.sealed_scheme, 1, "must not include already-migrated rows");
    }
}

/// `reseal_wallet` atomically swaps the sealed bytes and updates the scheme tag.
/// A second call with the same `expected_old_scheme` is a safe no-op (idempotency guard).
#[tokio::test]
async fn reseal_wallet_updates_scheme_and_is_idempotent() {
    let Some(store) = store().await else { return };

    let wallet_id = insert_wallet_with_scheme(&store, 0).await;

    // Simulate a reseal: write new (fake) ciphertext and bump scheme to 1.
    let updated = store
        .reseal_wallet(
            wallet_id,
            b"new-ciphertext",
            b"newnonce12by",
            b"newsaltnewsaltnewsaltnewsaltnews",
            1,   // new scheme
            0,   // expected old scheme
        )
        .await
        .expect("reseal_wallet");
    assert!(updated, "first reseal must update the row");

    // Verify the stored values changed.
    let row: (Vec<u8>, i16) =
        sqlx::query_as("SELECT sealed_ciphertext, sealed_scheme FROM wallets WHERE id = $1")
            .bind(wallet_id)
            .fetch_one(store.pool())
            .await
            .expect("fetch row");
    assert_eq!(row.0, b"new-ciphertext", "ciphertext must be updated");
    assert_eq!(row.1, 1i16, "scheme must be updated to 1");

    // A second call claiming the row is still at scheme 0 must be a no-op (row is now at 1).
    let second = store
        .reseal_wallet(
            wallet_id,
            b"should-not-overwrite",
            b"newnonce12by",
            b"newsaltnewsaltnewsaltnewsaltnews",
            1,
            0, // wrong expected_old_scheme → WHERE clause won't match
        )
        .await
        .expect("second reseal call");
    assert!(!second, "second reseal with stale expected_old_scheme must be a no-op");

    // Ciphertext is still the first update's value.
    let row2: (Vec<u8>,) =
        sqlx::query_as("SELECT sealed_ciphertext FROM wallets WHERE id = $1")
            .bind(wallet_id)
            .fetch_one(store.pool())
            .await
            .expect("fetch row2");
    assert_eq!(row2.0, b"new-ciphertext", "no-op must not overwrite ciphertext");
}

/// Full migration backfill scenario: seed several wallets at scheme 0, run the batch in
/// sub-batches (simulating an interrupted run), verify the second run completes the rest
/// without re-sealing already-migrated rows.
#[tokio::test]
async fn batch_reseal_is_resumable_and_does_not_double_reseal() {
    let Some(store) = store().await else { return };

    // Seed 5 wallets at scheme 0.
    let mut wallet_ids = Vec::new();
    for _ in 0..5 {
        wallet_ids.push(insert_wallet_with_scheme(&store, 0).await);
    }

    // --- First pass: process only the first 2 wallets (simulates interruption). ---
    let first_batch = store
        .list_wallets_needing_reseal(1, 2, None)
        .await
        .expect("first batch");
    assert_eq!(first_batch.len(), 2, "first batch must return 2 rows");

    let mut reseal_count_pass1 = 0usize;
    for w in &first_batch {
        let updated = store
            .reseal_wallet(
                w.id,
                b"migrated-ciphertext",
                b"newnonce12by",
                b"newsaltnewsaltnewsaltnewsaltnews",
                1,
                0,
            )
            .await
            .expect("reseal pass 1");
        if updated {
            reseal_count_pass1 += 1;
        }
    }
    assert_eq!(reseal_count_pass1, 2, "both rows in first batch must be updated");

    // --- Second pass: resume from after the last processed wallet. ---
    let last_processed = first_batch.last().unwrap().id;
    let second_batch = store
        .list_wallets_needing_reseal(1, 100, Some(last_processed))
        .await
        .expect("second batch");

    // Must return the remaining 3 wallets (those still at scheme 0 with id > last_processed).
    assert!(
        !second_batch.is_empty(),
        "second batch must return the remaining un-migrated wallets"
    );
    for w in &second_batch {
        assert_ne!(
            w.sealed_scheme, 1,
            "second batch must not include already-migrated rows"
        );
    }

    let mut reseal_count_pass2 = 0usize;
    for w in &second_batch {
        let updated = store
            .reseal_wallet(
                w.id,
                b"migrated-ciphertext",
                b"newnonce12by",
                b"newsaltnewsaltnewsaltnewsaltnews",
                1,
                0,
            )
            .await
            .expect("reseal pass 2");
        if updated {
            reseal_count_pass2 += 1;
        }
    }
    assert!(reseal_count_pass2 > 0, "second pass must migrate remaining wallets");

    // --- Verify: no wallets remain at scheme 0 for the IDs we inserted. ---
    let remaining = store
        .list_wallets_needing_reseal(1, 100, None)
        .await
        .expect("final check");
    for w in &remaining {
        assert!(
            !wallet_ids.contains(&w.id),
            "wallet {} should have been migrated but still shows scheme {}",
            w.id, w.sealed_scheme
        );
    }
}
