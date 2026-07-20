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
            sealed_scheme: 1, // octo_crypto::SCHEME_V1
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

    let list = store.list_addresses(wallet_id, 100, None).await.expect("list");
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

    let txs = store.list_transactions(wallet_id, 100, None).await.expect("list");
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
    assert_eq!(store.list_transactions(wallet_id, 100, None).await.unwrap().len(), 2);
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

/// Create a throwaway user with a unique email (so tests don't collide).
async fn fresh_user(store: &Store) -> Uuid {
    let email = format!("test-{}@example.invalid", Uuid::new_v4().simple());
    store
        .create_user(&email, "not-a-real-hash")
        .await
        .expect("create user")
        .id
}

// --- indexing-overhaul correctness regressions (hard/store/indexing-overhaul-with-load-test) ---
//
// These assert result *correctness* (ordering, filtering) for the query shapes the new indices in
// migrations/0008_sponsored_and_audit_indexing.sql target. An index change must never change which
// rows come back or in what order — if either of these starts failing, the index migration altered
// query semantics, not just performance, and that's a bug in the migration.

#[tokio::test]
async fn list_sponsored_transactions_orders_filters_and_paginates_correctly() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_wallet(&store).await;
    insert_sponsorship_config(&store, wallet_id).await;

    // Three rows, two different statuses, with `created_at` pinned to strictly increasing values
    // (rather than relying on wall-clock ordering, which is too coarse to guarantee distinct
    // timestamps for back-to-back inserts and would make the ORDER BY assertions flaky).
    let mut ids = Vec::new();
    for (i, (label, status)) in [("a", "pending"), ("b", "confirmed"), ("c", "confirmed")]
        .into_iter()
        .enumerate()
    {
        let row = store
            .record_sponsored_tx(NewSponsoredTx {
                wallet_id,
                inner_tx_hash: &format!("order-{label}-{}", Uuid::new_v4().simple()),
                fee_stroops: 100,
            })
            .await
            .expect("record");
        if status == "confirmed" {
            store
                .update_sponsored_tx_status(row.id, "confirmed", None, None)
                .await
                .expect("confirm");
        }
        sqlx::query("UPDATE sponsored_transactions SET created_at = now() - make_interval(secs => $2) WHERE id = $1")
            .bind(row.id)
            .bind((10 - i) as f64)
            .execute(store.pool())
            .await
            .expect("pin created_at");
        ids.push(row.id);
    }

    // Unfiltered: most-recent-first (created_at DESC, id DESC — insertion order reversed).
    let all = store
        .list_sponsored_transactions(wallet_id, 10, None, None)
        .await
        .expect("list all");
    let all_ids: Vec<Uuid> = all.iter().map(|r| r.id).collect();
    assert_eq!(all_ids, vec![ids[2], ids[1], ids[0]]);

    // Status filter: only the two confirmed rows, same relative order.
    let confirmed = store
        .list_sponsored_transactions(wallet_id, 10, Some("confirmed"), None)
        .await
        .expect("list confirmed");
    let confirmed_ids: Vec<Uuid> = confirmed.iter().map(|r| r.id).collect();
    assert_eq!(confirmed_ids, vec![ids[2], ids[1]]);

    // Cursor pagination: page of 1 starting after the newest row returns the next one down.
    let page = store
        .list_sponsored_transactions(wallet_id, 1, None, Some(ids[2]))
        .await
        .expect("list after cursor");
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].id, ids[1]);
}

#[tokio::test]
async fn list_audit_logs_filters_by_category_and_search_correctly() {
    let Some(store) = store().await else { return };
    let user_id = fresh_user(&store).await;

    store
        .record_audit(
            user_id,
            "signed in",
            "authentication",
            None,
            Some("203.0.113.1"),
        )
        .await
        .expect("record 1");
    store
        .record_audit(
            user_id,
            "created wallet octo master wallet",
            "wallet",
            Some("octo master wallet"),
            None,
        )
        .await
        .expect("record 2");
    store
        .record_audit(user_id, "rotated api key", "credentials", None, None)
        .await
        .expect("record 3");

    // Pin `created_at` to strictly increasing values in insertion order (see the sponsored-tx test
    // above for why wall-clock ordering alone isn't reliable enough for the ORDER BY assertions).
    for (offset_secs, action) in [
        (10.0, "signed in"),
        (9.0, "created wallet octo master wallet"),
        (8.0, "rotated api key"),
    ] {
        sqlx::query(
            "UPDATE audit_logs SET created_at = now() - make_interval(secs => $2) \
             WHERE user_id = $1 AND action = $3",
        )
        .bind(user_id)
        .bind(offset_secs)
        .bind(action)
        .execute(store.pool())
        .await
        .expect("pin created_at");
    }

    // Category filter: only the "wallet" row.
    let by_category = store
        .list_audit_logs(user_id, Some("wallet"), None, 10)
        .await
        .expect("list by category");
    assert_eq!(by_category.len(), 1);
    assert_eq!(by_category[0].category, "wallet");

    // Search filter (the ILIKE / trigram-index case): matches action OR target, case-insensitive.
    let by_search = store
        .list_audit_logs(user_id, None, Some("MASTER"), 10)
        .await
        .expect("list by search");
    assert_eq!(by_search.len(), 1);
    assert_eq!(by_search[0].action, "created wallet octo master wallet");

    // No match.
    let no_match = store
        .list_audit_logs(user_id, None, Some("nonexistent-term"), 10)
        .await
        .expect("list no match");
    assert!(no_match.is_empty());

    // Unfiltered: all three, most-recent-first.
    let all = store
        .list_audit_logs(user_id, None, None, 10)
        .await
        .expect("list all");
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].action, "rotated api key");
}
