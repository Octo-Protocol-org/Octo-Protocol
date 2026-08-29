//! Integration tests for octo-store. Require a running Postgres.
//!
//! Run with: `docker compose up -d db` then `cargo test -p octo-store`.
//!
//! `DATABASE_URL` is read from the workspace `.env` automatically (via dotenvy), so the plain
//! `cargo test -p octo-store` works without exporting anything. If no URL can be found, the tests
//! print a clear SKIPPED message and pass (so a DB-less `cargo test` of the whole workspace is
//! green). If a URL is found but the DB is unreachable, the test fails loudly with the reason.

use octo_store::{
    NewDeposit, NewEvmDeposit, NewEvmWallet, NewPaymentLink, NewSponsoredTx, NewWallet,
    NewWithdrawal, Store, StoreError,
};
use sqlx::Connection;
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
    fresh_wallet_on_network(store, "testnet").await
}

/// Like [`fresh_wallet`], but on a caller-chosen `network` — used by tests that need two wallets
/// on two different chains (`network` drives `chain_id` via
/// `octo_store::stellar_chain_id_for_network`).
async fn fresh_wallet_on_network(store: &Store, network: &'static str) -> Uuid {
    let acct = format!("G{}", Uuid::new_v4().simple()); // unique, not a real strkey (fine for store tests)
    let w = store
        .create_wallet(NewWallet {
            network,
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
    assert_eq!(
        w.chain_id, "stellar:testnet",
        "chain_id must be derived from network"
    );
}

#[tokio::test]
async fn create_wallet_maps_mainnet_network_to_the_pubnet_chain_id() {
    let Some(store) = store().await else { return };
    let id = fresh_wallet_on_network(&store, "mainnet").await;
    let w = store.get_wallet(id).await.expect("get");
    assert_eq!(w.network, "mainnet");
    assert_eq!(w.chain_id, "stellar:pubnet");
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

    assert_eq!(a.muxed_id, Some(1));
    assert_eq!(b.muxed_id, Some(2));
    assert_ne!(a.muxed_address, b.muxed_address);
    assert_eq!(a.chain_id, "stellar:testnet");
    assert_eq!(
        a.deposit_address, a.muxed_address,
        "deposit_address must mirror muxed_address for Stellar rows"
    );
    assert_eq!(a.derivation_index, None, "Stellar rows don't use this");

    let list = store
        .list_addresses(wallet_id, 100, None)
        .await
        .expect("list");
    assert_eq!(list.len(), 2);
}

// --- EVM deposit addresses (issue #220) ------------------------------------------------------
//
// These tests deliberately do NOT depend on octo-evm-core (store never depends on wallet-core
// either — see fresh_wallet's fake muxed encoding above), so the derive closure just returns a
// fake-but-validly-shaped `0x...` string. Real BIP-44/EIP-55 correctness is covered in
// crates/evm-core's own test suite (BIP-32 spec vectors, EIP-55 spec vectors, and cross-checks
// against an independent implementation); what belongs here is the STORE's contract: atomic
// index allocation and case-insensitive lookup.

/// Create a throwaway EVM wallet with a unique identity address (so tests don't collide).
async fn fresh_evm_wallet(store: &Store) -> Uuid {
    fresh_evm_wallet_with_depth(store, 6).await
}

/// Like [`fresh_evm_wallet`], with an explicit confirmation depth (rewind bound defaults to 2x,
/// the issue's suggested default) — for tests that exercise confirmation/reorg behavior.
async fn fresh_evm_wallet_with_depth(store: &Store, confirmation_depth: i32) -> Uuid {
    let identity = format!("0x{:040x}", Uuid::new_v4().as_u128());
    let w = store
        .create_evm_wallet(NewEvmWallet {
            network: "testnet",
            chain_id: "eip155:31337", // anvil's default chain id
            identity_address: &identity,
            sealed_ciphertext: b"ciphertext",
            sealed_nonce: b"nonce12bytes",
            sealed_salt: b"saltsaltsaltsalt",
            sealed_scheme: 1,
            confirmation_depth,
            reorg_rewind_bound: confirmation_depth * 2,
            label: Some("test-evm"),
            user_id: None,
            description: None,
        })
        .await
        .expect("create evm wallet");
    w.id
}

/// A fake-but-validly-shaped EIP-55-style address for a given index, unique per (wallet, index)
/// via a random prefix — good enough for exercising store-level allocation/lookup, not real
/// derivation.
fn fake_evm_address(salt: u128, index: u32) -> String {
    format!("0x{salt:032x}{index:08x}")
}

#[tokio::test]
async fn allocate_evm_address_increments_atomically() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_evm_wallet(&store).await;
    let salt = Uuid::new_v4().as_u128();

    let a = store
        .allocate_evm_address(
            wallet_id,
            |index| Ok(fake_evm_address(salt, index)),
            Some("user-a"),
            serde_json::json!({}),
        )
        .await
        .expect("alloc a");
    let b = store
        .allocate_evm_address(
            wallet_id,
            |index| Ok(fake_evm_address(salt, index)),
            Some("user-b"),
            serde_json::json!({}),
        )
        .await
        .expect("alloc b");

    assert_eq!(a.derivation_index, Some(0));
    assert_eq!(b.derivation_index, Some(1));
    assert_ne!(a.evm_address, b.evm_address);
    // The EVM shape, not the Stellar shape.
    assert_eq!(a.muxed_id, None);
    assert_eq!(a.muxed_address, None);

    let list = store
        .list_addresses(wallet_id, 100, None)
        .await
        .expect("list");
    assert_eq!(list.len(), 2);
}

/// N concurrent allocations on ONE evm wallet must yield N distinct, gap-free indexes and N
/// distinct addresses — the atomicity guarantee `allocate_address` already gives Stellar, carried
/// over to the EVM sibling. Modeled on the row-lock pattern exercised by
/// `crates/ingest/tests/supervisor_concurrency_tests.rs`.
#[tokio::test]
async fn allocate_evm_address_concurrent_allocations_are_gap_free_and_unique() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_evm_wallet(&store).await;
    let salt = Uuid::new_v4().as_u128();

    const N: usize = 25;
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let store = store.clone();
        handles.push(tokio::spawn(async move {
            store
                .allocate_evm_address(
                    wallet_id,
                    move |index| Ok(fake_evm_address(salt, index)),
                    None,
                    serde_json::json!({}),
                )
                .await
                .expect("concurrent alloc")
        }));
    }

    let mut indexes: Vec<i64> = Vec::with_capacity(N);
    let mut addresses = std::collections::HashSet::with_capacity(N);
    for h in handles {
        let addr = h.await.expect("task join");
        indexes.push(addr.derivation_index.expect("evm address"));
        addresses.insert(addr.evm_address.expect("evm address"));
    }

    indexes.sort_unstable();
    let expected: Vec<i64> = (0..N as i64).collect();
    assert_eq!(
        indexes, expected,
        "expected exactly 0..{N} with no gaps or duplicates"
    );
    assert_eq!(addresses.len(), N, "expected N distinct addresses");
}

/// Looking up a deposit address by its lowercase, uppercase, and original-cased forms all
/// resolve to the same row (the `evm_address_lower` generated column backs this).
#[tokio::test]
async fn evm_address_lookup_is_case_insensitive() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_evm_wallet(&store).await;
    let salt = Uuid::new_v4().as_u128();

    let allocated = store
        .allocate_evm_address(
            wallet_id,
            |index| Ok(fake_evm_address(salt, index)),
            None,
            serde_json::json!({}),
        )
        .await
        .expect("alloc");
    let original = allocated.evm_address.clone().expect("evm address");

    let by_lower = store
        .address_by_evm_address(&original.to_ascii_lowercase())
        .await
        .expect("lookup lower")
        .expect("found by lowercase");
    let by_upper = store
        .address_by_evm_address(&original.to_ascii_uppercase())
        .await
        .expect("lookup upper")
        .expect("found by uppercase");
    let by_original = store
        .address_by_evm_address(&original)
        .await
        .expect("lookup original")
        .expect("found by original casing");

    assert_eq!(by_lower.id, allocated.id);
    assert_eq!(by_upper.id, allocated.id);
    assert_eq!(by_original.id, allocated.id);
}

/// A Stellar wallet's allocation behaviour is completely unchanged by any of the above: it still
/// gets muxed_id/muxed_address, never touches the EVM columns, and defaults to chain_kind =
/// "stellar".
#[tokio::test]
async fn stellar_wallet_allocation_is_unaffected_by_evm_support() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_wallet(&store).await;
    let wallet = store.get_wallet(wallet_id).await.expect("get wallet");
    assert_eq!(wallet.chain_kind, "stellar");
    assert_eq!(wallet.chain_id, None);
    assert!(!wallet.is_evm());

    let wid = wallet_id.simple();
    let addr = store
        .allocate_address(
            wallet_id,
            |id| Ok(format!("M{wid}-{id}")),
            Some("user-a"),
            serde_json::json!({}),
        )
        .await
        .expect("alloc");

    assert_eq!(addr.muxed_id, Some(1));
    assert!(addr.muxed_address.is_some());
    assert_eq!(addr.derivation_index, None);
    assert_eq!(addr.evm_address, None);
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

    let txs = store
        .list_transactions(wallet_id, 100, None)
        .await
        .expect("list");
    assert_eq!(txs.len(), 1, "exactly one ledger entry for one on-chain op");
}

/// Mirrors `record_deposit_is_idempotent`, but for EVM: dedup on `(evm_tx_hash, log_index)`
/// rather than the Horizon op id. This is what makes a post-reorg rescan safe — if a
/// transaction the reorg carried away survives (re-included, same hash, in a later block), the
/// scanner re-detecting it must not credit it a second time.
#[tokio::test]
async fn record_evm_deposit_is_idempotent_on_rescan() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_evm_wallet(&store).await;
    let evm_tx_hash = format!("0x{}", Uuid::new_v4().simple());

    let dep = NewEvmDeposit {
        wallet_id,
        address_id: None,
        asset_code: "ETH".into(),
        asset_issuer: None,
        amount_stroops: 1_000_000,
        source_account: Some("0xsender".into()),
        destination_account: Some("0xreceiver".into()),
        evm_tx_hash: evm_tx_hash.clone(),
        log_index: 0,
        block_number: 100,
        block_hash: "0xblock100".into(),
    };

    // First detection records it — pending/detected, not yet spendable.
    let first = store.record_evm_deposit(&dep).await.expect("first");
    assert_eq!(
        first.expect("first detection must be recorded").status,
        "pending"
    );

    // A rescan re-detecting the SAME (evm_tx_hash, log_index) must be a no-op, never a second
    // credit — regardless of whether the row it collides with is detected/confirming/orphaned.
    let second = store.record_evm_deposit(&dep).await.expect("second");
    assert!(
        second.is_none(),
        "rescanning an already-recorded transaction must not double-credit it"
    );

    let txs = store
        .list_transactions(wallet_id, 100, None)
        .await
        .expect("list");
    assert_eq!(txs.len(), 1, "exactly one ledger entry for one on-chain deposit");
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
    assert_eq!(
        store
            .list_transactions(wallet_id, 100, None)
            .await
            .unwrap()
            .len(),
        2
    );
}

/// Regression test for #214: the anti-double-credit index must be scoped by `chain_id`, not just
/// `(tx_hash, operation_index)`. Before the fix, `uq_tx_onchain` was a bare
/// UNIQUE(stellar_tx_hash, operation_index) — a legitimate deposit on chain B with the same
/// `(tx_hash, operation_index)` as one already recorded on chain A would have been silently
/// rejected as a duplicate (a dropped-deposit bug). This proves both halves of the fix: the
/// same pair is now accepted across two different chains, and still rejected within one chain.
#[tokio::test]
async fn same_tx_hash_and_operation_index_is_accepted_across_chains_but_not_within_one() {
    let Some(store) = store().await else { return };
    // Two wallets on two different chains (mainnet -> stellar:pubnet, testnet -> stellar:testnet).
    let mainnet_wallet = fresh_wallet_on_network(&store, "mainnet").await;
    let testnet_wallet = fresh_wallet_on_network(&store, "testnet").await;

    let shared_hash = format!("shared-{}", Uuid::new_v4().simple());
    let dep_for = |wallet_id: Uuid, horizon_suffix: &str| NewDeposit {
        wallet_id,
        address_id: None,
        asset_code: "native".into(),
        asset_issuer: None,
        amount_stroops: 1,
        source_account: None,
        destination_account: None,
        stellar_tx_hash: shared_hash.clone(),
        operation_index: 0,
        horizon_op_id: format!("{shared_hash}-{horizon_suffix}"),
        ledger: None,
        memo_id: None,
    };

    // Same (tx_hash, operation_index) on chain A (mainnet) ...
    let on_mainnet = store
        .record_deposit(&dep_for(mainnet_wallet, "mainnet"))
        .await
        .expect("mainnet deposit");
    assert!(
        on_mainnet.is_some(),
        "first deposit on chain A must be recorded"
    );

    // ... and again on chain B (testnet) — must NOT be treated as a duplicate of chain A's row.
    let on_testnet = store
        .record_deposit(&dep_for(testnet_wallet, "testnet"))
        .await
        .expect("testnet deposit");
    assert!(
        on_testnet.is_some(),
        "the same (tx_hash, operation_index) on a DIFFERENT chain must be accepted, \
         not treated as a cross-chain duplicate"
    );

    // A genuine repeat within the SAME chain must still be rejected (the invariant we're
    // re-scoping, not removing).
    let repeat_on_mainnet = store
        .record_deposit(&dep_for(mainnet_wallet, "mainnet-repeat"))
        .await
        .expect("repeat within chain A");
    assert!(
        repeat_on_mainnet.is_none(),
        "a repeat of (tx_hash, operation_index) within the SAME chain must still be rejected"
    );

    assert_eq!(
        store
            .list_transactions(mainnet_wallet, 100, None)
            .await
            .unwrap()
            .len(),
        1,
        "chain A must have exactly one ledger entry, not two"
    );
    assert_eq!(
        store
            .list_transactions(testnet_wallet, 100, None)
            .await
            .unwrap()
            .len(),
        1,
        "chain B's deposit must be its own, independent ledger entry"
    );
}

#[tokio::test]
async fn sum_deposits_for_address_totals_only_that_addresss_confirmed_deposits() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_wallet(&store).await;
    let wid = wallet_id.simple();

    let addr_a = store
        .allocate_address(
            wallet_id,
            |id| Ok(format!("M{wid}-a-{id}")),
            Some("a"),
            serde_json::json!({}),
        )
        .await
        .expect("alloc a");
    let addr_b = store
        .allocate_address(
            wallet_id,
            |id| Ok(format!("M{wid}-b-{id}")),
            Some("b"),
            serde_json::json!({}),
        )
        .await
        .expect("alloc b");

    // Two deposits to A, one to B — A's total must be the sum of only its own two, not B's.
    for (i, amount) in [(0, 10_000_000i64), (1, 2_500_000)] {
        let tx_hash = Uuid::new_v4().to_string();
        store
            .record_deposit(&NewDeposit {
                wallet_id,
                address_id: Some(addr_a.id),
                asset_code: "native".into(),
                asset_issuer: None,
                amount_stroops: amount,
                source_account: Some("Gsender".into()),
                destination_account: Some("Gmaster".into()),
                stellar_tx_hash: tx_hash.clone(),
                operation_index: i,
                horizon_op_id: format!("{tx_hash}-{i}"),
                ledger: Some(1),
                memo_id: None,
            })
            .await
            .expect("record deposit to a");
    }
    let tx_hash_b = Uuid::new_v4().to_string();
    store
        .record_deposit(&NewDeposit {
            wallet_id,
            address_id: Some(addr_b.id),
            asset_code: "native".into(),
            asset_issuer: None,
            amount_stroops: 999_000_000,
            source_account: Some("Gsender".into()),
            destination_account: Some("Gmaster".into()),
            stellar_tx_hash: tx_hash_b.clone(),
            operation_index: 0,
            horizon_op_id: format!("{tx_hash_b}-0"),
            ledger: Some(1),
            memo_id: None,
        })
        .await
        .expect("record deposit to b");

    assert_eq!(
        store
            .sum_deposits_for_address(addr_a.id)
            .await
            .expect("sum a"),
        12_500_000,
        "A's total must be the sum of its own two deposits, unaffected by B's"
    );
    assert_eq!(
        store
            .sum_deposits_for_address(addr_b.id)
            .await
            .expect("sum b"),
        999_000_000
    );

    // A brand-new address with no deposits sums to 0, not an error.
    let addr_c = store
        .allocate_address(
            wallet_id,
            |id| Ok(format!("M{wid}-c-{id}")),
            Some("c"),
            serde_json::json!({}),
        )
        .await
        .expect("alloc c");
    assert_eq!(
        store
            .sum_deposits_for_address(addr_c.id)
            .await
            .expect("sum c"),
        0
    );

    // The batched form must agree with the per-address form, and only return entries that
    // actually have deposits (address C has none, so it's absent rather than a zero row).
    let batched = store
        .sum_deposits_for_addresses(&[addr_a.id, addr_b.id, addr_c.id])
        .await
        .expect("batched sum");
    let totals: std::collections::HashMap<Uuid, i64> = batched.into_iter().collect();
    assert_eq!(totals.get(&addr_a.id), Some(&12_500_000));
    assert_eq!(totals.get(&addr_b.id), Some(&999_000_000));
    assert_eq!(
        totals.get(&addr_c.id),
        None,
        "an address with zero deposits has no row in the batched result (GROUP BY yields nothing)"
    );

    // Empty id list must short-circuit to an empty result, not error or scan the whole table.
    assert_eq!(
        store
            .sum_deposits_for_addresses(&[])
            .await
            .expect("empty batch"),
        Vec::new()
    );
}

#[tokio::test]
async fn payment_link_lifecycle_intent_confirm_and_sum() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_wallet(&store).await;
    let wid = wallet_id.simple();

    let addr = store
        .allocate_address(
            wallet_id,
            |id| Ok(format!("M{wid}-{id}")),
            None,
            serde_json::json!({}),
        )
        .await
        .expect("alloc address");

    let slug = format!("link-{wid}");
    let link = store
        .create_payment_link(NewPaymentLink {
            wallet_id,
            address_id: addr.id,
            slug: &slug,
            name: "Support octo",
            description: Some("donations"),
            image_url: None,
            redirect_url: None,
            amount_usdc_stroops: None,
        })
        .await
        .expect("create link");
    assert_eq!(link.slug, slug);
    assert!(link.active);

    // Public lookup by slug must work with no wallet_id in hand.
    let by_slug = store
        .get_payment_link_by_slug(&slug)
        .await
        .expect("by slug");
    assert_eq!(by_slug.id, link.id);

    // A fresh link has nothing collected yet.
    assert_eq!(
        store
            .sum_payment_link_collected(link.id)
            .await
            .expect("sum"),
        0
    );

    let intent = store
        .record_payment_link_intent(
            link.id,
            Some("Ada"),
            Some("ada@example.com"),
            10_000_000,
            Some(addr.id),
        )
        .await
        .expect("record intent");
    assert_eq!(intent.status, "pending");

    let oldest = store
        .oldest_pending_payment_link_payment(link.id)
        .await
        .expect("oldest pending")
        .expect("one pending row");
    assert_eq!(oldest.id, intent.id);

    // Exact-address lookup is how ingest matches a deposit to one specific intent.
    let by_address = store
        .pending_payment_by_address(addr.id)
        .await
        .expect("by address")
        .expect("pending intent on this address");
    assert_eq!(by_address.id, intent.id);
    assert_eq!(by_address.address_id, Some(addr.id));

    let tx_hash = Uuid::new_v4().to_string();
    let dep = store
        .record_deposit(&NewDeposit {
            wallet_id,
            address_id: Some(addr.id),
            asset_code: "USDC".into(),
            asset_issuer: Some("GISSUER".into()),
            amount_stroops: 10_000_000,
            source_account: Some("Gpayer".into()),
            destination_account: Some("Gmaster".into()),
            stellar_tx_hash: tx_hash.clone(),
            operation_index: 0,
            horizon_op_id: format!("{tx_hash}-0"),
            ledger: Some(1),
            memo_id: None,
        })
        .await
        .expect("record deposit")
        .expect("first insert");

    store
        .confirm_payment_link_payment(intent.id, dep.id)
        .await
        .expect("confirm payment");

    let confirmed = store
        .get_payment_link_payment(link.id, intent.id)
        .await
        .expect("get payment");
    assert_eq!(confirmed.status, "confirmed");
    assert_eq!(confirmed.transaction_id, Some(dep.id));

    // Once confirmed, it's no longer the oldest pending (there is none left).
    assert!(store
        .oldest_pending_payment_link_payment(link.id)
        .await
        .expect("oldest pending after confirm")
        .is_none());

    assert_eq!(
        store
            .sum_payment_link_collected(link.id)
            .await
            .expect("sum after confirm"),
        10_000_000
    );

    let batch = store
        .sum_payment_link_collected_batch(&[link.id])
        .await
        .expect("batch sum");
    assert_eq!(batch, vec![(link.id, 10_000_000)]);

    // Deactivating is scoped to the owning wallet.
    let deactivated = store
        .set_payment_link_active(wallet_id, link.id, false)
        .await
        .expect("deactivate");
    assert!(!deactivated.active);
}

#[tokio::test]
async fn payment_link_mismatched_deposit_records_the_transaction_but_does_not_confirm() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_wallet(&store).await;
    let wid = wallet_id.simple();

    let addr = store
        .allocate_address(
            wallet_id,
            |id| Ok(format!("M{wid}-{id}")),
            None,
            serde_json::json!({}),
        )
        .await
        .expect("alloc address");

    let link = store
        .create_payment_link(NewPaymentLink {
            wallet_id,
            address_id: addr.id,
            slug: &format!("link-mismatch-{wid}"),
            name: "Underpaid test",
            description: None,
            image_url: None,
            redirect_url: None,
            amount_usdc_stroops: Some(10_000_000),
        })
        .await
        .expect("create link");

    let intent = store
        .record_payment_link_intent(link.id, None, None, 10_000_000, Some(addr.id))
        .await
        .expect("record intent");

    let tx_hash = Uuid::new_v4().to_string();
    let dep = store
        .record_deposit(&NewDeposit {
            wallet_id,
            address_id: Some(addr.id),
            asset_code: "USDC".into(),
            asset_issuer: Some("GISSUER".into()),
            amount_stroops: 5_000_000, // half of what was expected
            source_account: Some("Gpayer".into()),
            destination_account: Some("Gmaster".into()),
            stellar_tx_hash: tx_hash.clone(),
            operation_index: 0,
            horizon_op_id: format!("{tx_hash}-0"),
            ledger: Some(1),
            memo_id: None,
        })
        .await
        .expect("record deposit")
        .expect("first insert");

    store
        .mark_payment_link_payment_mismatched(intent.id, dep.id, "underpaid")
        .await
        .expect("mark mismatched");

    let mismatched = store
        .get_payment_link_payment(link.id, intent.id)
        .await
        .expect("get payment");
    assert_eq!(mismatched.status, "underpaid");
    assert_eq!(
        mismatched.transaction_id,
        Some(dep.id),
        "the short deposit must still be linked, so the merchant can see what actually arrived"
    );

    // A mismatched payment is not "pending" any more, so it must not still be matchable — ingest
    // must not later confuse a second, correct deposit with this already-resolved intent.
    assert!(store
        .pending_payment_by_address(addr.id)
        .await
        .expect("by address")
        .is_none());
}

#[tokio::test]
async fn expire_stale_payment_link_payments_only_sweeps_old_pending_rows() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_wallet(&store).await;
    let wid = wallet_id.simple();

    let addr = store
        .allocate_address(
            wallet_id,
            |id| Ok(format!("M{wid}-{id}")),
            None,
            serde_json::json!({}),
        )
        .await
        .expect("alloc address");

    let link = store
        .create_payment_link(NewPaymentLink {
            wallet_id,
            address_id: addr.id,
            slug: &format!("link-expiry-{wid}"),
            name: "Expiry test",
            description: None,
            image_url: None,
            redirect_url: None,
            amount_usdc_stroops: Some(10_000_000),
        })
        .await
        .expect("create link");

    let stale = store
        .record_payment_link_intent(link.id, None, None, 10_000_000, Some(addr.id))
        .await
        .expect("record stale intent");
    // Backdate it past the 1-hour deadline directly — this test can't wait an hour.
    sqlx::query(
        "UPDATE payment_link_payments SET created_at = now() - interval '2 hours' WHERE id = $1",
    )
    .bind(stale.id)
    .execute(store.pool())
    .await
    .expect("backdate");

    let fresh = store
        .record_payment_link_intent(link.id, None, None, 10_000_000, Some(addr.id))
        .await
        .expect("record fresh intent");

    let expired = store
        .expire_stale_payment_link_payments()
        .await
        .expect("sweep");
    let expired_ids: Vec<Uuid> = expired.iter().map(|p| p.id).collect();
    assert!(
        expired_ids.contains(&stale.id),
        "the >1hr-old pending row must be swept"
    );
    assert!(
        !expired_ids.contains(&fresh.id),
        "a freshly-created pending row must not be swept"
    );

    let stale_after = store
        .get_payment_link_payment(link.id, stale.id)
        .await
        .expect("get stale");
    assert_eq!(stale_after.status, "expired");

    let fresh_after = store
        .get_payment_link_payment(link.id, fresh.id)
        .await
        .expect("get fresh");
    assert_eq!(fresh_after.status, "pending");

    // Running the sweep again must be a no-op for already-expired rows (idempotent).
    let expired_again = store
        .expire_stale_payment_link_payments()
        .await
        .expect("sweep again");
    assert!(!expired_again.iter().any(|p| p.id == stale.id));
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
async fn sum_fees_today_can_use_wallet_status_created_at_index() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_wallet(&store).await;

    let mut tx = store.pool().begin().await.expect("begin transaction");
    sqlx::query("SET LOCAL enable_seqscan = off")
        .execute(&mut *tx)
        .await
        .expect("disable sequential scans for index eligibility check");
    let plan: Vec<String> = sqlx::query_scalar(
        r#"EXPLAIN (COSTS OFF)
           SELECT COALESCE(SUM(fee_stroops), 0)::bigint
           FROM sponsored_transactions
           WHERE wallet_id = $1
             AND status = 'confirmed'
             AND created_at >= date_trunc('day', now() AT TIME ZONE 'UTC')"#,
    )
    .bind(wallet_id)
    .fetch_all(&mut *tx)
    .await
    .expect("explain sum_sponsored_fees_today");
    let plan = plan.join("\n");

    assert!(
        plan.contains("idx_sponsored_wallet_status_"),
        "expected the wallet/status/created_at index, got:\n{plan}"
    );
    assert!(
        !plan.contains("Seq Scan"),
        "sum query must not require a full table scan:\n{plan}"
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

    // One version per file under crates/store/migrations/, 0001_init.sql .. 0033.
    // Guards against silent version collisions — sqlx keys migrations by version, so a repeated
    // number means only one of the colliding pair actually ran.
    assert_eq!(
        versions,
        vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33
        ],
        "expected exactly the thirty-three known migrations to be recorded as applied"
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

#[tokio::test]
async fn wallets_due_for_poll_applies_activity_backoff() {
    let Some(store) = store().await else { return };

    // `network` is CHECK-constrained to mainnet/testnet, so this test can't invent its own. It
    // uses mainnet (a handful of inert rows) and filters results down to the ids it created.
    let network = "mainnet";
    let mut ids = Vec::new();
    for label in ["never-polled", "active", "idle", "dormant"] {
        let acct = format!("G{}", Uuid::new_v4().simple());
        let w = store
            .create_wallet(NewWallet {
                network,
                stellar_account_g: &acct,
                sealed_ciphertext: b"ct",
                sealed_nonce: b"nonce",
                sealed_salt: b"salt",
                sealed_scheme: 1,
                label: Some(label),
                user_id: None,
                description: None,
            })
            .await
            .expect("create wallet");
        ids.push(w.id);
    }
    let (never, active, idle, dormant) = (ids[0], ids[1], ids[2], ids[3]);

    // Tiers for this test: active < 60s, idle polled at most every 100s, dormant (> 300s since
    // activity) polled at most every 100_000s.
    let mine = ids.clone();
    let due = |store: &Store| {
        let store = store.clone();
        let mine = mine.clone();
        async move {
            store
                .wallets_due_for_poll(network, 60, 100, 300, 100_000)
                .await
                .expect("due query")
                .into_iter()
                .map(|w| w.id)
                // Other mainnet rows may exist in a shared dev DB; only assert on our own.
                .filter(|id| mine.contains(id))
                .collect::<Vec<_>>()
        }
    };

    // Nothing has a cursor row yet: every wallet is due.
    let ids_due = due(&store).await;
    assert_eq!(
        ids_due.len(),
        4,
        "wallets with no cursor row are always due"
    );

    // Give each wallet a cursor row with a distinct activity/poll profile. All were *just*
    // polled, so only the active one should come back as due again immediately.
    for (id, activity_secs) in [(active, 10i64), (idle, 200), (dormant, 100_000)] {
        sqlx::query(
            "INSERT INTO ingest_cursor (wallet_id, paging_token, updated_at, last_polled_at)
             VALUES ($1, 'tok', now() - make_interval(secs => $2), now())",
        )
        .bind(id)
        .bind(activity_secs as f64)
        .execute(store.pool())
        .await
        .expect("seed cursor");
    }

    let ids_due = due(&store).await;
    assert!(
        ids_due.contains(&active),
        "an actively-transacting wallet must be polled every tick"
    );
    assert!(
        !ids_due.contains(&idle),
        "an idle wallet polled just now must wait for its interval"
    );
    assert!(
        !ids_due.contains(&dormant),
        "a dormant wallet polled just now must wait for its (longer) interval"
    );
    assert!(
        ids_due.contains(&never),
        "a wallet that has never been polled is still due"
    );

    // Move the idle wallet's last poll past its 100s interval — it becomes due, while the
    // dormant one (100_000s interval) is still not.
    sqlx::query("UPDATE ingest_cursor SET last_polled_at = now() - make_interval(secs => 150) WHERE wallet_id = $1")
        .bind(idle)
        .execute(store.pool())
        .await
        .expect("age idle poll");
    sqlx::query("UPDATE ingest_cursor SET last_polled_at = now() - make_interval(secs => 150) WHERE wallet_id = $1")
        .bind(dormant)
        .execute(store.pool())
        .await
        .expect("age dormant poll");

    let ids_due = due(&store).await;
    assert!(
        ids_due.contains(&idle),
        "idle wallet is due once its interval elapses"
    );
    assert!(
        !ids_due.contains(&dormant),
        "dormant wallet needs much longer than the idle interval before it is due"
    );
}

#[tokio::test]
async fn mark_polled_creates_and_updates_the_cursor_row() {
    let Some(store) = store().await else { return };
    let wallet_id = fresh_wallet(&store).await;

    // No cursor row yet — mark_polled must create one rather than silently no-op.
    store.mark_polled(wallet_id).await.expect("first mark");
    let first: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_polled_at FROM ingest_cursor WHERE wallet_id = $1")
            .bind(wallet_id)
            .fetch_one(store.pool())
            .await
            .expect("read cursor");
    let first = first.expect("last_polled_at set");

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    store.mark_polled(wallet_id).await.expect("second mark");
    let second: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_polled_at FROM ingest_cursor WHERE wallet_id = $1")
            .bind(wallet_id)
            .fetch_one(store.pool())
            .await
            .expect("read cursor again");
    assert!(
        second.expect("still set") > first,
        "repeat polls advance the timestamp"
    );

    // Marking a poll must NOT look like activity. If it did, every never-used wallet would count
    // as freshly active and the backoff tiers would never engage at all.
    let activity: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT updated_at FROM ingest_cursor WHERE wallet_id = $1")
            .bind(wallet_id)
            .fetch_one(store.pool())
            .await
            .expect("read updated_at");
    assert!(
        activity < chrono::Utc::now() - chrono::Duration::days(365),
        "mark_polled must not advance updated_at (last-activity); got {activity}"
    );

    // Marking a poll must not invent a paging token — that only advances on real activity.
    let token: Option<String> =
        sqlx::query_scalar("SELECT paging_token FROM ingest_cursor WHERE wallet_id = $1")
            .bind(wallet_id)
            .fetch_one(store.pool())
            .await
            .expect("read token");
    assert!(
        token.is_none(),
        "mark_polled must not fabricate a cursor position"
    );
}

// --- multi-chain migration round-trip (#214) -------------------------------------------------
//
// The tests below don't use the shared `store()` database (that one is already fully migrated
// through 0033 by the time any test runs). Instead they bootstrap a *fresh, scratch* database,
// apply only the pre-#214 migrations (0001..0020) to reproduce the exact schema shape that exists
// in production today, seed it with representative Stellar rows, then apply 0021..0033 and assert
// every row survived intact and every invariant now holds — the "zero data loss" and "every
// invariant still holds" deliverable called out in #214.

/// Legacy (pre-#214) migrations, in order — the schema shape live in production today.
const LEGACY_MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0001_init.sql"),
    include_str!("../migrations/0002_horizon_op_id.sql"),
    include_str!("../migrations/0003_users.sql"),
    include_str!("../migrations/0004_wallet_owner.sql"),
    include_str!("../migrations/0005_api_keys.sql"),
    include_str!("../migrations/0006_audit_logs.sql"),
    include_str!("../migrations/0007_gas_sponsorship.sql"),
    include_str!("../migrations/0008_scheme_version.sql"),
    include_str!("../migrations/0009_token_denylist.sql"),
    include_str!("../migrations/0010_sponsored_tx_status_index.sql"),
    include_str!("../migrations/0011_sponsored_and_audit_indexing.sql"),
    include_str!("../migrations/0012_client_custody.sql"),
    include_str!("../migrations/0013_withdrawal_allowlist.sql"),
    include_str!("../migrations/0014_payment_links.sql"),
    include_str!("../migrations/0015_payment_intent_address.sql"),
    include_str!("../migrations/0016_ingest_last_polled.sql"),
    include_str!("../migrations/0017_payment_link_redirect_url.sql"),
    include_str!("../migrations/0018_payment_status_expansion.sql"),
    include_str!("../migrations/0019_email_otp.sql"),
    include_str!("../migrations/0020_username.sql"),
];

/// The #214 multi-chain migrations, in order.
const MULTI_CHAIN_MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0021_chains_registry.sql"),
    include_str!("../migrations/0022_chain_scoped_columns.sql"),
    include_str!("../migrations/0023_backfill_wallets_chain_id.sql"),
    include_str!("../migrations/0024_backfill_addresses_chain_id.sql"),
    include_str!("../migrations/0025_backfill_transactions_chain_id.sql"),
    include_str!("../migrations/0026_chain_id_not_null_check.sql"),
    include_str!("../migrations/0027_validate_chain_id_not_null.sql"),
    include_str!("../migrations/0028_chain_id_set_not_null.sql"),
    include_str!("../migrations/0029_idx_addresses_chain_concurrent.sql"),
    include_str!("../migrations/0030_uq_addresses_chain_deposit_concurrent.sql"),
    include_str!("../migrations/0031_idx_tx_chain_concurrent.sql"),
    include_str!("../migrations/0032_uq_tx_onchain_chain_concurrent.sql"),
    include_str!("../migrations/0033_drop_legacy_uq_tx_onchain_concurrent.sql"),
];

/// Create a throwaway scratch database on the same server as `DATABASE_URL` and return
/// `(admin_url pointed at the `postgres` maintenance db, scratch db's own URL, scratch db name)`.
async fn create_scratch_database(base_url: &str) -> (String, String, String) {
    let scratch_db = format!("octo_migration_rt_{}", Uuid::new_v4().simple());
    let last_slash = base_url
        .rfind('/')
        .expect("DATABASE_URL must contain a path");
    let server_url = &base_url[..last_slash];
    let admin_url = format!("{server_url}/postgres");
    let scratch_url = format!("{server_url}/{scratch_db}");

    let mut admin_conn = sqlx::PgConnection::connect(&admin_url)
        .await
        .expect("connect to maintenance db");
    sqlx::raw_sql(&format!("CREATE DATABASE {scratch_db}"))
        .execute(&mut admin_conn)
        .await
        .expect("create scratch database");

    (admin_url, scratch_url, scratch_db)
}

/// Best-effort teardown: closes the pool, then drops the scratch database. Failures here don't
/// fail the test — leaked scratch databases are a local dev/CI-runner cleanup concern, not a
/// correctness one.
async fn drop_scratch_database(pool: sqlx::PgPool, admin_url: &str, scratch_db: &str) {
    pool.close().await;
    if let Ok(mut admin_conn) = sqlx::PgConnection::connect(admin_url).await {
        let _ = sqlx::raw_sql(&format!(
            "DROP DATABASE IF EXISTS {scratch_db} WITH (FORCE)"
        ))
        .execute(&mut admin_conn)
        .await;
    }
}

#[tokio::test]
async fn migration_round_trip_preserves_pre_migration_stellar_data_and_invariants() {
    let Some(base_url) = database_url() else {
        eprintln!("SKIPPED: DATABASE_URL is not set.");
        return;
    };

    let (admin_url, scratch_url, scratch_db) = create_scratch_database(&base_url).await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&scratch_url)
        .await
        .expect("connect to scratch database");

    // --- Phase 1: reproduce the exact pre-#214 production schema. ---
    for migration in LEGACY_MIGRATIONS {
        sqlx::raw_sql(migration)
            .execute(&pool)
            .await
            .expect("apply legacy migration");
    }

    // --- Phase 2: seed representative pre-migration Stellar rows. ---
    // A server-custody mainnet wallet and a client-custody testnet wallet (covering both the
    // NOT NULL sealed_* path and the nullable client-custody path), each with addresses and a mix
    // of confirmed deposits, a null-hash pending withdrawal row, and null asset_issuer/ledger
    // fields — the kinds of rows that actually exist in a production `transactions` table.
    let mainnet_wallet: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO wallets
            (network, stellar_account_g, sealed_ciphertext, sealed_nonce, sealed_salt,
             sealed_scheme, next_muxed_id, label)
        VALUES ('mainnet', $1, 'ct', 'n', 's', 1, 3, 'legacy mainnet wallet')
        RETURNING id
        "#,
    )
    .bind(format!("G{}", Uuid::new_v4().simple()))
    .fetch_one(&pool)
    .await
    .expect("seed mainnet wallet");

    let testnet_wallet: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO wallets
            (network, stellar_account_g, custody, encrypted_backup, next_muxed_id, label)
        VALUES ('testnet', $1, 'client', 'opaque-blob', 2, 'legacy client wallet')
        RETURNING id
        "#,
    )
    .bind(format!("G{}", Uuid::new_v4().simple()))
    .fetch_one(&pool)
    .await
    .expect("seed testnet wallet");

    let addr_a1: Uuid = sqlx::query_scalar(
        "INSERT INTO addresses (wallet_id, muxed_id, muxed_address, customer_ref)
         VALUES ($1, 1, $2, 'cust-a') RETURNING id",
    )
    .bind(mainnet_wallet)
    .bind(format!("M{}", Uuid::new_v4().simple()))
    .fetch_one(&pool)
    .await
    .expect("seed address a1");

    let addr_a2: Uuid = sqlx::query_scalar(
        "INSERT INTO addresses (wallet_id, muxed_id, muxed_address, customer_ref)
         VALUES ($1, 2, $2, 'cust-b') RETURNING id",
    )
    .bind(mainnet_wallet)
    .bind(format!("M{}", Uuid::new_v4().simple()))
    .fetch_one(&pool)
    .await
    .expect("seed address a2");

    let addr_b1: Uuid = sqlx::query_scalar(
        "INSERT INTO addresses (wallet_id, muxed_id, muxed_address, customer_ref)
         VALUES ($1, 1, $2, 'cust-c') RETURNING id",
    )
    .bind(testnet_wallet)
    .bind(format!("M{}", Uuid::new_v4().simple()))
    .fetch_one(&pool)
    .await
    .expect("seed address b1");

    let hash_1 = format!("hash-{}", Uuid::new_v4().simple());
    let hash_2 = format!("hash-{}", Uuid::new_v4().simple());
    let hash_3 = format!("hash-{}", Uuid::new_v4().simple());

    sqlx::query(
        r#"
        INSERT INTO transactions
            (wallet_id, address_id, direction, asset_code, amount_stroops, stellar_tx_hash,
             operation_index, horizon_op_id, ledger, status)
        VALUES ($1, $2, 'deposit', 'native', 10000000, $3, 0, $4, 100, 'confirmed')
        "#,
    )
    .bind(mainnet_wallet)
    .bind(addr_a1)
    .bind(&hash_1)
    .bind(format!("{hash_1}-0"))
    .execute(&pool)
    .await
    .expect("seed deposit 1");

    sqlx::query(
        r#"
        INSERT INTO transactions
            (wallet_id, address_id, direction, asset_code, asset_issuer, amount_stroops,
             stellar_tx_hash, operation_index, horizon_op_id, status)
        VALUES ($1, $2, 'deposit', 'USDC', 'GISSUER', 5000000, $3, 1, $4, 'confirmed')
        "#,
    )
    .bind(mainnet_wallet)
    .bind(addr_a2)
    .bind(&hash_2)
    .bind(format!("{hash_2}-1"))
    .execute(&pool)
    .await
    .expect("seed deposit 2");

    sqlx::query(
        r#"
        INSERT INTO transactions
            (wallet_id, address_id, direction, asset_code, amount_stroops, stellar_tx_hash,
             operation_index, horizon_op_id, status)
        VALUES ($1, $2, 'deposit', 'native', 2500000, $3, 0, $4, 'confirmed')
        "#,
    )
    .bind(testnet_wallet)
    .bind(addr_b1)
    .bind(&hash_3)
    .bind(format!("{hash_3}-0"))
    .execute(&pool)
    .await
    .expect("seed deposit 3");

    // A withdrawal-only row: no tx hash yet (mirrors a pending payout before submission).
    sqlx::query(
        "INSERT INTO transactions (wallet_id, direction, asset_code, amount_stroops, status)
         VALUES ($1, 'withdrawal', 'native', 1000000, 'pending')",
    )
    .bind(mainnet_wallet)
    .execute(&pool)
    .await
    .expect("seed pending withdrawal");

    let pre_wallet_count: i64 = sqlx::query_scalar("SELECT count(*) FROM wallets")
        .fetch_one(&pool)
        .await
        .unwrap();
    let pre_address_count: i64 = sqlx::query_scalar("SELECT count(*) FROM addresses")
        .fetch_one(&pool)
        .await
        .unwrap();
    let pre_tx_count: i64 = sqlx::query_scalar("SELECT count(*) FROM transactions")
        .fetch_one(&pool)
        .await
        .unwrap();

    // --- Phase 3: apply the #214 multi-chain migrations. ---
    for migration in MULTI_CHAIN_MIGRATIONS {
        sqlx::raw_sql(migration)
            .execute(&pool)
            .await
            .expect("apply multi-chain migration");
    }

    // --- Phase 4: zero data loss. ---
    let post_wallet_count: i64 = sqlx::query_scalar("SELECT count(*) FROM wallets")
        .fetch_one(&pool)
        .await
        .unwrap();
    let post_address_count: i64 = sqlx::query_scalar("SELECT count(*) FROM addresses")
        .fetch_one(&pool)
        .await
        .unwrap();
    let post_tx_count: i64 = sqlx::query_scalar("SELECT count(*) FROM transactions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pre_wallet_count, post_wallet_count, "no wallets lost");
    assert_eq!(pre_address_count, post_address_count, "no addresses lost");
    assert_eq!(pre_tx_count, post_tx_count, "no transactions lost");

    // --- Phase 5: every row backfilled correctly. ---
    let (mainnet_chain, testnet_chain): (String, String) = (
        sqlx::query_scalar("SELECT chain_id FROM wallets WHERE id = $1")
            .bind(mainnet_wallet)
            .fetch_one(&pool)
            .await
            .unwrap(),
        sqlx::query_scalar("SELECT chain_id FROM wallets WHERE id = $1")
            .bind(testnet_wallet)
            .fetch_one(&pool)
            .await
            .unwrap(),
    );
    assert_eq!(mainnet_chain, "stellar:pubnet");
    assert_eq!(testnet_chain, "stellar:testnet");

    let address_rows: Vec<(Uuid, String, String, String, Option<i64>)> = sqlx::query_as(
        "SELECT id, chain_id, muxed_address, deposit_address, derivation_index FROM addresses",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(address_rows.len(), 3);
    for (id, chain_id, muxed_address, deposit_address, derivation_index) in &address_rows {
        let expected_chain = if [addr_a1, addr_a2].contains(id) {
            &mainnet_chain
        } else {
            &testnet_chain
        };
        assert_eq!(
            chain_id, expected_chain,
            "address chain_id must match its wallet's"
        );
        assert_eq!(
            deposit_address, muxed_address,
            "deposit_address must mirror muxed_address for backfilled Stellar rows"
        );
        assert!(derivation_index.is_none());
    }

    let tx_rows: Vec<(String, Option<String>, Option<String>)> =
        sqlx::query_as("SELECT chain_id, stellar_tx_hash, tx_hash FROM transactions")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(tx_rows.len(), 4);
    for (chain_id, stellar_tx_hash, tx_hash) in &tx_rows {
        assert!(
            chain_id == &mainnet_chain || chain_id == &testnet_chain,
            "every transaction must have a real chain_id"
        );
        assert_eq!(
            tx_hash, stellar_tx_hash,
            "tx_hash must mirror stellar_tx_hash, including the NULL withdrawal row"
        );
    }
    assert!(
        tx_rows.iter().any(|(_, hash, _)| hash.is_none()),
        "the pending withdrawal's NULL hash must be preserved, not coerced to a value"
    );

    // --- Phase 6: NOT NULL is really enforced (not just true by coincidence of the seed data). ---
    let non_nullable: Vec<(String, String)> = sqlx::query_as(
        r#"
        SELECT table_name, column_name FROM information_schema.columns
        WHERE (table_name, column_name) IN (
            ('wallets', 'chain_id'), ('addresses', 'chain_id'),
            ('addresses', 'deposit_address'), ('transactions', 'chain_id')
        ) AND is_nullable = 'NO'
        "#,
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        non_nullable.len(),
        4,
        "all four chain-scoping columns must be NOT NULL after the migration set: {non_nullable:?}"
    );

    // --- Phase 7: the new chain-scoped unique indexes exist; the old global one is gone. ---
    let index_names: Vec<String> =
        sqlx::query_scalar("SELECT indexname FROM pg_indexes WHERE tablename = 'transactions'")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(index_names.contains(&"uq_tx_onchain_chain".to_string()));
    assert!(
        !index_names.contains(&"uq_tx_onchain".to_string()),
        "the old non-chain-scoped index must be dropped once the new one is live"
    );
    let addr_index_names: Vec<String> =
        sqlx::query_scalar("SELECT indexname FROM pg_indexes WHERE tablename = 'addresses'")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(addr_index_names.contains(&"uq_addresses_chain_deposit".to_string()));

    // --- Phase 8: the live Store API still works end-to-end against the migrated-in-place schema
    // (not just a from-scratch one) — allocate a new address and record a new deposit.
    let store = Store::from_pool(pool.clone());
    let wid = mainnet_wallet.simple();
    let new_address = store
        .allocate_address(
            mainnet_wallet,
            |id| Ok(format!("M{wid}-{id}")),
            Some("post-migration-customer"),
            serde_json::json!({}),
        )
        .await
        .expect("allocate address on migrated-in-place wallet");
    assert_eq!(new_address.chain_id, mainnet_chain);
    assert_eq!(
        new_address.muxed_id, 3,
        "counter continued from the legacy next_muxed_id"
    );

    let new_dep = NewDeposit {
        wallet_id: mainnet_wallet,
        address_id: Some(new_address.id),
        asset_code: "native".into(),
        asset_issuer: None,
        amount_stroops: 42,
        source_account: None,
        destination_account: None,
        stellar_tx_hash: format!("post-migration-{}", Uuid::new_v4().simple()),
        operation_index: 0,
        horizon_op_id: format!("post-migration-{}", Uuid::new_v4().simple()),
        ledger: None,
        memo_id: None,
    };
    let recorded = store
        .record_deposit(&new_dep)
        .await
        .expect("record deposit on migrated-in-place wallet");
    assert!(recorded.is_some());
    assert_eq!(recorded.unwrap().chain_id, mainnet_chain);

    drop_scratch_database(pool, &admin_url, &scratch_db).await;
}
