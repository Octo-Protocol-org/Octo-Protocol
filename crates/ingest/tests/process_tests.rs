//! Integration tests for deposit processing. Require Postgres via `DATABASE_URL` (from .env).
//!
//! These exercise the full `Ingestor::process` path against the DB: attribution by muxed id and
//! memo id, quarantine of unattributed deposits, idempotent dedup, and skipping of failed txs.

use octo_ingest::horizon::{PaymentRecord, TransactionRecord};
use octo_ingest::{Ingestor, Processed};
use octo_store::{NewWallet, Store};
use octo_wallet_core::encode_muxed;
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

async fn setup() -> Option<(Store, Ingestor, Uuid)> {
    let url = database_url()?;
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");

    // A wallet whose base account is BASE, but with a unique stored account string per test run so
    // rows don't collide. We use a unique muxed_address per allocation; BASE is what the ingestor
    // matches against, so set the wallet's stored account to BASE-with-suffix is not possible (the
    // ingestor compares to account_g we pass in). So create the wallet, then drive the Ingestor
    // with account_g = the wallet's stored G... value.
    let acct = BASE; // ingestor matches rec.to == account_g; allocate uses real encode_muxed(BASE)
    let wallet = store
        .create_wallet(NewWallet {
            network: "testnet",
            stellar_account_g: &format!("{acct}-{}", Uuid::new_v4().simple()),
            sealed_ciphertext: b"ct",
            sealed_nonce: b"nonce",
            sealed_salt: b"salt",
            sealed_scheme: 1,
            label: None,
            user_id: None,
            description: None,
        })
        .await
        .expect("wallet");

    let ingestor = Ingestor::new(store.clone(), "http://unused", wallet.id, BASE.to_string());
    Some((store, ingestor, wallet.id))
}

fn base_record(id: &str) -> PaymentRecord {
    PaymentRecord {
        id: id.into(),
        paging_token: id.into(),
        kind: "payment".into(),
        transaction_hash: Some(format!("hash-{id}")),
        transaction_successful: true,
        from: Some("Gsender".into()),
        to: Some(BASE.into()),
        to_muxed: None,
        to_muxed_id: None,
        asset_type: Some("native".into()),
        asset_code: None,
        asset_issuer: None,
        amount: Some("5.0000000".into()),
        starting_balance: None,
        transaction: None,
    }
}

#[tokio::test]
async fn deposit_to_muxed_address_is_attributed() {
    let Some((store, ingestor, wallet_id)) = setup().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };

    // Allocate a customer address (muxed id 1).
    let addr = store
        .allocate_address(
            wallet_id,
            |id| encode_muxed(BASE, id as u64).map_err(|_| ()),
            Some("cust-1"),
            serde_json::json!({}),
        )
        .await
        .unwrap();

    // A payment sent to that customer's muxed address.
    let mut rec = base_record("op-muxed-1");
    rec.to_muxed = Some(addr.muxed_address.clone());

    let outcome = ingestor.process(&rec).await.unwrap();
    assert_eq!(outcome, Processed::Recorded { attributed: true });

    // The recorded transaction links to the customer address.
    let txs = store.list_transactions(wallet_id, 100, None).await.unwrap();
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0].address_id, Some(addr.id));
    assert_eq!(txs[0].amount_stroops, 50_000_000);
}

#[tokio::test]
async fn deposit_with_memo_id_is_attributed() {
    let Some((store, ingestor, wallet_id)) = setup().await else {
        return;
    };

    let addr = store
        .allocate_address(
            wallet_id,
            |id| encode_muxed(BASE, id as u64).map_err(|_| ()),
            Some("cust-memo"),
            serde_json::json!({}),
        )
        .await
        .unwrap();

    // Sent to the base account with a numeric memo equal to the muxed id.
    let mut rec = base_record("op-memo-1");
    rec.transaction = Some(TransactionRecord {
        memo_type: Some("id".into()),
        memo: Some(addr.muxed_id.to_string()),
        ledger: Some(99),
    });

    let outcome = ingestor.process(&rec).await.unwrap();
    assert_eq!(outcome, Processed::Recorded { attributed: true });
    let txs = store.list_transactions(wallet_id, 100, None).await.unwrap();
    assert_eq!(txs[0].address_id, Some(addr.id));
    assert_eq!(txs[0].memo_id, Some(addr.muxed_id));
}

#[tokio::test]
async fn unattributed_deposit_is_quarantined() {
    let Some((store, ingestor, wallet_id)) = setup().await else {
        return;
    };

    // Plain payment to the base account, no muxed, no memo → recorded but not attributed.
    let rec = base_record("op-plain-1");
    let outcome = ingestor.process(&rec).await.unwrap();
    assert_eq!(outcome, Processed::Recorded { attributed: false });

    let txs = store.list_transactions(wallet_id, 100, None).await.unwrap();
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0].address_id, None, "unattributed → quarantined");
}

#[tokio::test]
async fn duplicate_operation_is_idempotent() {
    let Some((store, ingestor, wallet_id)) = setup().await else {
        return;
    };

    let rec = base_record("op-dup-1");
    assert_eq!(
        ingestor.process(&rec).await.unwrap(),
        Processed::Recorded { attributed: false }
    );
    // Same Horizon op id again → no double-credit.
    assert_eq!(ingestor.process(&rec).await.unwrap(), Processed::Duplicate);

    assert_eq!(
        store
            .list_transactions(wallet_id, 100, None)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn failed_tx_is_skipped() {
    let Some((store, ingestor, wallet_id)) = setup().await else {
        return;
    };

    let mut rec = base_record("op-failed-1");
    rec.transaction_successful = false;
    assert_eq!(ingestor.process(&rec).await.unwrap(), Processed::Skipped);
    assert_eq!(
        store
            .list_transactions(wallet_id, 100, None)
            .await
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
async fn payment_to_other_account_is_skipped() {
    let Some((store, ingestor, wallet_id)) = setup().await else {
        return;
    };

    let mut rec = base_record("op-other-1");
    rec.to = Some("GSOMEOTHERACCOUNT".into());
    assert_eq!(ingestor.process(&rec).await.unwrap(), Processed::Skipped);
    assert_eq!(
        store
            .list_transactions(wallet_id, 100, None)
            .await
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
async fn missing_amount_and_starting_balance_is_skipped() {
    let Some((store, ingestor, wallet_id)) = setup().await else {
        return;
    };

    // Neither `amount` nor `starting_balance` present: amount_str falls back to "", and
    // amount::to_stroops("") must return None, so process() must skip cleanly rather than panic.
    let mut rec = base_record("op-no-amount-1");
    rec.amount = None;
    rec.starting_balance = None;

    let outcome = ingestor.process(&rec).await.unwrap();
    assert_eq!(outcome, Processed::Skipped);
    assert_eq!(
        store
            .list_transactions(wallet_id, 100, None)
            .await
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
async fn credit_asset_with_missing_code_falls_back_to_unknown() {
    let Some((store, ingestor, wallet_id)) = setup().await else {
        return;
    };

    // A non-native asset_type with no asset_code must fall back to the literal "unknown" rather
    // than panicking or leaving the field empty.
    let mut rec = base_record("op-credit-no-code-1");
    rec.asset_type = Some("credit_alphanum4".into());
    rec.asset_code = None;

    let outcome = ingestor.process(&rec).await.unwrap();
    assert_eq!(outcome, Processed::Recorded { attributed: false });

    let txs = store.list_transactions(wallet_id, 100, None).await.unwrap();
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0].asset_code, "unknown");
}

#[tokio::test]
async fn missing_transaction_field_yields_no_memo_and_no_panic() {
    let Some((store, ingestor, wallet_id)) = setup().await else {
        return;
    };

    // No joined `transaction` at all: memo_id()'s `self.transaction.as_ref()?` must short-circuit
    // to None without panicking, and the recorded deposit must carry no memo/ledger.
    let mut rec = base_record("op-no-tx-1");
    rec.transaction = None;

    let outcome = ingestor.process(&rec).await.unwrap();
    assert_eq!(outcome, Processed::Recorded { attributed: false });

    let txs = store.list_transactions(wallet_id, 100, None).await.unwrap();
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0].memo_id, None);
    assert_eq!(txs[0].ledger, None);
}
