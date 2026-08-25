//! Integration tests for deposit processing. Require Postgres via `DATABASE_URL` (from .env).
//!
//! These exercise the full `Ingestor::process` path against the DB: attribution by muxed id and
//! memo id, quarantine of unattributed deposits, idempotent dedup, and skipping of failed txs.

use octo_ingest::horizon::{PaymentRecord, TransactionRecord};
use octo_ingest::{Ingestor, Processed};
use octo_store::{NewPaymentLink, NewWallet, Store};
use octo_wallet_core::encode_muxed;
use std::sync::Once;
use uuid::Uuid;

/// Same testnet USDC issuer the ingest crate matches payment-link deposits against.
const USDC_TESTNET_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

/// A fresh, syntactically-valid `G...` base account, distinct on every call.
///
/// Every wallet in this file needs its own real base account rather than sharing one fixed
/// constant: `octo_store`'s multi-chain schema (#214) enforces `UNIQUE(chain_id,
/// deposit_address)` across *all* wallets on a chain (previously only `UNIQUE(wallet_id,
/// muxed_id)` was enforced), and `encode_muxed(base, id)` is a pure function of the base account —
/// two wallets sharing one base account would derive identical muxed addresses for the same id
/// and collide against that constraint. Real Stellar accounts never share a base key, so this
/// also makes the fixture more realistic, not just constraint-satisfying.
///
/// The bytes don't need to correspond to a real keypair — `stellar_strkey` only checks the
/// checksum/format, which is all `encode_muxed`'s decode step verifies.
fn fresh_base_account() -> String {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    format!("{}", stellar_strkey::ed25519::PublicKey(bytes))
}

async fn setup() -> Option<(Store, Ingestor, Uuid, String)> {
    let url = database_url()?;
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");

    let base_account = fresh_base_account();
    let wallet = store
        .create_wallet(NewWallet {
            network: "testnet",
            stellar_account_g: &base_account,
            sealed_ciphertext: b"ct",
            sealed_nonce: b"nonce",
            sealed_salt: b"salt",
            sealed_scheme: 1, // octo_crypto::SCHEME_V1
            label: None,
            user_id: None,
            description: None,
        })
        .await
        .expect("wallet");

    let ingestor = Ingestor::new(
        store.clone(),
        "http://unused",
        wallet.id,
        base_account.clone(),
    );
    Some((store, ingestor, wallet.id, base_account))
}

fn base_record(id: &str, base_account: &str) -> PaymentRecord {
    // Deposits dedup on the Horizon operation id, which is globally unique and persists in the
    // DB. A fixed literal here made every one of these tests a `Duplicate` on the second run
    // against the same database, so they only passed on a fresh DB. Suffix a per-run uuid to
    // keep them re-runnable while preserving the readable prefix.
    let id = format!("{id}-{}", Uuid::new_v4().simple());
    let id = id.as_str();
    PaymentRecord {
        id: id.into(),
        paging_token: id.into(),
        kind: "payment".into(),
        transaction_hash: Some(format!("hash-{id}")),
        transaction_successful: true,
        from: Some("Gsender".into()),
        to: Some(base_account.into()),
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
    let Some((store, ingestor, wallet_id, base_account)) = setup().await else {
        eprintln!("SKIPPED: set DATABASE_URL");
        return;
    };

    // Allocate a customer address (muxed id 1).
    let addr = store
        .allocate_address(
            wallet_id,
            |id| encode_muxed(&base_account, id as u64).map_err(|_| ()),
            Some("cust-1"),
            serde_json::json!({}),
        )
        .await
        .unwrap();

    // A payment sent to that customer's muxed address.
    let mut rec = base_record("op-muxed-1", &base_account);
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
    let Some((store, ingestor, wallet_id, base_account)) = setup().await else {
        return;
    };

    let addr = store
        .allocate_address(
            wallet_id,
            |id| encode_muxed(&base_account, id as u64).map_err(|_| ()),
            Some("cust-memo"),
            serde_json::json!({}),
        )
        .await
        .unwrap();

    // Sent to the base account with a numeric memo equal to the muxed id.
    let mut rec = base_record("op-memo-1", &base_account);
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
    let Some((store, ingestor, wallet_id, base_account)) = setup().await else {
        return;
    };

    // Plain payment to the base account, no muxed, no memo → recorded but not attributed.
    let rec = base_record("op-plain-1", &base_account);
    let outcome = ingestor.process(&rec).await.unwrap();
    assert_eq!(outcome, Processed::Recorded { attributed: false });

    let txs = store.list_transactions(wallet_id, 100, None).await.unwrap();
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0].address_id, None, "unattributed → quarantined");
}

#[tokio::test]
async fn duplicate_operation_is_idempotent() {
    let Some((store, ingestor, wallet_id, base_account)) = setup().await else {
        return;
    };

    let rec = base_record("op-dup-1", &base_account);
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
    let Some((store, ingestor, wallet_id, base_account)) = setup().await else {
        return;
    };

    let mut rec = base_record("op-failed-1", &base_account);
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
    let Some((store, ingestor, wallet_id, base_account)) = setup().await else {
        return;
    };

    let mut rec = base_record("op-other-1", &base_account);
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
    let Some((store, ingestor, wallet_id, base_account)) = setup().await else {
        return;
    };

    // Neither `amount` nor `starting_balance` present: amount_str falls back to "", and
    // amount::to_stroops("") must return None, so process() must skip cleanly rather than panic.
    let mut rec = base_record("op-no-amount-1", &base_account);
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
    let Some((store, ingestor, wallet_id, base_account)) = setup().await else {
        return;
    };

    // A non-native asset_type with no asset_code must fall back to the literal "unknown" rather
    // than panicking or leaving the field empty.
    let mut rec = base_record("op-credit-no-code-1", &base_account);
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
    let Some((store, ingestor, wallet_id, base_account)) = setup().await else {
        return;
    };

    // No joined `transaction` at all: memo_id()'s `self.transaction.as_ref()?` must short-circuit
    // to None without panicking, and the recorded deposit must carry no memo/ledger.
    let mut rec = base_record("op-no-tx-1", &base_account);
    rec.transaction = None;

    let outcome = ingestor.process(&rec).await.unwrap();
    assert_eq!(outcome, Processed::Recorded { attributed: false });

    let txs = store.list_transactions(wallet_id, 100, None).await.unwrap();
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0].memo_id, None);
    assert_eq!(txs[0].ledger, None);
}

async fn make_usdc_payment_link(
    store: &Store,
    wallet_id: Uuid,
    base_account: &str,
    amount_usdc_stroops: i64,
) -> (String, Uuid, Uuid) {
    let addr = store
        .allocate_address(
            wallet_id,
            |id| encode_muxed(base_account, id as u64).map_err(|_| ()),
            None,
            serde_json::json!({}),
        )
        .await
        .unwrap();
    let link = store
        .create_payment_link(NewPaymentLink {
            wallet_id,
            address_id: addr.id,
            slug: &format!("link-{}", Uuid::new_v4().simple()),
            name: "Test link",
            description: None,
            image_url: None,
            redirect_url: None,
            amount_usdc_stroops: Some(amount_usdc_stroops),
        })
        .await
        .unwrap();
    let intent = store
        .record_payment_link_intent(link.id, None, None, amount_usdc_stroops, Some(addr.id))
        .await
        .unwrap();
    (addr.muxed_address, link.id, intent.id)
}

fn usdc_record(id: &str, base_account: &str, to_muxed: String, amount: &str) -> PaymentRecord {
    let mut rec = base_record(id, base_account);
    rec.to_muxed = Some(to_muxed);
    rec.asset_type = Some("credit_alphanum4".into());
    rec.asset_code = Some("USDC".into());
    rec.asset_issuer = Some(USDC_TESTNET_ISSUER.into());
    rec.amount = Some(amount.into());
    rec
}

#[tokio::test]
async fn underpaid_payment_link_deposit_is_recorded_but_left_unconfirmed() {
    let Some((store, ingestor, wallet_id, base_account)) = setup().await else {
        return;
    };

    let (muxed, link_id, intent_id) =
        make_usdc_payment_link(&store, wallet_id, &base_account, 100_000_000).await;
    let rec = usdc_record("op-underpaid-1", &base_account, muxed, "5.0000000");

    let outcome = ingestor.process(&rec).await.unwrap();
    assert_eq!(outcome, Processed::Recorded { attributed: true });

    let payment = store
        .get_payment_link_payment(link_id, intent_id)
        .await
        .unwrap();
    assert_eq!(payment.status, "underpaid");
    assert!(
        payment.transaction_id.is_some(),
        "the short deposit must still be linked so the merchant can see what arrived"
    );
}

#[tokio::test]
async fn overpaid_payment_link_deposit_is_recorded_but_left_unconfirmed() {
    let Some((store, ingestor, wallet_id, base_account)) = setup().await else {
        return;
    };

    let (muxed, link_id, intent_id) =
        make_usdc_payment_link(&store, wallet_id, &base_account, 100_000_000).await;
    let rec = usdc_record("op-overpaid-1", &base_account, muxed, "15.0000000");

    let outcome = ingestor.process(&rec).await.unwrap();
    assert_eq!(outcome, Processed::Recorded { attributed: true });

    let payment = store
        .get_payment_link_payment(link_id, intent_id)
        .await
        .unwrap();
    assert_eq!(payment.status, "overpaid");
    assert!(payment.transaction_id.is_some());
}

#[tokio::test]
async fn exact_payment_link_deposit_confirms() {
    let Some((store, ingestor, wallet_id, base_account)) = setup().await else {
        return;
    };

    let (muxed, link_id, intent_id) =
        make_usdc_payment_link(&store, wallet_id, &base_account, 100_000_000).await;
    let rec = usdc_record("op-exact-1", &base_account, muxed, "10.0000000");

    let outcome = ingestor.process(&rec).await.unwrap();
    assert_eq!(outcome, Processed::Recorded { attributed: true });

    let payment = store
        .get_payment_link_payment(link_id, intent_id)
        .await
        .unwrap();
    assert_eq!(payment.status, "confirmed");
}
