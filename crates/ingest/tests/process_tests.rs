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
            sealed_scheme: 1, // octo_crypto::SCHEME_V1
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
        to: Some(BASE.into()),
        to_muxed: None,
        to_muxed_id: None,
        asset_type: Some("native".into()),
        asset_code: None,
        asset_issuer: None,
        amount: Some("5.0000000".into()),
        starting_balance: None,
        balance_id: None,
        claimant: None,
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
    assert_eq!(ingestor.process(&rec).await.unwrap(), Processed::FailedTransaction);
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

async fn make_usdc_payment_link(
    store: &Store,
    wallet_id: Uuid,
    amount_usdc_stroops: i64,
) -> (String, Uuid, Uuid) {
    let addr = store
        .allocate_address(
            wallet_id,
            |id| encode_muxed(BASE, id as u64).map_err(|_| ()),
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

fn usdc_record(id: &str, to_muxed: String, amount: &str) -> PaymentRecord {
    let mut rec = base_record(id);
    rec.to_muxed = Some(to_muxed);
    rec.asset_type = Some("credit_alphanum4".into());
    rec.asset_code = Some("USDC".into());
    rec.asset_issuer = Some(USDC_TESTNET_ISSUER.into());
    rec.amount = Some(amount.into());
    rec
}

#[tokio::test]
async fn underpaid_payment_link_deposit_is_recorded_but_left_unconfirmed() {
    let Some((store, ingestor, wallet_id)) = setup().await else {
        return;
    };

    let (muxed, link_id, intent_id) = make_usdc_payment_link(&store, wallet_id, 100_000_000).await;
    let rec = usdc_record("op-underpaid-1", muxed, "5.0000000");

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
    let Some((store, ingestor, wallet_id)) = setup().await else {
        return;
    };

    let (muxed, link_id, intent_id) = make_usdc_payment_link(&store, wallet_id, 100_000_000).await;
    let rec = usdc_record("op-overpaid-1", muxed, "15.0000000");

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
    let Some((store, ingestor, wallet_id)) = setup().await else {
        return;
    };

    let (muxed, link_id, intent_id) = make_usdc_payment_link(&store, wallet_id, 100_000_000).await;
    let rec = usdc_record("op-exact-1", muxed, "10.0000000");

    let outcome = ingestor.process(&rec).await.unwrap();
    assert_eq!(outcome, Processed::Recorded { attributed: true });

    let payment = store
        .get_payment_link_payment(link_id, intent_id)
        .await
        .unwrap();
    assert_eq!(payment.status, "confirmed");
}

/// A fresh, decodable Horizon TOID (random ledger and tx order, first operation) and its ledger.
fn unique_toid() -> (String, i64) {
    let r = Uuid::new_v4().as_u128();
    let ledger = 1 + (r % 50_000_000) as u64;
    let tx_order = 1 + ((r >> 64) % 1_000) as u64;
    (((ledger << 32) | (tx_order << 12) | 1).to_string(), ledger as i64)
}

/// A Horizon-shaped path payment that spent 100 XLM and delivered 9.5 USDC to `to_muxed`.
fn path_payment_record(kind: &str, to_muxed: Option<String>) -> PaymentRecord {
    let (toid, ledger) = unique_toid();
    serde_json::from_value(serde_json::json!({
        "id": toid,
        "paging_token": toid,
        "type": kind,
        "transaction_successful": true,
        "transaction_hash": format!("pathhash-{}", Uuid::new_v4().simple()),
        "from": "GPATHSENDER",
        "to": BASE,
        "to_muxed": to_muxed,
        "asset_type": "credit_alphanum4",
        "asset_code": "USDC",
        "asset_issuer": USDC_TESTNET_ISSUER,
        "amount": "9.5000000",
        "source_asset_type": "native",
        "source_amount": "100.0000000",
        "transaction": { "ledger": ledger },
    }))
    .expect("path payment fixture")
}

#[tokio::test]
async fn path_payment_deposits_are_recorded_once_with_the_received_amount() {
    let Some((store, ingestor, wallet_id)) = setup().await else {
        return;
    };

    for kind in ["path_payment_strict_send", "path_payment_strict_receive"] {
        let addr = store
            .allocate_address(
                wallet_id,
                |id| encode_muxed(BASE, id as u64).map_err(|_| ()),
                Some(kind),
                serde_json::json!({}),
            )
            .await
            .unwrap();
        let rec = path_payment_record(kind, Some(addr.muxed_address.clone()));

        assert_eq!(
            ingestor.process(&rec).await.unwrap(),
            Processed::Recorded { attributed: true },
            "{kind}"
        );
        // Dedup by operation id still holds for path payments.
        assert_eq!(ingestor.process(&rec).await.unwrap(), Processed::Duplicate, "{kind}");

        let txs = store.list_transactions(wallet_id, 100, None).await.unwrap();
        let row = txs
            .iter()
            .find(|t| t.address_id == Some(addr.id))
            .expect("deposit row");
        assert_eq!(row.amount_stroops, 95_000_000, "{kind}: destination amount, not source");
        assert_eq!(row.asset_code, "USDC", "{kind}: destination asset, not source");
        assert_eq!(
            txs.iter().filter(|t| t.address_id == Some(addr.id)).count(),
            1,
            "{kind}"
        );
    }
}

#[tokio::test]
async fn self_path_payment_conversion_is_not_a_deposit() {
    let Some((store, ingestor, wallet_id)) = setup().await else {
        return;
    };

    // The master account converting its own XLM into USDC must not look like incoming funds.
    let mut rec = path_payment_record("path_payment_strict_send", None);
    rec.from = Some(BASE.into());
    assert_eq!(ingestor.process(&rec).await.unwrap(), Processed::Skipped);
    assert!(store
        .list_transactions(wallet_id, 100, None)
        .await
        .unwrap()
        .is_empty());
}

/// A `claim_claimable_balance` by our master account of `balance_id`.
fn claim_record(balance_id: &str) -> PaymentRecord {
    let (toid, ledger) = unique_toid();
    serde_json::from_value(serde_json::json!({
        "id": toid,
        "paging_token": toid,
        "type": "claim_claimable_balance",
        "transaction_successful": true,
        "transaction_hash": format!("claimhash-{}", Uuid::new_v4().simple()),
        "source_account": BASE,
        "balance_id": balance_id,
        "claimant": BASE,
        "transaction": { "ledger": ledger },
    }))
    .expect("claim fixture")
}

/// Mount Horizon's claim effects and balance history: `creator` made the balance with `memo_id`.
async fn mock_claim_horizon(
    rec: &PaymentRecord,
    balance_id: &str,
    creator: &str,
    memo_id: i64,
) -> wiremock::MockServer {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/operations/{}/effects", rec.id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "_embedded": { "records": [
                { "type": "claimable_balance_claimed", "balance_id": balance_id,
                  "asset": format!("USDC:{USDC_TESTNET_ISSUER}"), "amount": "12.0000000" },
                { "type": "account_credited", "account": BASE, "asset_type": "credit_alphanum4",
                  "asset_code": "USDC", "asset_issuer": USDC_TESTNET_ISSUER, "amount": "12.0000000" },
            ]}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/claimable_balances/{balance_id}/operations")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "_embedded": { "records": [{
                "type": "create_claimable_balance",
                "source_account": creator,
                "transaction": { "memo_type": "id", "memo": memo_id.to_string() },
            }]}
        })))
        .mount(&server)
        .await;
    server
}

fn unique_balance_id() -> String {
    format!("00000000{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

#[tokio::test]
async fn claimable_balance_claim_creates_a_single_attributed_deposit() {
    let Some((store, _, wallet_id)) = setup().await else {
        return;
    };
    let addr = store
        .allocate_address(
            wallet_id,
            |id| encode_muxed(BASE, id as u64).map_err(|_| ()),
            Some("cust-claim"),
            serde_json::json!({}),
        )
        .await
        .unwrap();
    let balance_id = unique_balance_id();
    let rec = claim_record(&balance_id);
    let server = mock_claim_horizon(&rec, &balance_id, "GCREATOR", addr.muxed_id).await;
    let ingestor = Ingestor::new(store.clone(), &server.uri(), wallet_id, BASE.to_string());

    assert_eq!(
        ingestor.process(&rec).await.unwrap(),
        Processed::Recorded { attributed: true }
    );
    assert_eq!(ingestor.process(&rec).await.unwrap(), Processed::Duplicate);

    let txs = store.list_transactions(wallet_id, 100, None).await.unwrap();
    assert_eq!(txs.len(), 1, "one claim → one deposit row");
    assert_eq!(txs[0].address_id, Some(addr.id));
    assert_eq!(txs[0].amount_stroops, 120_000_000);
    assert_eq!(txs[0].asset_code, "USDC");
    assert_eq!(txs[0].source_account.as_deref(), Some("GCREATOR"), "origin is the creator");
    assert_eq!(txs[0].memo_id, Some(addr.muxed_id));
}

#[tokio::test]
async fn reclaiming_our_own_claimable_balance_is_not_a_deposit() {
    let Some((store, _, wallet_id)) = setup().await else {
        return;
    };
    let balance_id = unique_balance_id();
    let rec = claim_record(&balance_id);
    let server = mock_claim_horizon(&rec, &balance_id, BASE, 1).await;
    let ingestor = Ingestor::new(store.clone(), &server.uri(), wallet_id, BASE.to_string());

    assert_eq!(ingestor.process(&rec).await.unwrap(), Processed::Skipped);
    assert!(store
        .list_transactions(wallet_id, 100, None)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn claim_by_another_account_is_skipped_without_calling_horizon() {
    let Some((store, ingestor, wallet_id)) = setup().await else {
        return;
    };
    // `ingestor` points at an unreachable Horizon, so any lookup here would error, not skip.
    let mut rec = claim_record(&unique_balance_id());
    rec.claimant = Some("GSOMEOTHERACCOUNT".into());
    assert_eq!(ingestor.process(&rec).await.unwrap(), Processed::Skipped);
    assert!(store
        .list_transactions(wallet_id, 100, None)
        .await
        .unwrap()
        .is_empty());
}

/// Every crediting operation type, each from a failed transaction, with a valid TOID.
fn failed_fixtures() -> Vec<PaymentRecord> {
    let mut payment = path_payment_record("path_payment_strict_send", None);
    payment.kind = "payment".into();
    let mut create = path_payment_record("path_payment_strict_send", None);
    create.kind = "create_account".into();
    create.starting_balance = Some("5.0000000".into());
    let mut all = vec![
        payment,
        create,
        path_payment_record("path_payment_strict_send", None),
        path_payment_record("path_payment_strict_receive", None),
        claim_record(&unique_balance_id()),
    ];
    for rec in &mut all {
        rec.transaction_successful = false;
    }
    all
}

// Invariant #449: failed payments never create deposits, whatever the operation type.
#[tokio::test]
async fn invariant_failed_transactions_never_create_deposits() {
    let Some((store, ingestor, wallet_id)) = setup().await else {
        return;
    };
    // `ingestor` targets an unreachable Horizon: a failed claim must not even attempt a lookup.
    for rec in failed_fixtures() {
        assert_eq!(
            ingestor.process(&rec).await.unwrap(),
            Processed::FailedTransaction,
            "{}",
            rec.kind
        );
    }
    assert!(store
        .list_transactions(wallet_id, 100, None)
        .await
        .unwrap()
        .is_empty());
}

// Invariant #449 end to end: a failed payment served by Horizon is passed over, not credited.
#[tokio::test]
async fn invariant_failed_payment_from_horizon_creates_no_deposit_row() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let Some((store, _, wallet_id)) = setup().await else {
        return;
    };
    let mut failed = path_payment_record("path_payment_strict_send", None);
    failed.kind = "payment".into();
    failed.transaction_successful = false;

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/accounts/{BASE}/operations")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "_embedded": { "records": [failed] }
        })))
        .mount(&server)
        .await;
    let ingestor = Ingestor::new(store.clone(), &server.uri(), wallet_id, BASE.to_string());

    assert_eq!(ingestor.poll_once(10).await.unwrap(), 1);
    assert!(store
        .list_transactions(wallet_id, 100, None)
        .await
        .unwrap()
        .is_empty());
    // The cursor still moves past it, so a failed op is never re-fetched forever.
    assert_eq!(
        store.get_cursor(wallet_id).await.unwrap().as_deref(),
        Some(failed.paging_token.as_str())
    );
}

#[tokio::test]
async fn deposit_after_link_expiry_is_recorded_but_not_matched() {
    let Some((store, ingestor, wallet_id)) = setup().await else {
        return;
    };

    // The intent was opened while the link was live; the deadline passed before funds landed.
    let past = chrono::Utc::now() - chrono::Duration::minutes(1);
    let (muxed, link_id, intent_id) =
        make_usdc_payment_link_expiring(&store, wallet_id, 100_000_000, Some(past)).await;
    let rec = usdc_record("op-late-expired-1", muxed, "10.0000000");

    let outcome = ingestor.process(&rec).await.unwrap();
    assert_eq!(outcome, Processed::Recorded { attributed: true });

    let payment = store
        .get_payment_link_payment(link_id, intent_id)
        .await
        .unwrap();
    assert_eq!(payment.status, "pending", "a late deposit must not confirm the intent");
    assert!(payment.transaction_id.is_none());
}

#[tokio::test]
async fn deposit_after_link_cancel_is_recorded_but_not_matched() {
    let Some((store, ingestor, wallet_id)) = setup().await else {
        return;
    };

    let (muxed, link_id, intent_id) = make_usdc_payment_link(&store, wallet_id, 100_000_000).await;
    let (_, cancelled) = store.cancel_payment_link(wallet_id, link_id).await.unwrap();
    assert_eq!(cancelled.len(), 1);
    let rec = usdc_record("op-late-cancelled-1", muxed, "10.0000000");

    let outcome = ingestor.process(&rec).await.unwrap();
    assert_eq!(outcome, Processed::Recorded { attributed: true });

    let payment = store
        .get_payment_link_payment(link_id, intent_id)
        .await
        .unwrap();
    assert_eq!(payment.status, "cancelled");
    assert!(payment.transaction_id.is_none());
}
