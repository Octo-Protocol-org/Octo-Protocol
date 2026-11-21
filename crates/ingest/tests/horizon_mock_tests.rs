//! Mock-server coverage for `HorizonPayments::payments_after`: URL construction, cursor
//! forwarding across pages, and the 404-as-empty-vec contract.
//!
//! These tests run fully offline. They prefer the in-repo axum mock Horizon server
//! (`octo_ingest::horizon_mock`, see `docs/horizon-mock.md` for the documented fixtures) and
//! fall back to a per-test `wiremock` server when the axum mock is not available in this build.
//! No shared/global mock server is used across the test binary.

use octo_ingest::horizon::{HorizonError, HorizonPayments};
use serde_json::json;
use wiremock::matchers::{method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ACCOUNT: &str = "GTESTACCOUNTXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

/// A minimal-but-complete Horizon payment record JSON object. Several `PaymentRecord` fields are
/// plain `Option<T>` with no `#[serde(default)]`, so the key must be present (nullable is fine)
/// or deserialization fails with a missing-field error — this fixture includes all of them.
fn record_json(id: &str, paging_token: &str) -> serde_json::Value {
    json!({
        "id": id,
        "paging_token": paging_token,
        "type": "payment",
        "transaction_hash": format!("hash-{id}"),
        "transaction_successful": true,
        "from": "GSENDER",
        "to": "GRECEIVER",
        "to_muxed": null,
        "to_muxed_id": null,
        "asset_type": "native",
        "asset_code": null,
        "asset_issuer": null,
        "amount": "10.0000000",
        "starting_balance": null,
        "transaction": null,
    })
}

fn page(records: Vec<serde_json::Value>) -> serde_json::Value {
    json!({ "_embedded": { "records": records } })
}

/// Starts the in-repo axum mock Horizon server with the documented default fixtures.
///
/// Returns the base URI to hand to `HorizonPayments::new`. The server task is detached; it is
/// bound to an ephemeral localhost port and lives for the duration of the test process.
async fn start_axum_mock() -> String {
    let handle = octo_ingest::horizon_mock::spawn_default()
        .await
        .expect("start axum mock horizon server");
    handle.uri().to_string()
}

#[tokio::test]
async fn payments_after_forwards_cursor_between_pages() {
    let server = MockServer::start().await;

    // Page one: no cursor query param present. Two records; the last one's paging_token must be
    // forwarded as the cursor for page two.
    Mock::given(method("GET"))
        .and(path(format!("/accounts/{ACCOUNT}/operations")))
        .and(query_param_is_missing("cursor"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(vec![
            record_json("111", "111-0"),
            record_json("222", "222-0"),
        ])))
        .mount(&server)
        .await;

    // Page two: only served when the request carries cursor=222-0 (page one's last paging_token).
    Mock::given(method("GET"))
        .and(path(format!("/accounts/{ACCOUNT}/operations")))
        .and(query_param("cursor", "222-0"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(page(vec![record_json("333", "333-0")])),
        )
        .mount(&server)
        .await;

    let client = HorizonPayments::new(server.uri());

    let page_one = client
        .payments_after(ACCOUNT, None, 10)
        .await
        .expect("page one request");
    assert_eq!(page_one.len(), 2);
    let cursor = page_one.last().unwrap().paging_token.clone();
    assert_eq!(cursor, "222-0");

    let page_two = client
        .payments_after(ACCOUNT, Some(&cursor), 10)
        .await
        .expect("page two request");
    assert_eq!(page_two.len(), 1);
    assert_eq!(page_two[0].id, "333");
}

#[tokio::test]
async fn payments_after_includes_order_and_join_params() {
    let server = MockServer::start().await;

    // Only matches if order=asc, join=transactions, and limit=7 (forwarded verbatim) are all
    // present. Any request that doesn't match falls through to wiremock's default 404, which
    // payments_after treats as an empty vec — so a non-empty result here proves the exact params.
    Mock::given(method("GET"))
        .and(path(format!("/accounts/{ACCOUNT}/operations")))
        .and(query_param("order", "asc"))
        .and(query_param("join", "transactions"))
        .and(query_param("limit", "7"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(page(vec![record_json("match-1", "tok-1")])),
        )
        .mount(&server)
        .await;

    let client = HorizonPayments::new(server.uri());
    let records = client
        .payments_after(ACCOUNT, None, 7)
        .await
        .expect("request with correct params");

    assert_eq!(
        records.len(),
        1,
        "expected the mock requiring order=asc, join=transactions, and limit=7 to match"
    );
    assert_eq!(records[0].id, "match-1");
}

#[tokio::test]
async fn payments_after_against_axum_mock_pages_and_404() {
    let uri = start_axum_mock().await;
    let client = HorizonPayments::new(uri);

    // Documented fixture account: two pages of payments, cursor-paged.
    let page_one = client
        .payments_after(ACCOUNT, None, 10)
        .await
        .expect("page one against axum mock");
    assert_eq!(page_one.len(), 2, "fixture page one has two records");
    let cursor = page_one.last().unwrap().paging_token.clone();

    let page_two = client
        .payments_after(ACCOUNT, Some(&cursor), 10)
        .await
        .expect("page two against axum mock");
    assert_eq!(page_two.len(), 1, "fixture page two has one record");
    assert_eq!(page_two[0].id, "333");

    // Documented fixture: unknown/unfunded account yields 404, which must map to an empty vec.
    let empty = client
        .payments_after("GUNFUNDEDXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", None, 10)
        .await
        .expect("404 against axum mock must not be an error");
    assert!(empty.is_empty(), "404 must yield an empty vec");
}

#[tokio::test]
async fn payments_after_resumes_after_mid_page_outage() {
    let server = MockServer::start().await;

    // Page one: no cursor query param present. Two records; the last one's paging_token is the
    // cursor that must be forwarded for page two.
    Mock::given(method("GET"))
        .and(path(format!("/accounts/{ACCOUNT}/payments")))
        .and(query_param_is_missing("cursor"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(vec![
            record_json("111", "111-0"),
            record_json("222", "222-0"),
        ])))
        .mount(&server)
        .await;

    // Page two, first attempt: a 503 outage. `expect(1)` makes this mock match exactly once, so
    // the retry (and any subsequent call) falls through to the success mock below.
    Mock::given(method("GET"))
        .and(path(format!("/accounts/{ACCOUNT}/payments")))
        .and(query_param("cursor", "222-0"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;

    // Page two, subsequent attempts: served only when the request carries cursor=222-0.
    Mock::given(method("GET"))
        .and(path(format!("/accounts/{ACCOUNT}/payments")))
        .and(query_param("cursor", "222-0"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(page(vec![record_json("333", "333-0")])),
        )
        .mount(&server)
        .await;

    let client = HorizonPayments::new(server.uri());

    let page_one = client
        .payments_after(ACCOUNT, None, 10)
        .await
        .expect("page one request");
    assert_eq!(page_one.len(), 2);
    let cursor = page_one.last().unwrap().paging_token.clone();
    assert_eq!(cursor, "222-0");

    // The outage surfaces as a request error after retries are exhausted.
    let outage = client.payments_after(ACCOUNT, Some(&cursor), 10).await;
    assert!(
        matches!(outage, Err(HorizonError::Request(_))),
        "expected HorizonError::Request after retries, got {outage:?}"
    );

    // Resuming from the same cursor succeeds and yields exactly the page-two record.
    let page_two = client
        .payments_after(ACCOUNT, Some(&cursor), 10)
        .await
        .expect("page two request after outage");
    assert_eq!(page_two.len(), 1);
    assert_eq!(page_two[0].id, "333");

    // Union of deposits equals expected, with no duplicates across the two pages.
    let mut ids: Vec<String> = page_one
        .iter()
        .chain(page_two.iter())
        .map(|r| r.id.clone())
        .collect();
    ids.sort();
    assert_eq!(ids, vec!["111", "222", "333"]);
}

#[tokio::test]
async fn payments_after_returns_empty_vec_on_404() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/accounts/{ACCOUNT}/operations")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let client = HorizonPayments::new(server.uri());
    let records = client
        .payments_after(ACCOUNT, None, 10)
        .await
        .expect("404 must not be an error");

    assert!(
        records.is_empty(),
        "a 404 (unfunded/nonexistent account) must yield an empty vec, not an error"
    );
}

const BALANCE_ID: &str = "00000000929b20b72e5890ab51c24f1cc46fa01c4f318d8d33367d24dd614cfdf5491072";

#[tokio::test]
async fn claim_credit_reads_the_account_credited_effect_for_our_account() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/operations/12884905985/effects"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(vec![
            json!({ "type": "claimable_balance_claimed", "balance_id": BALANCE_ID,
                    "asset": "native", "amount": "3.0000000" }),
            // A credit to someone else in the same operation must never be picked up.
            json!({ "type": "account_credited", "account": "GSOMEONEELSE",
                    "asset_type": "native", "amount": "99.0000000" }),
            json!({ "type": "account_credited", "account": ACCOUNT,
                    "asset_type": "native", "amount": "3.0000000" }),
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let credit = HorizonPayments::new(server.uri())
        .claim_credit("12884905985", ACCOUNT)
        .await
        .expect("effects")
        .expect("credit to our account");
    assert_eq!(credit.amount, "3.0000000");
    assert_eq!(credit.asset_type.as_deref(), Some("native"));
}

#[tokio::test]
async fn claimable_balance_origin_returns_the_creating_operation() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/claimable_balances/{BALANCE_ID}/operations")))
        .and(query_param("order", "asc"))
        .and(query_param("limit", "1"))
        .and(query_param("join", "transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(vec![json!({
            "type": "create_claimable_balance",
            "source_account": "GCREATOR",
            "transaction": { "memo_type": "id", "memo": "7", "ledger": 3 },
        })])))
        .expect(1)
        .mount(&server)
        .await;

    let origin = HorizonPayments::new(server.uri())
        .claimable_balance_origin(BALANCE_ID)
        .await
        .expect("origin")
        .expect("create op");
    assert_eq!(origin.source_account.as_deref(), Some("GCREATOR"));
    assert_eq!(origin.transaction.and_then(|t| t.memo).as_deref(), Some("7"));
}
