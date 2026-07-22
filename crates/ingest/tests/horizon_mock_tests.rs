//! Mock-server coverage for `HorizonPayments::payments_after`: URL construction, cursor
//! forwarding across pages, and the 404-as-empty-vec contract. Uses a per-test `wiremock`
//! server (no shared/global mock server across the test binary).

use octo_ingest::horizon::HorizonPayments;
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

#[tokio::test]
async fn payments_after_forwards_cursor_between_pages() {
    let server = MockServer::start().await;

    // Page one: no cursor query param present. Two records; the last one's paging_token must be
    // forwarded as the cursor for page two.
    Mock::given(method("GET"))
        .and(path(format!("/accounts/{ACCOUNT}/payments")))
        .and(query_param_is_missing("cursor"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(vec![
            record_json("111", "111-0"),
            record_json("222", "222-0"),
        ])))
        .mount(&server)
        .await;

    // Page two: only served when the request carries cursor=222-0 (page one's last paging_token).
    Mock::given(method("GET"))
        .and(path(format!("/accounts/{ACCOUNT}/payments")))
        .and(query_param("cursor", "222-0"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(page(vec![record_json("333", "333-0")])),
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
        .and(path(format!("/accounts/{ACCOUNT}/payments")))
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
async fn payments_after_returns_empty_vec_on_404() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/accounts/{ACCOUNT}/payments")))
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
