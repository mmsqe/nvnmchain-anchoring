use std::sync::Arc;

use serde_json::{json, Value};

use nvnmchain_anchoring::contract::Registry;
use nvnmchain_anchoring::index::Index;
use nvnmchain_anchoring::service::{router, App, SEARCH_PATH};
use nvnmchain_anchoring::sync::Status;

fn registry(id: u64, name: &str) -> Registry {
    Registry {
        id,
        name: name.into(),
        description: "d".into(),
        creator: "nvnm1c".into(),
        createdAt: "t".into(),
        metadata: "m".into(),
    }
}

/// The service over `registries`, reporting `status`, and its base URL.
async fn serve(registries: &[Registry], status: Arc<Status>) -> String {
    let index = Index::open(":memory:").unwrap();
    index.insert(registries).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = router(App {
        index: Arc::new(index),
        status,
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

async fn get(url: &str, query: &str) -> (u16, Value) {
    let response = reqwest::get(format!("{url}{SEARCH_PATH}?{query}"))
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap())
}

fn ids(body: &Value) -> Vec<String> {
    body["registries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn answers_in_the_modules_json() {
    let url = serve(
        &[registry(1, "Alpha Fund"), registry(2, "alpha fund")],
        Arc::default(),
    )
    .await;
    let (status, body) = get(&url, "name=ALPHA%20FUND").await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        json!({
            "registries": [
                {"id": "1", "name": "Alpha Fund", "description": "d", "creator": "nvnm1c", "created_at": "t", "metadata": "m"},
                {"id": "2", "name": "alpha fund", "description": "d", "creator": "nvnm1c", "created_at": "t", "metadata": "m"},
            ],
            "pagination": null,
        })
    );
}

#[tokio::test]
async fn a_mode_is_taken_by_name_or_by_number() {
    let url = serve(
        &[registry(1, "Alpha Fund"), registry(2, "Fund Alpha")],
        Arc::default(),
    )
    .await;
    for mode in ["3", "REGISTRY_NAME_MATCH_MODE_SUFFIX"] {
        assert_eq!(
            ids(&get(&url, &format!("name=alpha&mode={mode}")).await.1),
            ["2"]
        );
    }
    for mode in ["2", "REGISTRY_NAME_MATCH_MODE_PREFIX"] {
        assert_eq!(
            ids(&get(&url, &format!("name=alpha&mode={mode}")).await.1),
            ["1"]
        );
    }
    assert_eq!(ids(&get(&url, "name=fund&mode=4").await.1), ["1", "2"]);
    // Unspecified is exact.
    assert!(ids(&get(&url, "name=alpha&mode=0").await.1).is_empty());
}

#[tokio::test]
async fn a_page_is_fifty_unless_asked_and_two_hundred_at_most() {
    let all: Vec<Registry> = (1..=250)
        .map(|id| registry(id, &format!("Registry {id}")))
        .collect();
    let url = serve(&all, Arc::default()).await;
    let page = |query: &'static str| {
        let url = url.clone();
        async move { get(&url, &format!("name=registry&mode=2&{query}")).await.1 }
    };

    assert_eq!(ids(&page("").await).len(), 50);
    assert_eq!(ids(&page("pagination.limit=1000").await).len(), 200);
    let tail = page("pagination.offset=240&pagination.limit=50").await;
    assert_eq!(ids(&tail).first().unwrap(), "241");
    assert_eq!(ids(&tail).len(), 10);
    assert_eq!(tail["pagination"], json!({"next_key": null, "total": "0"}));
}

/// `/health` carries the last round of sync, and is a 503 while the node cannot be read.
#[tokio::test]
async fn health_reports_the_last_round_of_sync() {
    let status = Arc::new(Status::default());
    let url = serve(&[registry(1, "Alpha")], status.clone()).await;
    let health = || async {
        let response = reqwest::get(format!("{url}/health")).await.unwrap();
        (
            response.status().as_u16(),
            response.json::<Value>().await.unwrap(),
        )
    };

    assert_eq!(
        health().await,
        (200, json!({"last_id": 1, "synced_at": null, "error": null}))
    );

    status.failed(&anyhow::anyhow!("eth_call request: connection refused"));
    let (code, body) = health().await;
    assert_eq!(code, 503);
    assert_eq!(body["error"], json!("eth_call request: connection refused"));
    assert_eq!(body["last_id"], json!(1), "what it holds is still reported");

    status.ok();
    let (code, body) = health().await;
    assert_eq!(code, 200);
    assert!(body["synced_at"].as_u64().unwrap() > 0);
    assert_eq!(body["error"], Value::Null);
}

#[tokio::test]
async fn a_bad_request_says_what_is_wrong() {
    let url = serve(&[registry(1, "Alpha")], Arc::default()).await;
    for (query, message) in [
        ("", "name must be provided"),
        ("name=", "name must be provided"),
        ("name=alpha&mode=5", "invalid mode 5"),
        ("name=alpha&nmae=beta", "unknown parameter nmae"),
        (
            "name=alpha&pagination.limit=x",
            "pagination.limit=x: not a number",
        ),
    ] {
        let (status, body) = get(&url, query).await;
        assert_eq!(status, 400, "{query}");
        assert_eq!(
            body,
            json!({"code": 3, "message": message, "details": []}),
            "{query}"
        );
    }
}
