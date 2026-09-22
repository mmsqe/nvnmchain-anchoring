//! The REST surface over a stub node: what a request turns into, and what an answer turns back.
//! The matching itself is the node's, and `tempo-e2e` covers it there.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};

use nvnmchain_anchoring::rpc::Rpc;
use nvnmchain_anchoring::service::{router, App, SEARCH_PATH};

/// A node's `anchoring_` methods, canned. Search answers `registries` whatever it is asked, and
/// records the params it was asked with.
struct Node {
    asked: Option<Value>,
    registries: Value,
    status: Value,
    /// Answered instead of either, as a node that is down or not running the index would.
    error: Option<String>,
}

impl Default for Node {
    /// Answers every method, emptily. A derived default leaves both results `null`, which neither
    /// decodes from, and every case below becomes a 500 that still recorded what it was asked.
    fn default() -> Self {
        Self {
            asked: None,
            registries: json!([]),
            status: json!({"lastId": 0, "registryCount": 0}),
            error: None,
        }
    }
}

type Stub = Arc<Mutex<Node>>;

async fn answer(State(stub): State<Stub>, Json(body): Json<Value>) -> Json<Value> {
    let mut node = stub.lock().unwrap();
    if let Some(message) = node.error.clone() {
        return Json(
            json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": message}}),
        );
    }
    let result = match body["method"].as_str().unwrap_or_default() {
        "anchoring_searchRegistriesByName" => {
            node.asked = Some(body["params"][0].clone());
            json!({"registries": node.registries.clone()})
        }
        "anchoring_nameIndexStatus" => node.status.clone(),
        other => {
            let error = json!({"code": -32601, "message": format!("no method {other}")});
            return Json(json!({"jsonrpc": "2.0", "id": 1, "error": error}));
        }
    };
    Json(json!({"jsonrpc": "2.0", "id": 1, "result": result}))
}

/// The stub, and the service pointed at it.
async fn serve(node: Node) -> (Stub, String) {
    let stub: Stub = Arc::new(Mutex::new(node));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_url = format!("http://{}", listener.local_addr().unwrap());
    let routes = Router::new()
        .route("/", post(answer))
        .with_state(stub.clone());
    tokio::spawn(async move { axum::serve(listener, routes).await.unwrap() });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = router(App {
        rpc: Arc::new(Rpc::new(node_url).unwrap()),
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (stub, url)
}

fn registry(id: u64, name: &str) -> Value {
    json!({
        "id": id,
        "name": name,
        "description": "d",
        "creator": "nvnm1c",
        "createdAt": "t",
        "metadata": "m",
    })
}

async fn get(url: &str, query: &str) -> (u16, Value) {
    let response = reqwest::get(format!("{url}{SEARCH_PATH}?{query}"))
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap())
}

#[tokio::test]
async fn answers_in_the_modules_json() {
    let (_stub, url) = serve(Node {
        registries: json!([registry(1, "Alpha Fund"), registry(2, "alpha fund")]),
        ..Node::default()
    })
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
    let (stub, url) = serve(Node::default()).await;
    let asked = |query: &'static str| {
        let url = url.clone();
        let stub = stub.clone();
        async move {
            get(&url, query).await;
            stub.lock().unwrap().asked.clone().unwrap()["mode"].clone()
        }
    };

    assert_eq!(asked("name=a").await, json!("exact"));
    for query in ["name=a&mode=0", "name=a&mode=1"] {
        assert_eq!(asked(query).await, json!("exact"), "{query}");
    }
    assert_eq!(asked("name=a&mode=2").await, json!("prefix"));
    assert_eq!(
        asked("name=a&mode=REGISTRY_NAME_MATCH_MODE_SUFFIX").await,
        json!("suffix")
    );
    assert_eq!(asked("name=a&mode=4").await, json!("contains"));
}

#[tokio::test]
async fn a_page_is_fifty_unless_asked_and_two_hundred_at_most() {
    let (stub, url) = serve(Node::default()).await;
    let asked = |query: &'static str| {
        let url = url.clone();
        let stub = stub.clone();
        async move {
            let (status, body) = get(&url, query).await;
            assert_eq!(status, 200, "{query}: {body}");
            let asked = stub.lock().unwrap().asked.clone().unwrap();
            (asked["offset"].clone(), asked["limit"].clone(), body)
        }
    };

    let (offset, limit, body) = asked("name=a").await;
    assert_eq!((offset, limit), (json!(0), json!(50)));
    assert_eq!(body["pagination"], Value::Null, "none was asked for");

    let (_, limit, _) = asked("name=a&pagination.limit=1000").await;
    assert_eq!(limit, json!(200));

    let (offset, limit, body) = asked("name=a&pagination.offset=240&pagination.limit=50").await;
    assert_eq!((offset, limit), (json!(240), json!(50)));
    assert_eq!(body["pagination"], json!({"next_key": null, "total": "0"}));
}

/// `/health` carries how far the node's index reaches, and is a 503 while it cannot be read.
#[tokio::test]
async fn health_reports_what_the_node_has_indexed() {
    let (stub, url) = serve(Node {
        status: json!({"lastId": 7, "registryCount": 9, "blockNumber": 3}),
        ..Node::default()
    })
    .await;
    let health = || async {
        let response = reqwest::get(format!("{url}/health")).await.unwrap();
        (
            response.status().as_u16(),
            response.json::<Value>().await.unwrap(),
        )
    };

    assert_eq!(
        health().await,
        (
            200,
            json!({"last_id": 7, "registry_count": 9, "error": null})
        )
    );

    stub.lock().unwrap().error = Some("connection refused".into());
    let (code, body) = health().await;
    assert_eq!(code, 503);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("connection refused"),
        "{body}"
    );
}

#[tokio::test]
async fn a_bad_request_says_what_is_wrong() {
    // Every one is refused before the node is asked, so the stub answers nothing.
    let (stub, url) = serve(Node::default()).await;
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
    assert!(stub.lock().unwrap().asked.is_none());
}

/// A node that cannot answer is the gateway's `codes.Internal`, not a bad request.
#[tokio::test]
async fn a_node_that_fails_is_a_500() {
    let (_stub, url) = serve(Node {
        error: Some("no method anchoring_searchRegistriesByName".into()),
        ..Node::default()
    })
    .await;
    let (status, body) = get(&url, "name=alpha").await;
    assert_eq!(status, 500);
    assert_eq!(body["code"], json!(13));
}
