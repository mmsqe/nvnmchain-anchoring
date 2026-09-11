use std::sync::{Arc, Mutex};

use alloy_primitives::{hex, Address};
use alloy_sol_types::SolCall;
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};

use nvnmchain_anchoring::contract::{registriesCall, registriesReturn, PageResponse, Registry};
use nvnmchain_anchoring::index::{Index, Mode};
use nvnmchain_anchoring::rpc::Rpc;
use nvnmchain_anchoring::sync::catch_up;

type Chain = Arc<Mutex<Vec<Registry>>>;

fn registry(id: u64) -> Registry {
    Registry {
        id,
        name: format!("Registry {id}"),
        ..Default::default()
    }
}

/// A node whose contract holds `chain`, paging `registries` the way the contract
/// does: from the cursor, at most `limit`, with a next key while more follow.
async fn node(chain: Chain) -> String {
    async fn rpc(State(chain): State<Chain>, Json(request): Json<Value>) -> Json<Value> {
        let data = hex::decode(request["params"][0]["data"].as_str().unwrap()).unwrap();
        let call = registriesCall::abi_decode(&data).unwrap();
        let start = u64::from_be_bytes(call.pagination.key[..].try_into().unwrap());
        let chain = chain.lock().unwrap();
        let rest: Vec<Registry> = chain.iter().filter(|r| r.id >= start).cloned().collect();
        let n = rest.len().min(call.pagination.limit as usize);
        let next_key = if rest.len() > n {
            (start + n as u64).to_be_bytes().to_vec()
        } else {
            Vec::new()
        };
        let returned = registriesCall::abi_encode_returns(&registriesReturn {
            registriesOut: rest[..n].to_vec(),
            paginationOut: PageResponse {
                nextKey: next_key.into(),
                total: 0,
            },
        });
        Json(
            json!({"jsonrpc": "2.0", "id": request["id"], "result": hex::encode_prefixed(returned)}),
        )
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().route("/", post(rpc)).with_state(chain);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

#[tokio::test]
async fn catches_up_across_pages_then_takes_only_what_is_new() {
    let chain: Chain = Arc::new(Mutex::new((1..=450).map(registry).collect()));
    let rpc = Rpc::new(node(chain.clone()).await).unwrap();
    let index = Index::open(":memory:").unwrap();

    assert_eq!(catch_up(&rpc, Address::ZERO, &index).await.unwrap(), 450);
    assert_eq!(index.last_id().unwrap(), 450);
    let found = index.search(Mode::Exact, "registry 450", 50, 0).unwrap();
    assert_eq!(found, [registry(450)]);

    chain.lock().unwrap().extend([registry(451), registry(452)]);
    assert_eq!(catch_up(&rpc, Address::ZERO, &index).await.unwrap(), 2);
    assert_eq!(catch_up(&rpc, Address::ZERO, &index).await.unwrap(), 0);
    assert_eq!(index.last_id().unwrap(), 452);
}

#[tokio::test]
async fn a_page_with_a_hole_is_refused_whole() {
    let chain: Chain = Arc::new(Mutex::new(vec![registry(1), registry(2), registry(4)]));
    let rpc = Rpc::new(node(chain).await).unwrap();
    let index = Index::open(":memory:").unwrap();

    let err = catch_up(&rpc, Address::ZERO, &index).await.unwrap_err();
    assert_eq!(err.to_string(), "registry 4 came where 3 was due");
    assert_eq!(index.last_id().unwrap(), 0);
}
