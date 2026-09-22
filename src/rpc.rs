//! A JSON-RPC client for the two `anchoring_` methods a node running the index serves.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};

/// `IAnchoring.Registry` as the node answers one: a number for the id, and camelCase.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Registry {
    pub id: u64,
    pub name: String,
    pub description: String,
    pub creator: String,
    pub created_at: String,
    pub metadata: String,
}

/// How far the node's index reaches. It also reports the block it is level with, which is not
/// something a caller of this service can act on.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexStatus {
    pub last_id: u64,
    pub registry_count: u64,
}

pub struct Rpc {
    client: Client,
    url: String,
}

impl Rpc {
    pub fn new(url: impl Into<String>) -> Result<Self> {
        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .context("build http client")?,
            url: url.into(),
        })
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        // One response per request, so the id is never matched against anything.
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let mut response: Value = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("{method} request"))?
            .json()
            .await
            .with_context(|| format!("{method} response"))?;
        if let Some(error) = response.get("error") {
            bail!("{method}: {error}");
        }
        Ok(response["result"].take())
    }

    /// Registries whose name matches. `mode` is the bare word the node's `Mode` deserializes.
    pub async fn search(
        &self,
        name: &str,
        mode: &str,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<Registry>> {
        let params = json!([{"name": name, "mode": mode, "offset": offset, "limit": limit}]);
        let mut answer = self
            .call("anchoring_searchRegistriesByName", params)
            .await?;
        serde_json::from_value(answer["registries"].take()).context("decode registries")
    }

    pub async fn status(&self) -> Result<IndexStatus> {
        let answer = self.call("anchoring_nameIndexStatus", json!([])).await?;
        serde_json::from_value(answer).context("decode nameIndexStatus")
    }
}
