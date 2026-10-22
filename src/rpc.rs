//! A JSON-RPC client for the two `anchoring_` methods a node running the index serves.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::{de, Deserialize, Deserializer};
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

/// One page of matches, and how many match in all.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub registries: Vec<Registry>,
    /// The next match's id, which the node writes as 8 bytes in hex.
    #[serde(default, deserialize_with = "hex_id")]
    pub next_key: Option<u64>,
    pub total: u64,
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

    /// Registries whose name matches, from the id `key` or past `offset` matches. `mode` is the
    /// bare word the node's `Mode` deserializes.
    pub async fn search(
        &self,
        name: &str,
        mode: &str,
        key: Option<u64>,
        offset: u64,
        limit: u64,
    ) -> Result<Page> {
        let mut params = json!({"name": name, "mode": mode, "offset": offset, "limit": limit});
        if let Some(key) = key {
            params["key"] = json!(format!("0x{key:016x}"));
        }
        let answer = self
            .call("anchoring_searchRegistriesByName", json!([params]))
            .await?;
        serde_json::from_value(answer).context("decode search")
    }

    pub async fn status(&self) -> Result<IndexStatus> {
        let answer = self.call("anchoring_nameIndexStatus", json!([])).await?;
        serde_json::from_value(answer).context("decode nameIndexStatus")
    }
}

fn hex_id<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
    let Some(key) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    let digits = key.strip_prefix("0x").unwrap_or(&key);
    if digits.len() != 16 {
        return Err(de::Error::custom(format!("nextKey {key}: not 8 bytes")));
    }
    u64::from_str_radix(digits, 16)
        .map(Some)
        .map_err(|_| de::Error::custom(format!("nextKey {key}: not hex")))
}
