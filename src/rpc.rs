//! A JSON-RPC client for the one read the index makes: `eth_call`.

use std::time::Duration;

use alloy_primitives::{hex, Address};
use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde_json::{json, Value};

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

    /// The chain the node serves.
    pub async fn chain_id(&self) -> Result<u64> {
        let id = self.call("eth_chainId", json!([])).await?;
        let id = id.as_str().context("eth_chainId: result is not a string")?;
        u64::from_str_radix(id.trim_start_matches("0x"), 16)
            .context("eth_chainId: result is not hex")
    }

    /// What `to` returns for `data` at the latest block.
    pub async fn eth_call(&self, to: Address, data: &[u8]) -> Result<Vec<u8>> {
        let params = json!([{"to": to.to_string(), "data": hex::encode_prefixed(data)}, "latest"]);
        let returned = self.call("eth_call", params).await?;
        let returned = returned
            .as_str()
            .context("eth_call: result is not a string")?;
        hex::decode(returned).context("eth_call: result is not hex")
    }
}
