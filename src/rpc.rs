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

    /// What `to` returns for `data` at the latest block.
    pub async fn eth_call(&self, to: Address, data: &[u8]) -> Result<Vec<u8>> {
        // One response per request, so the id is never matched against anything.
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [{"to": to.to_string(), "data": hex::encode_prefixed(data)}, "latest"],
        });
        let response: Value = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .context("eth_call request")?
            .json()
            .await
            .context("eth_call response")?;
        if let Some(error) = response.get("error") {
            bail!("eth_call: {error}");
        }
        let returned = response["result"]
            .as_str()
            .context("eth_call: result is not a string")?;
        hex::decode(returned).context("eth_call: result is not hex")
    }
}
