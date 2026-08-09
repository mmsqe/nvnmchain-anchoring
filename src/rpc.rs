//! A JSON-RPC client with exactly the four calls this indexer makes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde_json::{json, Value};

pub struct Rpc {
    client: Client,
    url: String,
    next_id: AtomicU64,
}

impl Rpc {
    pub fn new(url: impl Into<String>) -> Result<Self> {
        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .context("build http client")?,
            url: url.into(),
            next_id: AtomicU64::new(0),
        })
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let response: Value = self
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
        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    }

    pub async fn block_number(&self) -> Result<u64> {
        let result = self.call("eth_blockNumber", json!([])).await?;
        parse_hex_u64(result.as_str().unwrap_or("0x0")).context("parse block number")
    }

    /// The canonical hash of `number`, for detecting a reorg under our cursor.
    pub async fn block_hash(&self, number: u64) -> Result<Option<String>> {
        let result = self
            .call(
                "eth_getBlockByNumber",
                json!([format!("0x{number:x}"), false]),
            )
            .await?;
        Ok(result
            .get("hash")
            .and_then(Value::as_str)
            .map(str::to_string))
    }

    /// Logs from `address` whose topic0 is one of `topics0`, over an inclusive
    /// block range. One call per range — the whole reason this indexer does not
    /// need to walk blocks.
    pub async fn logs(
        &self,
        address: &str,
        topics0: &[&str],
        from: u64,
        to: u64,
    ) -> Result<Vec<Value>> {
        let filter = json!({
            "address": address,
            "fromBlock": format!("0x{from:x}"),
            "toBlock": format!("0x{to:x}"),
            "topics": [topics0],
        });
        let result = self.call("eth_getLogs", json!([filter])).await?;
        Ok(result.as_array().cloned().unwrap_or_default())
    }

    /// Several calls in one request. The endpoint answers out of order, so
    /// results are put back in request order by id — batching is what makes an
    /// audit over thousands of keys finish in seconds rather than hours.
    pub async fn call_batch(&self, calls: Vec<(&str, Value)>) -> Result<Vec<Value>> {
        if calls.is_empty() {
            return Ok(Vec::new());
        }
        let first = self
            .next_id
            .fetch_add(calls.len() as u64, Ordering::Relaxed);
        let body: Vec<Value> = calls
            .iter()
            .enumerate()
            .map(|(i, (method, params))| {
                json!({"jsonrpc": "2.0", "id": first + i as u64, "method": method, "params": params})
            })
            .collect();
        let response: Vec<Value> = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .context("batch request")?
            .json()
            .await
            .context("batch response")?;

        let mut out = vec![Value::Null; calls.len()];
        for entry in response {
            let Some(id) = entry.get("id").and_then(Value::as_u64) else {
                continue;
            };
            let Some(slot) = id.checked_sub(first).map(|i| i as usize) else {
                continue;
            };
            if let Some(cell) = out.get_mut(slot) {
                if let Some(error) = entry.get("error") {
                    bail!("{}: {error}", calls[slot].0);
                }
                *cell = entry.get("result").cloned().unwrap_or(Value::Null);
            }
        }
        Ok(out)
    }

    /// `latest(namespace, key)` on the precompile — the node's own answer for a
    /// head, used to calibrate our slot derivation against it.
    pub async fn latest(&self, namespace: &str, key: &str) -> Result<String> {
        let data = format!(
            "{}{:0>64}{}",
            crate::precompile::LATEST_SELECTOR,
            crate::eth::strip_hex(namespace),
            crate::eth::strip_hex(key)
        );
        let result = self
            .call(
                "eth_call",
                json!([{"to": crate::precompile::ADDRESS, "data": data}, "latest"]),
            )
            .await?;
        Ok(result.as_str().unwrap_or("0x").to_string())
    }

    /// One range of logs plus the hash of its last block, in a single request —
    /// the checkpoint then costs no extra round trip and can commit with the
    /// cursor it belongs to.
    pub async fn logs_and_block_hash(
        &self,
        address: &str,
        topics0: &[&str],
        from: u64,
        to: u64,
    ) -> Result<(Vec<Value>, String)> {
        let filter = json!({
            "address": address,
            "fromBlock": format!("0x{from:x}"),
            "toBlock": format!("0x{to:x}"),
            "topics": [topics0],
        });
        let results = self
            .call_batch(vec![
                ("eth_getLogs", json!([filter])),
                ("eth_getBlockByNumber", json!([format!("0x{to:x}"), false])),
            ])
            .await?;
        let logs = match results.first() {
            Some(Value::Array(logs)) => logs.clone(),
            _ => Vec::new(),
        };
        let hash = results
            .get(1)
            .and_then(|b| b.get("hash"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        Ok((logs, hash))
    }

    pub async fn storage_at(&self, address: &str, slot: &str) -> Result<String> {
        let result = self
            .call("eth_getStorageAt", json!([address, slot, "latest"]))
            .await?;
        Ok(result.as_str().unwrap_or("0x").to_string())
    }
}

pub fn parse_hex_u64(value: &str) -> Option<u64> {
    u64::from_str_radix(value.trim().strip_prefix("0x").unwrap_or(value.trim()), 16).ok()
}
