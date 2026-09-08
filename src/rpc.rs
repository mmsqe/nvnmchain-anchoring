//! A JSON-RPC client with exactly the state reads the audit makes.
//!
//! The log itself no longer comes from here — tidx has it. What a node still
//! answers that an index cannot is the precompile's own state, which is the
//! whole point of auditing against it rather than against a second index.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde_json::{json, Value};

use crate::eth::{strip_hex, word_to_usize};

pub struct Rpc {
    client: Client,
    url: String,
    next_id: AtomicU64,
}

/// What `state(namespace)` answers: the leaf count and the peaks, highest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmrState {
    pub count: u64,
    pub peaks: Vec<String>,
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

    /// Several calls in one request. The endpoint answers out of order, so
    /// results are put back in request order by id — batching is what makes an
    /// audit over thousands of namespaces finish in seconds rather than hours.
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

    /// The `eth_call` params for `state(namespace)` on the precompile at `block`,
    /// so a batch can carry many of them.
    pub fn state_call(namespace: &str, block: u64) -> Value {
        let data = format!(
            "{}{:0>64}",
            crate::precompile::STATE_SELECTOR,
            strip_hex(namespace).to_lowercase()
        );
        json!([{"to": crate::precompile::ADDRESS, "data": data}, block_tag(block)])
    }

    /// `state(namespace)` on the precompile — the node's own answer for what a
    /// namespace's MMR holds.
    pub async fn mmr_state(&self, namespace: &str, block: u64) -> Result<MmrState> {
        let result = self
            .call("eth_call", Self::state_call(namespace, block))
            .await?;
        decode_state(result.as_str().unwrap_or("0x"))
            .with_context(|| format!("state({namespace}): malformed return"))
    }

    pub async fn storage_at(&self, address: &str, slot: &str, block: u64) -> Result<String> {
        let result = self
            .call("eth_getStorageAt", json!([address, slot, block_tag(block)]))
            .await?;
        Ok(result.as_str().unwrap_or("0x").to_string())
    }
}

/// `(uint256 count, bytes32[] peaks)` as `eth_call` returns it.
pub fn decode_state(returned: &str) -> Option<MmrState> {
    let data = hex::decode(strip_hex(returned)).ok()?;
    let count = u64::try_from(word_to_usize(data.get(0..32)?)?).ok()?;
    let offset = word_to_usize(data.get(32..64)?)?;
    let start = offset.checked_add(32)?;
    let len = word_to_usize(data.get(offset..start)?)?;
    let peaks = data
        .get(start..start.checked_add(len.checked_mul(32)?)?)?
        .chunks(32)
        .map(crate::eth::hex0x)
        .collect();
    Some(MmrState { count, peaks })
}

/// A block number as a JSON-RPC block tag. Every read the audit makes names a
/// block rather than `latest`, so this is never `"latest"`.
pub fn block_tag(block: u64) -> String {
    format!("0x{block:x}")
}
