//! The anchored log, read from tidx rather than scanned from the node.
//!
//! tidx ingests every log on this chain, so what used to be a scan, a store and
//! a reorg cursor is one SQL result. The coverage it arrives with is not
//! decoration: an index that has not backfilled to the precompile's first block
//! cannot be audited for keys it never saw.
//!
//! Queries read the base `logs` table — `topic1`, `topic2`, `data`, all real
//! indexed columns — rather than the decoded event table a `?signature=`
//! parameter would generate. tidx cannot decode this event: dynamic `bytes`
//! comes back as its ABI offset word (see [`crate::precompile::decode_anchored_data`]).
//! Reading raw also means the only contract fact in the SQL is a topic0 that
//! `tests/signatures.rs` already pins against the compiled ABI.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde_json::Value;

use crate::eth::{address_from_topic, normalize_hex, strip_hex};
use crate::precompile::{decode_anchored_data, ADDRESS, ANCHORED_TOPIC};

/// Which engine the query runs on. It decides one thing that matters here: a
/// byte string is `'\x…'` for PostgreSQL and `'0x…'` for ClickHouse, so a
/// predicate carried between them matches nothing — an empty result, not an
/// error. Results come back `0x`-prefixed either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    Postgres,
    ClickHouse,
}

impl Engine {
    /// The `?engine=` value, and the name it is configured by.
    pub fn as_param(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::ClickHouse => "clickhouse",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [Self::Postgres, Self::ClickHouse]
            .into_iter()
            .find(|e| e.as_param().eq_ignore_ascii_case(value.trim()))
    }

    /// A byte string as this engine's SQL literal. The PostgreSQL cast is
    /// redundant — an unknown literal resolves against the `bytea` column it is
    /// compared to — but it is the spelling `tempo-e2e` already proves against a
    /// running tidx, and being explicit costs nothing.
    pub fn bytes_literal(self, value: &str) -> String {
        let hexed = strip_hex(value).to_lowercase();
        match self {
            Self::Postgres => format!("'\\x{hexed}'::bytea"),
            Self::ClickHouse => format!("'0x{hexed}'"),
        }
    }
}

/// One `(namespace, key)`'s current commitment, as the index has it.
#[derive(Debug, Clone)]
pub struct Head {
    pub namespace: String,
    pub key: String,
    pub commitment: String,
    pub metadata: Vec<u8>,
}

/// How much of the chain the index holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Coverage {
    /// How far ingest has reached, and the block every audited read is pinned to.
    ///
    /// `tip_num`, not `synced_num`. Realtime sync advances this one and leaves
    /// `synced_num` to gap-fill — tidx's own writer calls it "avoids clobbering
    /// synced_num" — so on an index following the chain rather than backfilling
    /// it, `synced_num` sits below rows that are already there. An audit bounded
    /// by it checks almost nothing and reports clean.
    pub tip_num: u64,
    /// The lowest block of the contiguous interval. `None` before backfill starts.
    pub backfill_num: Option<u64>,
    pub head_num: u64,
}

impl Coverage {
    /// Whether the index reaches back far enough to have seen every anchor.
    pub fn reaches(&self, first_block: u64) -> bool {
        matches!(self.backfill_num, Some(floor) if floor <= first_block)
    }

    /// Blocks behind the chain. Normal and transient — the audit pins its reads
    /// to `tip_num` rather than treating lag as a fault.
    pub fn lag(&self) -> u64 {
        self.head_num.saturating_sub(self.tip_num)
    }
}

/// A `/query` result: named columns and the rows under them.
#[derive(Debug, Clone)]
pub struct Table {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
}

impl Table {
    /// A `/query` body as a table. tidx answers 200 with `ok: false` for a
    /// rejected query, so the status code alone would read a refusal as an
    /// empty result — which is also what a wrong-but-accepted query looks like.
    pub fn from_response(response: &Value) -> Result<Self> {
        if response.get("ok").and_then(Value::as_bool) != Some(true) {
            bail!("tidx refused the query: {response}");
        }
        Ok(Self {
            columns: array(&response["columns"])
                .iter()
                .map(|c| c.as_str().unwrap_or_default().to_string())
                .collect(),
            rows: array(&response["rows"])
                .iter()
                .map(|row| array(row).to_vec())
                .collect(),
        })
    }

    fn index_of(&self, column: &str) -> Result<usize> {
        self.columns
            .iter()
            .position(|c| c.eq_ignore_ascii_case(column))
            .with_context(|| format!("no `{column}` column in {:?}", self.columns))
    }
}

fn array(value: &Value) -> &[Value] {
    value.as_array().map_or(&[], Vec::as_slice)
}

fn text(row: &[Value], at: usize) -> &str {
    row.get(at).and_then(Value::as_str).unwrap_or_default()
}

pub struct Tidx {
    client: Client,
    url: String,
    chain_id: u64,
    engine: Engine,
}

impl Tidx {
    pub fn new(url: impl Into<String>, chain_id: u64, engine: Engine) -> Result<Self> {
        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .context("build http client")?,
            url: url.into().trim_end_matches('/').to_string(),
            chain_id,
            engine,
        })
    }

    async fn get_json(&self, path: &str, params: &[(&str, &str)]) -> Result<Value> {
        self.client
            .get(format!("{}{path}", self.url))
            .query(params)
            .send()
            .await
            .with_context(|| format!("tidx {path} request"))?
            .json()
            .await
            .with_context(|| format!("tidx {path} response"))
    }

    /// `GET /query`, over the base tables.
    pub async fn query(&self, sql: &str) -> Result<Table> {
        let chain_id = self.chain_id.to_string();
        let params = [
            ("chainId", chain_id.as_str()),
            ("engine", self.engine.as_param()),
            ("sql", sql),
        ];
        Table::from_response(&self.get_json("/query", &params).await?)
    }

    /// Every `(namespace, key)`'s newest commitment as of `up_to` — what the
    /// audit compares against the chain's storage at that same block.
    pub async fn heads(&self, up_to: u64) -> Result<Vec<Head>> {
        parse_heads(&self.query(&heads_sql(self.engine, up_to)).await?)
    }

    /// `GET /status`, which is the only way to this: `/query` allowlists
    /// `blocks`, `txs`, `logs` and `receipts`, and refuses `sync_state` by name
    /// with a 422 — a rejection at the HTTP layer, before the `ok: false` body
    /// the rest of this module guards against.
    pub async fn coverage(&self) -> Result<Coverage> {
        parse_coverage(&self.get_json("/status", &[]).await?, self.chain_id)
    }
}

/// The precompile's own rule as SQL: one word per `(namespace, key)`, newest
/// anchor wins. A subselect rather than `DISTINCT ON` so it runs on either
/// engine, and the address and topic are spelled for the one it will run on.
///
/// `topic1` and `topic2` are the indexed `caller` and `key`; `data` is decoded
/// here rather than by tidx (see the module docs).
///
/// Bounded at `up_to` because tidx's realtime sync runs ahead of its contiguous
/// interval: an unbounded query can return a head newer than the block the
/// audit reads state at, which reports as a mismatch that is really skew.
pub fn heads_sql(engine: Engine, up_to: u64) -> String {
    format!(
        "SELECT namespace, key, data FROM (\
           SELECT topic1 AS namespace, topic2 AS key, data, \
                  ROW_NUMBER() OVER (PARTITION BY topic1, topic2 \
                                     ORDER BY block_num DESC, log_idx DESC) AS rn \
           FROM logs WHERE address = {} AND selector = {} AND block_num <= {up_to}\
         ) heads WHERE rn = 1",
        engine.bytes_literal(ADDRESS),
        engine.bytes_literal(ANCHORED_TOPIC),
    )
}

/// Rows into heads. Every log this query returns was written by the precompile,
/// so a row that does not read as one is not a strange anchor — it is the
/// index's copy gone bad, or this query gone wrong. Either is an error, not a
/// skip: the query keeps only each pair's newest row, so dropping a corrupt one
/// would take its whole `(namespace, key)` out of the audit silently.
pub fn parse_heads(table: &Table) -> Result<Vec<Head>> {
    let (ns, key, data) = (
        table.index_of("namespace")?,
        table.index_of("key")?,
        table.index_of("data")?,
    );
    table
        .rows
        .iter()
        .map(|row| {
            let (commitment, metadata) = hex::decode(strip_hex(text(row, data)))
                .ok()
                .and_then(|payload| decode_anchored_data(&payload))
                .with_context(|| format!("key {}: not an Anchored payload", text(row, key)))?;
            Ok(Head {
                // Checksummed on the way in, so a head reads the same here as
                // it does in an explorer and in an envelope's `creator` field.
                namespace: address_from_topic(text(row, ns)).with_context(|| {
                    format!("key {}: malformed namespace topic", text(row, key))
                })?,
                key: normalize_hex(text(row, key)),
                commitment,
                metadata,
            })
        })
        .collect()
}

/// The chain's entry in a `/status` body. `tip_num` and `head_num` are always
/// serialized, so a missing one is schema drift and errors — defaulted to zero
/// it would bound the heads query at block 0, and an audit over zero heads
/// reports clean.
pub fn parse_coverage(response: &Value, chain_id: u64) -> Result<Coverage> {
    let chain = array(&response["chains"])
        .iter()
        .find(|c| c["chain_id"].as_u64() == Some(chain_id))
        .with_context(|| format!("chain {chain_id} is not in tidx's /status: {response}"))?;
    let field = |name: &str| match &chain[name] {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    };
    let required =
        |name: &str| field(name).with_context(|| format!("no `{name}` in /status entry: {chain}"));
    Ok(Coverage {
        tip_num: required("tip_num")?,
        backfill_num: field("backfill_num"),
        head_num: required("head_num")?,
    })
}
