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

    /// A byte string as this engine's SQL literal.
    ///
    /// Uncast, though PostgreSQL would take `::bytea`. The cast is redundant —
    /// an unknown literal resolves against the column it is compared to, in a
    /// predicate and across a `UNION` alike — and tidx's pushdown extractor
    /// reads a bare literal but not a cast expression.
    ///
    /// Hex digits only, by construction. These queries are built by string
    /// interpolation, and two callers now put an outside value into one: an
    /// HTTP path segment, and a cursor splicing back a value tidx handed out.
    /// Anything that is not a hex digit is dropped rather than escaped — a
    /// quote cannot reach the literal at all. A backstop, not the validation:
    /// a *filtered* address would query some other address and answer "nothing
    /// here", so callers reject a malformed one up front.
    pub fn bytes_literal(self, value: &str) -> String {
        let hexed: String = strip_hex(value)
            .chars()
            .filter(char::is_ascii_hexdigit)
            .map(|c| c.to_ascii_lowercase())
            .collect();
        match self {
            Self::Postgres => format!("'\\x{hexed}'"),
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

    pub fn index_of(&self, column: &str) -> Result<usize> {
        self.columns
            .iter()
            .position(|c| c.eq_ignore_ascii_case(column))
            .with_context(|| format!("no `{column}` column in {:?}", self.columns))
    }
}

fn array(value: &Value) -> &[Value] {
    value.as_array().map_or(&[], Vec::as_slice)
}

pub fn text(row: &[Value], at: usize) -> &str {
    row.get(at).and_then(Value::as_str).unwrap_or_default()
}

/// tidx's own per-query row cap (`HARD_LIMIT_MAX`), which is also its default:
/// it truncates at this many rows and says nothing about having done so. Pinned
/// here because the only defence is knowing the number — see
/// [`reject_truncated`].
pub const HARD_LIMIT: usize = 10_000;

/// A full page is refused rather than returned.
///
/// [`Tidx::paged`] answers a full page by asking for the next one, so anything
/// that reaches here full was not paged and is a truncated answer wearing a
/// complete one's clothes — an audit over the first 10,000 heads of a larger
/// chain reports clean. Erring on a *legitimately* full page costs one
/// confusing message; not erring costs a silent one.
pub fn reject_truncated(table: Table, limit: usize) -> Result<Table> {
    if table.rows.len() >= limit {
        bail!(
            "tidx returned {} rows, its per-query maximum — this answer is truncated, \
             and a short list here is indistinguishable from a complete one",
            table.rows.len()
        );
    }
    Ok(table)
}

/// A paged query's ordering: the column each value is *read* from, paired with
/// the SQL the predicate is written against. They differ wherever the predicate
/// belongs inside a subquery — `topic1` there is `namespace` in the answer.
pub type Key<'a> = &'a [(&'a str, &'a str)];

/// `AND` … placing a query after `row`, lexicographically over `key`.
///
/// Spelled out rather than as a row-value comparison, which not every engine
/// takes. Numbers go in bare and strings through the engine's byte literal —
/// which is also what keeps a value tidx handed back from reaching SQL as
/// anything but hex.
pub fn cursor_after(engine: Engine, table: &Table, key: Key, row: &[Value]) -> Result<String> {
    let mut cells = Vec::with_capacity(key.len());
    for (column, sql) in key {
        let value = row
            .get(table.index_of(column)?)
            .with_context(|| format!("no `{column}` in the last row"))?;
        cells.push(match value {
            Value::Number(n) => (*sql, n.to_string()),
            Value::String(s) => (*sql, engine.bytes_literal(s)),
            other => bail!("`{column}` is not a cursor column: {other}"),
        });
    }
    // (a, b) > (x, y) as a > x OR (a = x AND b > y), nested to any width.
    let mut predicate = String::new();
    for (name, literal) in cells.iter().rev() {
        predicate = if predicate.is_empty() {
            format!("{name} > {literal}")
        } else {
            format!("{name} > {literal} OR ({name} = {literal} AND ({predicate}))")
        };
    }
    Ok(format!(" AND ({predicate})"))
}

/// A numeric cell. tidx serializes integers as JSON numbers on one engine and
/// as strings on the other, so reading only one of the two drops the column to
/// zero without saying so.
pub fn number(row: &[Value], at: usize) -> Option<u64> {
    match row.get(at)? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

pub struct Tidx {
    client: Client,
    url: String,
    chain_id: u64,
    engine: Engine,
    /// Rows per round trip, and so what a full page means. Defaults to tidx's
    /// own cap; smaller only trades round trips for memory, and lets a test
    /// exercise the paging loop without ten thousand rows to hand.
    page: usize,
}

impl Tidx {
    pub fn new(url: impl Into<String>, chain_id: u64, engine: Engine) -> Result<Self> {
        Self::with_page(url, chain_id, engine, HARD_LIMIT)
    }

    pub fn with_page(
        url: impl Into<String>,
        chain_id: u64,
        engine: Engine,
        page: usize,
    ) -> Result<Self> {
        Ok(Self {
            page: page.clamp(1, HARD_LIMIT),
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
        self.query_with(sql, &[]).await
    }

    /// `GET /query` with generated event tables. Each signature becomes a table
    /// named after its event, with argument names for columns; without one only
    /// the base tables exist. A signature tidx cannot match builds its table off
    /// some other topic0 and returns no rows rather than an error.
    pub async fn query_with(&self, sql: &str, signatures: &[&str]) -> Result<Table> {
        reject_truncated(self.one_page(sql, signatures).await?, self.page)
    }

    /// One page. Left un-checked for truncation because [`Self::paged`] answers a
    /// full page by asking for the next one, which is the whole point.
    async fn one_page(&self, sql: &str, signatures: &[&str]) -> Result<Table> {
        let chain_id = self.chain_id.to_string();
        let limit = self.page.to_string();
        let mut params = vec![
            ("chainId", chain_id.as_str()),
            ("engine", self.engine.as_param()),
            // Asked for explicitly, though it is also tidx's default: the number
            // is what `reject_truncated` recognises, so it should not be one
            // this side merely assumes.
            ("limit", limit.as_str()),
            ("sql", sql),
        ];
        params.extend(signatures.iter().map(|s| ("signature", *s)));
        Table::from_response(&self.get_json("/query", &params).await?)
    }

    /// A query walked to exhaustion, one page per round trip.
    ///
    /// `build` is handed an `AND …` predicate placing it after the last row
    /// seen, and `key` names the columns that predicate is over — which must be
    /// the columns the query orders by.
    ///
    /// For a windowed query those columns must also be the *partition*: a page
    /// boundary that falls inside a partition would compute "newest per key"
    /// from half a key's rows. Aligned to the partition, every page's window is
    /// as correct as the unpaged one's.
    /// A query walked to exhaustion, one page per round trip.
    ///
    /// `build` is handed an `AND …` predicate placing it after the last row
    /// seen, and `key` names the columns that predicate is over — which must be
    /// the columns the query orders by.
    ///
    /// For a windowed query those columns must also be the *partition*: a page
    /// boundary that falls inside a partition would compute "newest per key"
    /// from half a key's rows. Aligned to the partition, every page's window is
    /// as correct as the unpaged one's.
    pub async fn paged(
        &self,
        signatures: &[&str],
        key: Key<'_>,
        build: impl Fn(&str) -> String,
    ) -> Result<Table> {
        let mut all = self.one_page(&build(""), signatures).await?;
        let (mut fetched, mut after) = (all.rows.len(), String::new());
        while fetched >= self.page {
            let last = all
                .rows
                .last()
                .cloned()
                .expect("a full page has a last row");
            let next = cursor_after(self.engine, &all, key, &last)?;
            // A cursor that does not move fetches the same page forever, which
            // means `key` is not unique per row — the caller's bug, not a chain
            // worth asking again.
            if next == after {
                let columns: Vec<_> = key.iter().map(|(c, _)| *c).collect();
                bail!("paging stalled: {} does not advance", columns.join(", "));
            }
            after = next;
            let mut page = self.one_page(&build(&after), signatures).await?;
            fetched = page.rows.len();
            all.rows.append(&mut page.rows);
        }
        Ok(all)
    }

    /// Every `(namespace, key)`'s newest commitment as of `up_to` — what the
    /// audit compares against the chain's storage at that same block.
    pub async fn heads(&self, up_to: u64) -> Result<Vec<Head>> {
        let table = self
            .paged(&[], HEADS_KEY, |after| heads_sql(self.engine, up_to, after))
            .await?;
        parse_heads(&table)
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
pub fn heads_sql(engine: Engine, up_to: u64, after: &str) -> String {
    heads_where(engine, None, up_to, after)
}

/// What [`heads_sql`] pages on: the indexed caller and key, which are also its
/// window's partition, so a page boundary never splits one.
pub const HEADS_KEY: Key<'static> = &[("namespace", "topic1"), ("key", "topic2")];

/// The same rule narrowed to one namespace — one registry's heads, for a
/// projection over its records rather than an audit over the whole chain.
///
/// `topic1` is the caller, and `idx_logs_address_topic1` leads on it, so this is
/// the cheaper query of the two despite doing the same thing.
pub fn namespace_heads_sql(engine: Engine, namespace: &str, up_to: u64, after: &str) -> String {
    heads_where(engine, Some(namespace), up_to, after)
}

fn heads_where(engine: Engine, namespace: Option<&str>, up_to: u64, after: &str) -> String {
    let scope = namespace.map_or_else(String::new, |ns| {
        // `topic1` is a 32-byte word with the address right-aligned, not the
        // 20-byte `address` column beside it. Comparing the bare address matches
        // no row at all, which reads as a registry that has anchored nothing.
        let word = format!("{:0>64}", strip_hex(ns));
        format!(" AND topic1 = {}", engine.bytes_literal(&word))
    });
    format!(
        "SELECT namespace, key, data FROM (\
           SELECT topic1 AS namespace, topic2 AS key, data, \
                  ROW_NUMBER() OVER (PARTITION BY topic1, topic2 \
                                     ORDER BY block_num DESC, log_idx DESC) AS rn \
           FROM logs WHERE address = {} AND selector = {}{scope} \
                 AND block_num <= {up_to}{after}\
         ) heads WHERE rn = 1 ORDER BY namespace, key",
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
