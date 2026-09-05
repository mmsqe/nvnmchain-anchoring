//! The precompile's log, read from tidx rather than scanned from the node.
//!
//! tidx ingests every log on this chain, so what used to be a scan, a store and
//! a reorg cursor is one SQL result. The coverage it arrives with is not
//! decoration: an index that has not backfilled to the precompile's first block
//! cannot fold a namespace it only saw part of.
//!
//! Queries read the base `logs` table — `topic1`, `topic2`, `data`, all real
//! indexed columns — rather than the decoded event table a `?signature=`
//! parameter would generate. tidx cannot decode these events: a dynamic argument
//! comes back as its ABI offset word (see [`crate::precompile::decode_leaf_appended`]).
//! Reading raw also means the only contract facts in the SQL are two topic0s that
//! `tests/signatures.rs` pins against the compiled ABI.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde_json::Value;

use crate::eth::{address_from_topic, normalize_hex, strip_hex, word_to_usize};
use crate::precompile::{
    decode_leaf_appended, decode_leaves_appended, ADDRESS, LEAF_APPENDED_TOPIC,
    LEAVES_APPENDED_TOPIC,
};

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

/// One leaf, as the index has it: what `LeafAppended` said, and where in the log.
#[derive(Debug, Clone)]
pub struct Leaf {
    pub namespace: String,
    pub index: u64,
    pub commitment: String,
    pub metadata: Vec<u8>,
    pub block_num: u64,
    pub log_idx: u64,
}

/// One append, of either shape, as the audit replays it.
#[derive(Debug, Clone)]
pub enum Appended {
    Leaf {
        index: u64,
        commitment: String,
    },
    Leaves {
        first: u64,
        count: u64,
        chunk_roots: Vec<String>,
        chunk_heights: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub struct Append {
    pub namespace: String,
    pub what: Appended,
    pub root: String,
    pub peaks: Vec<String>,
    pub metadata: Vec<u8>,
    pub block_num: u64,
    pub log_idx: u64,
}

impl Append {
    /// The leaf count this append left behind — which, for the newest one a
    /// namespace has, is what its MMR holds.
    pub fn count(&self) -> u64 {
        match self.what {
            Appended::Leaf { index, .. } => index + 1,
            Appended::Leaves { count, .. } => count,
        }
    }
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
    /// Whether the index reaches back far enough to have seen every append.
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
/// complete one's clothes — an audit over the first 10,000 leaves of a larger
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
    /// boundary that falls inside a partition would compute "newest per
    /// namespace" from half a namespace's rows. Aligned to the partition, every
    /// page's window is as correct as the unpaged one's.
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

    /// Every leaf on the chain as of `up_to`, in log order.
    pub async fn leaves(&self, up_to: u64) -> Result<Vec<Leaf>> {
        let table = self
            .paged(&[], LEAVES_KEY, |after| {
                leaves_sql(self.engine, &[], up_to, after)
            })
            .await?;
        parse_leaves(&table)
    }

    /// Every namespace's appends as of `up_to`, each in log order, in one walk of the
    /// index.
    pub async fn histories(&self, up_to: u64) -> Result<Vec<(String, Vec<Append>)>> {
        let table = self
            .paged(&[], HISTORIES_KEY, |after| {
                histories_sql(self.engine, up_to, after)
            })
            .await?;
        Ok(group_by_namespace(parse_appends(&table)?))
    }

    /// `GET /status`, which is the only way to this: `/query` allowlists
    /// `blocks`, `txs`, `logs` and `receipts`, and refuses `sync_state` by name
    /// with a 422 — a rejection at the HTTP layer, before the `ok: false` body
    /// the rest of this module guards against.
    pub async fn coverage(&self) -> Result<Coverage> {
        parse_coverage(&self.get_json("/status", &[]).await?, self.chain_id)
    }
}

/// `AND topic1 …` over `namespaces`, or nothing at all for every one of them —
/// a caller that meant "none" must not ask.
///
/// `topic1` is a 32-byte word with the address right-aligned, not the 20-byte
/// `address` column beside it, so each is padded: comparing the bare address
/// matches no row, which reads as a registry that has appended nothing.
fn under(engine: Engine, namespaces: &[String]) -> String {
    let word = |ns: &String| engine.bytes_literal(&format!("{:0>64}", strip_hex(ns)));
    match namespaces {
        [] => String::new(),
        [one] => format!(" AND topic1 = {}", word(one)),
        many => format!(
            " AND topic1 IN ({})",
            many.iter().map(word).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// `AND block_num IN (…)`, or nothing — for fetching the leaves beside a set of
/// registry events without walking a namespace.
fn in_blocks(blocks: &[u64]) -> String {
    if blocks.is_empty() {
        return String::new();
    }
    let list: Vec<String> = blocks.iter().map(u64::to_string).collect();
    format!(" AND block_num IN ({})", list.join(", "))
}

/// Both selectors, for the queries that read either shape of append.
fn either_append(engine: Engine) -> String {
    format!(
        "selector IN ({}, {})",
        engine.bytes_literal(LEAF_APPENDED_TOPIC),
        engine.bytes_literal(LEAVES_APPENDED_TOPIC)
    )
}

/// What every walk in log order pages on: the row's place in the log, which is
/// also its order. No window to align to — every row is returned.
pub const LEAVES_KEY: Key<'static> = &[("block_num", "block_num"), ("log_idx", "log_idx")];

/// Every `LeafAppended` row under `namespaces`, oldest first.
///
/// `topic1` is the indexed namespace and `topic2` the leaf index; `data` is
/// decoded here rather than by tidx (see the module docs). Bounded at `up_to`
/// because tidx's realtime sync runs ahead of its contiguous interval: an
/// unbounded query can return a leaf newer than the block the audit reads state
/// at, which reports as a mismatch that is really skew.
pub fn leaves_sql(engine: Engine, namespaces: &[String], up_to: u64, after: &str) -> String {
    leaves_in_sql(engine, namespaces, &[], up_to, after)
}

/// [`leaves_sql`] narrowed to a set of blocks as well — the leaves beside the
/// registry events a lookup by checksum found, fetched without walking a namespace.
pub fn leaves_in_sql(
    engine: Engine,
    namespaces: &[String],
    blocks: &[u64],
    up_to: u64,
    after: &str,
) -> String {
    format!(
        "SELECT topic1 AS namespace, topic2 AS index, data, block_num, log_idx \
         FROM logs WHERE address = {} AND selector = {}{}{} \
               AND block_num <= {up_to}{after} ORDER BY block_num, log_idx",
        engine.bytes_literal(ADDRESS),
        engine.bytes_literal(LEAF_APPENDED_TOPIC),
        under(engine, namespaces),
        in_blocks(blocks),
    )
}

/// What [`appends_sql`] pages on: the namespace, which is also its window's
/// partition, so a page boundary never splits one.
pub const APPENDS_KEY: Key<'static> = &[("namespace", "topic1")];

/// Which end of a namespace's history [`appends_sql`] keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    /// The newest append: the MMR as it stands.
    Newest,
    /// The oldest: what the tree was first loaded with.
    Oldest,
}

/// One append per namespace, of either shape, at `edge` of its history — every
/// event carries the count and peaks it left. A subselect rather than `DISTINCT ON`
/// so it runs on either engine.
pub fn appends_sql(
    engine: Engine,
    namespaces: &[String],
    up_to: u64,
    after: &str,
    edge: Edge,
) -> String {
    let order = match edge {
        Edge::Newest => "DESC",
        Edge::Oldest => "ASC",
    };
    format!(
        "SELECT namespace, index, selector, data, block_num, log_idx FROM (\
           SELECT topic1 AS namespace, topic2 AS index, selector, data, block_num, log_idx, \
                  ROW_NUMBER() OVER (PARTITION BY topic1 \
                                     ORDER BY block_num {order}, log_idx {order}) AS rn \
           FROM logs WHERE address = {} AND {}{} \
                 AND block_num <= {up_to}{after}\
         ) heads WHERE rn = 1 ORDER BY namespace",
        engine.bytes_literal(ADDRESS),
        either_append(engine),
        under(engine, namespaces),
    )
}

/// What [`histories_sql`] pages on: the namespace, then the row's place in the log,
/// so a page boundary inside a namespace falls between two of its rows.
pub const HISTORIES_KEY: Key<'static> = &[
    ("namespace", "topic1"),
    ("block_num", "block_num"),
    ("log_idx", "log_idx"),
];

/// Every append on the chain, of either shape, by namespace and then in log order.
pub fn histories_sql(engine: Engine, up_to: u64, after: &str) -> String {
    format!(
        "SELECT topic1 AS namespace, topic2 AS index, selector, data, block_num, log_idx \
         FROM logs WHERE address = {} AND {} \
               AND block_num <= {up_to}{after} ORDER BY topic1, block_num, log_idx",
        engine.bytes_literal(ADDRESS),
        either_append(engine),
    )
}

/// Rows into leaves. Every log this query returns was written by the precompile,
/// so a row that does not read as one is not a strange leaf — it is the index's
/// copy gone bad, or this query gone wrong. Either is an error, not a skip:
/// dropping a leaf would take it out of every fold and listing silently.
pub fn parse_leaves(table: &Table) -> Result<Vec<Leaf>> {
    let (ns, index, data, block, idx) = (
        table.index_of("namespace")?,
        table.index_of("index")?,
        table.index_of("data")?,
        table.index_of("block_num")?,
        table.index_of("log_idx")?,
    );
    table
        .rows
        .iter()
        .map(|row| {
            let at = || format!("leaf {} / {}", text(row, ns), text(row, index));
            let leaf = hex::decode(strip_hex(text(row, data)))
                .ok()
                .and_then(|payload| decode_leaf_appended(&payload))
                .with_context(|| format!("{}: not a LeafAppended payload", at()))?;
            Ok(Leaf {
                // Checksummed on the way in, so a namespace reads the same here as
                // it does in an explorer and in an envelope's `author` field.
                namespace: address_from_topic(text(row, ns))
                    .with_context(|| format!("{}: malformed namespace topic", at()))?,
                index: topic_number(text(row, index))
                    .with_context(|| format!("{}: malformed index topic", at()))?,
                commitment: leaf.commitment,
                metadata: leaf.metadata,
                block_num: number(row, block).with_context(|| format!("{}: no block_num", at()))?,
                log_idx: number(row, idx).with_context(|| format!("{}: no log_idx", at()))?,
            })
        })
        .collect()
}

/// A number in an indexed topic: a 32-byte word.
fn topic_number(topic: &str) -> Option<u64> {
    let word = hex::decode(strip_hex(topic)).ok()?;
    u64::try_from(word_to_usize(&word)?).ok()
}

/// The rows either append query returns — [`histories_sql`]'s in log order, and
/// [`appends_sql`]'s one per namespace, which is that namespace's MMR.
pub fn parse_appends(table: &Table) -> Result<Vec<Append>> {
    let (ns, index, selector, data, block, idx) = (
        table.index_of("namespace")?,
        table.index_of("index")?,
        table.index_of("selector")?,
        table.index_of("data")?,
        table.index_of("block_num")?,
        table.index_of("log_idx")?,
    );
    table
        .rows
        .iter()
        .map(|row| {
            let at = || format!("namespace {} at block {}", text(row, ns), text(row, block));
            let payload = hex::decode(strip_hex(text(row, data))).unwrap_or_default();
            let topic = normalize_hex(text(row, selector));
            // `topic2` is the leaf index for one shape and the first leaf for the other.
            let position = topic_number(text(row, index))
                .with_context(|| format!("{}: malformed index topic", at()))?;
            let (what, root, peaks, metadata) = if topic == LEAF_APPENDED_TOPIC {
                let leaf = decode_leaf_appended(&payload)
                    .with_context(|| format!("{}: not a LeafAppended payload", at()))?;
                (
                    Appended::Leaf {
                        index: position,
                        commitment: leaf.commitment,
                    },
                    leaf.root,
                    leaf.peaks,
                    leaf.metadata,
                )
            } else if topic == LEAVES_APPENDED_TOPIC {
                let leaves = decode_leaves_appended(&payload)
                    .with_context(|| format!("{}: not a LeavesAppended payload", at()))?;
                (
                    Appended::Leaves {
                        first: position,
                        count: leaves.count,
                        chunk_roots: leaves.chunk_roots,
                        chunk_heights: leaves.chunk_heights,
                    },
                    leaves.root,
                    leaves.peaks,
                    leaves.metadata,
                )
            } else {
                bail!("{}: selector {topic} is neither append", at());
            };
            Ok(Append {
                namespace: address_from_topic(text(row, ns))
                    .with_context(|| format!("{}: malformed namespace topic", at()))?,
                what,
                root,
                peaks,
                metadata,
                block_num: number(row, block).with_context(|| format!("{}: no block_num", at()))?,
                log_idx: number(row, idx).with_context(|| format!("{}: no log_idx", at()))?,
            })
        })
        .collect()
}

/// [`histories_sql`]'s rows grouped by namespace, which the query returns consecutively.
pub fn group_by_namespace(appends: Vec<Append>) -> Vec<(String, Vec<Append>)> {
    let mut out: Vec<(String, Vec<Append>)> = Vec::new();
    for append in appends {
        match out.last_mut() {
            Some((namespace, history)) if *namespace == append.namespace => history.push(append),
            _ => out.push((append.namespace.clone(), vec![append])),
        }
    }
    out
}

/// The chain's entry in a `/status` body. `tip_num` and `head_num` are always
/// serialized, so a missing one is schema drift and errors — defaulted to zero
/// it would bound the queries at block 0, and an audit over nothing reports clean.
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
