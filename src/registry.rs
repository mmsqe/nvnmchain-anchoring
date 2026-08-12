//! `Registry`'s own events — where role history lives.
//!
//! Role changes are not anchored: membership is each registry's state, read with
//! `hasRole`, and history is these events, which carry every field they need. A
//! third copy in the anchored log would only be something to drift.
//!
//! `roles` folds in SQL over an index because every argument outside the topics
//! is `bytes32`, which tidx decodes itself; a dynamic one comes back as its ABI
//! offset word ([`crate::tidx::heads_sql`] reads raw `data` for that reason).
//!
//! A whole records projection does not fold that far, but its *numbering* does.
//! [`record_ids_sql`] is where the record id went when the contract stopped
//! assigning one.
//!
//! Neither query is run here. Both are what a caller sends tidx, and nothing in
//! this crate reads the answer.

use anyhow::{Context, Result};

use std::collections::BTreeMap;

use serde::Serialize;

use crate::envelope::{bytes32_label, decode_envelope, decode_strings};
use crate::eth::{address_from_topic, normalize_hex, strip_hex};
use crate::tidx::{number, text, Engine, Head, Key, Table};

/// `RegistryDeployed`'s topic0, the selector [`registries_sql`] filters on.
/// The factory's event, not a registry's -- but it belongs in the same table so
/// the same fixture check covers it.
pub const REGISTRY_DEPLOYED_TOPIC: &str =
    "0xf4b5c87afebf8726b6bcc7e82c820be7557069b4f32a003e37772dd4d67cd576";

/// `RecordAdded`'s topic0, the selector [`record_ids_sql`] filters on. Named so
/// the query and the [`REGISTRY_TOPICS`] row checked against the contract cannot
/// come apart.
pub const RECORD_ADDED_TOPIC: &str =
    "0xb4aaf705a3bf1baf4b094ef32b3517c8df84a8766f0d751a0c85aa41b63be45c";

/// `(topic0, signature)` for every event the registry contracts emit, canonical
/// form -- the factory's deployment announcement included.
/// `tests/signatures.rs` checks the hashes against these signatures and the
/// signatures against the contract, so neither can sit here quietly matching
/// nothing — a signature that drifts builds its table off some other topic0
/// and decodes empty rather than failing.
pub const REGISTRY_TOPICS: &[(&str, &str)] = &[
    (
        REGISTRY_DEPLOYED_TOPIC,
        "RegistryDeployed(address,address,string,string,string)",
    ),
    (RECORD_ADDED_TOPIC, "RecordAdded(bytes32,uint256,string)"),
    (
        "0x7735f518b96096d1410ef5122b09bdb190e8d94e93e6896cbeff28f034ea883c",
        "RecordStatusUpdated(bytes32,uint256,string)",
    ),
    (
        "0xd61bf855a7ed7c857a0c46025807cab964fad9226a03392763af3e0c57ea4ae2",
        "RoleGranted(bytes32,address,bytes32)",
    ),
    (
        "0x3e24446ed0a47b5a935b76dac730872c525ce8eff3f3e5c159b83e0a7f0bd40d",
        "RoleRevoked(bytes32,address,bytes32)",
    ),
];

/// The events [`roles_sql`] reads, in the form `?signature=` takes: argument
/// names become result columns, `indexed` says which come from the topics.
///
/// The same events as above said twice — those are what a topic0 hashes from,
/// these are what tidx parses — so `tests/signatures.rs` checks one against the
/// other. A drift decodes an empty table rather than failing.
///
/// Two, not three: a registry announces its creator's admin as an ordinary
/// `RoleGranted` when the factory initializes it, so the fold needs no seed.
pub const ROLE_EVENTS: &[&str] = &[
    "RoleGranted(bytes32 indexed checksumHash, address indexed account, bytes32 role)",
    "RoleRevoked(bytes32 indexed checksumHash, address indexed account, bytes32 role)",
];

/// A head query like the precompile's: newest row per `(checksumHash, account,
/// role)` wins, kept only if it granted. Revokes are ordered against grants
/// rather than subtracted from them — the same key can be granted, revoked and
/// granted again.
///
/// The address is a parameter because a registry is a deployment, and tidx's
/// generated CTEs filter on topic0 alone. It is also the whole partition: one
/// contract per registry is what removed the registry id from the key, the seed
/// arm that used to supply the creator's admin, and the `topic1` narrowing that
/// used to keep one registry's answer out of another's.
/// What [`roles_sql`] pages on, which is the role key its window partitions by.
pub const ROLES_KEY: Key<'static> = &[
    ("checksumHash", "\"checksumHash\""),
    ("account", "account"),
    ("role", "role"),
];

pub fn roles_sql(engine: Engine, registry: &str, up_to: u64, after: &str) -> String {
    // Repeated into both arms on purpose. tidx pushes these predicates into the
    // CTEs it generates, and PostgreSQL inlines those CTEs and pushes them again;
    // the copies here are what filters if either ever stops.
    let filter = format!(
        "address = {} AND block_num <= {up_to}{after}",
        engine.bytes_literal(registry),
    );
    // The role key: what the projection returns, and what it partitions by.
    // Written once so the two cannot drift into answering different questions.
    let key = "\"checksumHash\", account, role";
    let arm = |table, granted| {
        format!(
            "SELECT block_num, log_idx, {key}, {granted} AS granted FROM {table} WHERE {filter}"
        )
    };
    format!(
        "WITH acl AS ({granted} UNION ALL {revoked}) \
         SELECT {key}, block_num FROM (\
           SELECT {key}, block_num, granted, \
                  ROW_NUMBER() OVER (PARTITION BY {key} \
                                     ORDER BY block_num DESC, log_idx DESC) AS rn \
           FROM acl\
         ) held WHERE rn = 1 AND granted ORDER BY {key}",
        granted = arm("RoleGranted", "TRUE"),
        revoked = arm("RoleRevoked", "FALSE"),
    )
}

/// The record ids the contract stopped assigning: `RecordAdded` in first-anchor
/// order, numbered from 1 within one registry — the whole of what `recordCount`
/// and `recordIdByChecksum` did before a record became `keccak256(checksum)`.
///
/// Reads the base `logs` table rather than a generated one: the checksum hash is
/// `topic1`, so numbering never touches the data section and needs no
/// `?signature=`.
///
/// The window keeps each checksum's *first* appearance — numbering the rows
/// themselves would give every version an id, so re-anchoring an early record
/// would shift every record after it. Ascending, where
/// [`crate::tidx::heads_sql`] is descending: that wants the newest row per key,
/// this one the oldest.
///
/// Ordered by the hash so it can page on its own partition; the numbering is
/// applied to the result by [`parse_record_ids`], since no page knows what came
/// before it.
///
/// Cost tracks the registry's own `RecordAdded` rows, not the chain. Measured on
/// tidx's schema in PostgreSQL 16, index-backed with no sequential scan:
///
/// | query | rows scanned | rows out | time |
/// |---|---|---|---|
/// | this, 20k-record registry | 60k | 20k | 37ms |
/// | this, 200k-record registry | 600k | 200k | 468ms |
/// | `heads_sql`, for scale | 200k | 40k | 153ms |
///
/// A full walk, with no cheap single-record path — a number is a property of
/// the whole ordering. Materialize it for a large registry rather
/// than answering a page load with it.
/// What [`record_ids_sql`] pages on: the checksum hash, which is its window's
/// partition, so a page holds every row of every record it reports on.
pub const RECORD_IDS_KEY: Key<'static> = &[("checksum_hash", "topic1")];

pub fn record_ids_sql(engine: Engine, registry: &str, up_to: u64, after: &str) -> String {
    format!(
        "SELECT checksum_hash, block_num, log_idx FROM (\
           SELECT topic1 AS checksum_hash, block_num, log_idx, \
                  ROW_NUMBER() OVER (PARTITION BY topic1 \
                                     ORDER BY block_num, log_idx) AS rn \
           FROM logs WHERE address = {} AND selector = {} \
                 AND block_num <= {up_to}{after}\
         ) firsts WHERE rn = 1 ORDER BY checksum_hash",
        engine.bytes_literal(registry),
        engine.bytes_literal(RECORD_ADDED_TOPIC),
    )
}

/// Every registry one factory deployed, in deployment order.
///
/// No envelope behind it: name, description and metadata are descriptive, set
/// once, and ride in the event itself. They are dynamic `string`s, so the row
/// carries raw `data` for [`crate::envelope::decode_strings`] rather than a
/// column tidx generated -- the same reason [`crate::tidx::heads_sql`] reads
/// raw `data`.
///
/// Ordered, because deployment order is the canonical numbering: an index into
/// this list is what an on-chain counter would have assigned. The factory
/// address is a parameter for the reason it is everywhere else here -- tidx's
/// tables filter on topic0 alone, so without it any contract emitting the same
/// event answers too.
/// What [`registries_sql`] pages on. No window to align to — deployment order
/// *is* the order, so the cursor is the last row's place in the log.
pub const REGISTRIES_KEY: Key<'static> = &[("block_num", "block_num"), ("log_idx", "log_idx")];

pub fn registries_sql(engine: Engine, factory: &str, up_to: u64, after: &str) -> String {
    format!(
        "SELECT topic1 AS registry, topic2 AS creator, data, block_num, log_idx \
         FROM logs WHERE address = {} AND selector = {} AND block_num <= {up_to}{after} \
         ORDER BY block_num, log_idx",
        engine.bytes_literal(factory),
        engine.bytes_literal(REGISTRY_DEPLOYED_TOPIC),
    )
}

/// One registry, as the deployment log announces it.
#[derive(Debug, Clone, Serialize)]
pub struct Deployed {
    /// Deployment order, 1-based — what an on-chain counter would have assigned,
    /// and the same rule [`record_ids_sql`] applies one level down.
    pub number: u64,
    pub address: String,
    pub creator: String,
    pub name: String,
    pub description: String,
    pub metadata: String,
    pub block_num: u64,
}

/// [`registries_sql`]'s rows. The strings come out of raw `data` here, so a row
/// that is not a `RegistryDeployed` payload is an error rather than a registry
/// with empty fields — the query is scoped to one factory and one topic0, so a
/// payload that will not decode means the schema moved, not that a caller
/// anchored something odd.
pub fn parse_registries(table: &Table) -> Result<Vec<Deployed>> {
    const STRINGS: &[&str] = &["name", "description", "metadata"];
    let (registry, creator, data, block) = (
        table.index_of("registry")?,
        table.index_of("creator")?,
        table.index_of("data")?,
        table.index_of("block_num")?,
    );
    table
        .rows
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let at = || format!("row {i}");
            let fields = hex::decode(strip_hex(text(row, data)))
                .ok()
                .and_then(|raw| decode_strings(STRINGS, &raw))
                .with_context(|| format!("{}: not a RegistryDeployed payload", at()))?;
            let field = |name: &str| {
                fields
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map_or(String::new(), |(_, v)| v.clone())
            };
            Ok(Deployed {
                number: i as u64 + 1,
                address: address_from_topic(text(row, registry))
                    .with_context(|| format!("{}: malformed registry topic", at()))?,
                creator: address_from_topic(text(row, creator))
                    .with_context(|| format!("{}: malformed creator topic", at()))?,
                name: field("name"),
                description: field("description"),
                metadata: field("metadata"),
                block_num: number(row, block).with_context(|| format!("{}: no block_num", at()))?,
            })
        })
        .collect()
}

/// One role a registry holds as granted.
#[derive(Debug, Clone, Serialize)]
pub struct RoleHeld {
    /// `keccak256("")` for a registry-scoped role, the record's checksum hash
    /// otherwise. Not resolvable back to the checksum — it is a hash.
    pub scope: String,
    pub account: String,
    /// `admin` or `editor`, read back from its right-padded `bytes32`.
    pub role: String,
    pub block_num: u64,
}

/// [`roles_sql`]'s rows. Every column is `bytes32` or an address, so these come
/// from tables tidx decoded rather than from raw `data`.
pub fn parse_roles(table: &Table) -> Result<Vec<RoleHeld>> {
    let (scope, account, role, block) = (
        table.index_of("checksumHash")?,
        table.index_of("account")?,
        table.index_of("role")?,
        table.index_of("block_num")?,
    );
    table
        .rows
        .iter()
        .enumerate()
        .map(|(i, row)| {
            Ok(RoleHeld {
                scope: normalize_hex(text(row, scope)),
                account: address_from_topic(text(row, account))
                    .unwrap_or_else(|| normalize_hex(text(row, account))),
                role: hex::decode(strip_hex(text(row, role)))
                    .ok()
                    .and_then(|raw| <[u8; 32]>::try_from(raw.as_slice()).ok())
                    .map_or_else(|| normalize_hex(text(row, role)), |w| bytes32_label(&w)),
                block_num: number(row, block).with_context(|| format!("row {i}: no block_num"))?,
            })
        })
        .collect()
}

/// [`record_ids_sql`]'s rows, as `checksum_hash -> record_id`.
///
/// The numbering happens here rather than in SQL. The query pages on the
/// checksum hash, so it arrives in hash order and no page knows how many
/// records came before it — but sorted back into first-anchor order, a record's
/// position *is* the id the contract used to assign.
pub fn parse_record_ids(table: &Table) -> Result<BTreeMap<String, u64>> {
    let (hash, block, idx) = (
        table.index_of("checksum_hash")?,
        table.index_of("block_num")?,
        table.index_of("log_idx")?,
    );
    let mut firsts = table
        .rows
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let at = |name| format!("row {i}: no {name}");
            Ok((
                number(row, block).with_context(|| at("block_num"))?,
                number(row, idx).with_context(|| at("log_idx"))?,
                normalize_hex(text(row, hash)),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    firsts.sort_unstable();
    Ok(firsts
        .into_iter()
        .enumerate()
        .map(|(i, (_, _, hash))| (hash, i as u64 + 1))
        .collect())
}

/// One record at its newest version, with the status anchored against that
/// version if there is one.
#[derive(Debug, Clone, Serialize)]
pub struct Record {
    /// The id the contract stopped assigning, from [`parse_record_ids`]. `None`
    /// only if the two queries disagree, which is worth seeing rather than
    /// hiding behind a zero.
    pub number: Option<u64>,
    pub checksum_hash: String,
    /// The newest version index. The head holds only this one — earlier
    /// versions are in the log, not in state.
    pub version: u64,
    pub uri: String,
    pub checksum: String,
    pub checksum_algo: String,
    pub metadata: String,
    pub timestamp: u64,
    pub status: Option<String>,
}

/// A registry's records, from its heads.
///
/// A head that will not decode is an error: only this registry anchors under its
/// namespace and only in these two shapes, so skipping one would drop a record
/// and still look like a full list. Statuses attach only to the version they
/// name — one against version 2 of a record now at 3 is not its status.
pub fn parse_records(heads: &[Head], numbers: &BTreeMap<String, u64>) -> Result<Vec<Record>> {
    let mut records: BTreeMap<String, Record> = BTreeMap::new();
    let mut statuses: BTreeMap<(String, u64), String> = BTreeMap::new();

    for head in heads {
        let envelope = decode_envelope(&head.key, &head.metadata)
            .with_context(|| format!("key {}: not a registry envelope", head.key))?;
        let hash = normalize_hex(envelope.field("checksum_hash"));
        let index = envelope
            .field("index")
            .parse::<u64>()
            .with_context(|| format!("key {}: index {:?}", head.key, envelope.field("index")))?;
        match envelope.kind {
            "record" => {
                records.insert(
                    hash.clone(),
                    Record {
                        number: numbers.get(&hash).copied(),
                        checksum_hash: hash,
                        version: index,
                        uri: envelope.field("uri").to_string(),
                        checksum: envelope.field("checksum").to_string(),
                        checksum_algo: envelope.field("checksum_algo").to_string(),
                        metadata: envelope.field("metadata").to_string(),
                        timestamp: envelope.field("timestamp").parse().with_context(|| {
                            format!(
                                "key {}: timestamp {:?}",
                                head.key,
                                envelope.field("timestamp")
                            )
                        })?,
                        status: None,
                    },
                );
            }
            "status" => {
                statuses.insert((hash, index), envelope.field("status").to_string());
            }
            other => anyhow::bail!("key {}: unknown envelope kind {other}", head.key),
        }
    }

    let mut out: Vec<Record> = records
        .into_values()
        .map(|mut record| {
            record.status = statuses
                .get(&(record.checksum_hash.clone(), record.version))
                .cloned();
            record
        })
        .collect();
    // In the order the contract would have numbered them; unnumbered last, so a
    // disagreement between the two queries stands out instead of sorting as 0.
    out.sort_by_key(|r| (r.number.is_none(), r.number, r.checksum_hash.clone()));
    Ok(out)
}
