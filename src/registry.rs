//! `Registry`'s own events, and its records read out of the precompile's leaves.
//!
//! Role changes are not leaves: membership is each registry's state, read with
//! `hasRole`, and history is these events, which carry every field they need.
//! `roles` folds in SQL over an index because every argument outside the topics
//! is `bytes32`, which tidx decodes itself; a dynamic one comes back as its ABI
//! offset word ([`crate::tidx::leaves_sql`] reads raw `data` for that reason).
//!
//! A whole records projection does not fold that far, but its *numbering* does.
//! [`record_ids_sql`] is where the record id went when the contract stopped
//! assigning one. And a lookup *by checksum* starts from `RecordAdded`, whose
//! `topic1` is the checksum hash: the leaf beside it in the same transaction is
//! the version's envelope.

use anyhow::{Context, Result};

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::envelope::{
    bytes32_label, decode_envelope, decode_strings, decode_uint_string, Envelope,
};
use crate::eth::{address_from_topic, checksum_address, normalize_hex, strip_hex, word_to_usize};
use crate::tidx::{number, text, Engine, Key, Leaf, Table};

/// `RegistryDeployed`'s topic0, the selector [`registries_sql`] filters on.
/// The factory's event, not a registry's -- but it belongs in the same table so
/// the same fixture check covers it.
pub const REGISTRY_DEPLOYED_TOPIC: &str =
    "0xf4b5c87afebf8726b6bcc7e82c820be7557069b4f32a003e37772dd4d67cd576";

/// `RecordAdded`'s topic0, the selector [`record_ids_sql`] and
/// [`record_added_sql`] filter on. Named so the queries and the
/// [`REGISTRY_TOPICS`] row checked against the contract cannot come apart.
pub const RECORD_ADDED_TOPIC: &str =
    "0x0024919acb3ad6f0be467a901b1e780b3d21245c92d17015954313ee46a28005";

/// `RecordStatusUpdated`'s topic0, the selector [`status_updated_sql`] filters on.
pub const RECORD_STATUS_UPDATED_TOPIC: &str =
    "0x7735f518b96096d1410ef5122b09bdb190e8d94e93e6896cbeff28f034ea883c";

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
    (
        RECORD_ADDED_TOPIC,
        "RecordAdded(bytes32,uint256,string,uint8,string,address)",
    ),
    (
        RECORD_STATUS_UPDATED_TOPIC,
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

/// A window query like the MMR-head one: newest row per `(checksumHash, account,
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
/// themselves would give every version an id, so re-adding an early record
/// would shift every record after it. Ascending, where the MMR-head query is
/// descending: that wants the newest row per namespace, this one the oldest.
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

/// What [`record_added_sql`] and [`status_updated_sql`] page on: their place in
/// the log, which is also their order.
pub const EVENTS_KEY: Key<'static> = &[("block_num", "block_num"), ("log_idx", "log_idx")];

/// `AND address = …`, or nothing: one registry's events, or every emitter's.
fn emitter(engine: Engine, registry: Option<&str>) -> String {
    registry.map_or(String::new(), |r| {
        format!(" AND address = {}", engine.bytes_literal(r))
    })
}

/// Every `RecordAdded` for one checksum hash, oldest first — under one registry,
/// or under every emitter, which is what a lookup across registries starts from.
///
/// `topic1` is the checksum hash, indexed, so this never walks a registry. The
/// version's own fields are in the leaf beside it, which [`pair_leaves`] finds.
pub fn record_added_sql(
    engine: Engine,
    registry: Option<&str>,
    hash: &str,
    up_to: u64,
    after: &str,
) -> String {
    format!(
        "SELECT address, block_num, log_idx, data \
         FROM logs WHERE selector = {} AND topic1 = {}{} \
               AND block_num <= {up_to}{after} ORDER BY block_num, log_idx",
        engine.bytes_literal(RECORD_ADDED_TOPIC),
        engine.bytes_literal(hash),
        emitter(engine, registry),
    )
}

/// Every `RecordStatusUpdated` for one checksum hash, oldest first. The status
/// text is in the event itself, so no leaf is needed beside it.
pub fn status_updated_sql(
    engine: Engine,
    registry: Option<&str>,
    hash: &str,
    up_to: u64,
    after: &str,
) -> String {
    format!(
        "SELECT address, block_num, log_idx, data \
         FROM logs WHERE selector = {} AND topic1 = {}{} \
               AND block_num <= {up_to}{after} ORDER BY block_num, log_idx",
        engine.bytes_literal(RECORD_STATUS_UPDATED_TOPIC),
        engine.bytes_literal(hash),
        emitter(engine, registry),
    )
}

/// Every registry one factory deployed, in deployment order.
///
/// No envelope behind it: name, description and metadata are descriptive, set
/// once, and ride in the event itself. They are dynamic `string`s, so the row
/// carries raw `data` for [`crate::envelope::decode_strings`] rather than a
/// column tidx generated -- the same reason the leaves query reads raw `data`.
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

/// Whether one address is a registry this factory deployed.
///
/// The announced address is `topic1` and indexed, so this is a lookup where
/// [`registries_sql`] is a walk. It answers the question the module answered with
/// "registry 999 does not exist": an id was a number the module could check
/// against its counter, and the address that replaced it carries no such fact —
/// the deployment log is where it went.
pub fn deployment_sql(engine: Engine, factory: &str, registry: &str, up_to: u64) -> String {
    let word = format!("{:0>64}", strip_hex(registry));
    format!(
        "SELECT block_num FROM logs WHERE address = {} AND selector = {} AND topic1 = {} \
               AND block_num <= {up_to} ORDER BY block_num",
        engine.bytes_literal(factory),
        engine.bytes_literal(REGISTRY_DEPLOYED_TOPIC),
        engine.bytes_literal(&word),
    )
}

/// One registry, as the deployment log announces it.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Which registries to keep, by name — the module's `registriesByName`.
///
/// Applied after decoding rather than in SQL, and not for convenience: the name
/// is a dynamic `string` in the deployment event, which is exactly what tidx
/// hands back as an ABI offset word. There is nothing to filter on in the query,
/// so the walk is the one `/registries` already does and only the rows returned
/// differ.
///
/// Byte-exact in every mode, because a name is not an identifier here — the
/// address is — and a filter matching a name the caller did not write would be
/// answering about a different registry. Every set filter has to match, so a
/// contradictory pair returns nothing rather than one of them silently winning.
#[derive(Debug, Clone, Default)]
pub struct NameFilter {
    pub name: Option<String>,
    pub prefix: Option<String>,
    pub suffix: Option<String>,
    pub contains: Option<String>,
}

impl NameFilter {
    pub fn matches(&self, name: &str) -> bool {
        self.name.as_ref().is_none_or(|exact| name == exact)
            && self.prefix.as_ref().is_none_or(|p| name.starts_with(p))
            && self.suffix.as_ref().is_none_or(|s| name.ends_with(s))
            && self.contains.as_ref().is_none_or(|c| name.contains(c))
    }
}

/// [`registries_sql`]'s rows. The strings come out of raw `data` here, so a row
/// that is not a `RegistryDeployed` payload is an error rather than a registry
/// with empty fields — the query is scoped to one factory and one topic0, so a
/// payload that will not decode means the schema moved, not that a caller
/// appended something odd.
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

/// One `RecordAdded`: where it sits in the log, and the version it announced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordEvent {
    pub registry: String,
    pub block_num: u64,
    pub log_idx: u64,
    pub index: u64,
}

/// One `RecordStatusUpdated`: where it sits, and the status it set on a version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusEvent {
    pub registry: String,
    pub block_num: u64,
    pub log_idx: u64,
    pub index: u64,
    pub status: String,
}

/// [`record_added_sql`]'s rows. The version is the first data word; the rest of
/// the data section is what the leaf beside it carries in full.
pub fn parse_record_events(table: &Table) -> Result<Vec<RecordEvent>> {
    let (address, block, idx, data) = (
        table.index_of("address")?,
        table.index_of("block_num")?,
        table.index_of("log_idx")?,
        table.index_of("data")?,
    );
    table
        .rows
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let at = |what: &str| format!("row {i}: {what}");
            let raw = hex::decode(strip_hex(text(row, data))).unwrap_or_default();
            Ok(RecordEvent {
                registry: checksum_address(text(row, address)),
                block_num: number(row, block).with_context(|| at("no block_num"))?,
                log_idx: number(row, idx).with_context(|| at("no log_idx"))?,
                index: raw
                    .get(..32)
                    .and_then(word_to_usize)
                    .and_then(|n| u64::try_from(n).ok())
                    .with_context(|| at("not a RecordAdded payload"))?,
            })
        })
        .collect()
}

/// [`status_updated_sql`]'s rows.
pub fn parse_status_events(table: &Table) -> Result<Vec<StatusEvent>> {
    let (address, block, idx, data) = (
        table.index_of("address")?,
        table.index_of("block_num")?,
        table.index_of("log_idx")?,
        table.index_of("data")?,
    );
    table
        .rows
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let at = |what: &str| format!("row {i}: {what}");
            let (index, status) = hex::decode(strip_hex(text(row, data)))
                .ok()
                .and_then(|raw| decode_uint_string(&raw))
                .with_context(|| at("not a RecordStatusUpdated payload"))?;
            Ok(StatusEvent {
                registry: checksum_address(text(row, address)),
                block_num: number(row, block).with_context(|| at("no block_num"))?,
                log_idx: number(row, idx).with_context(|| at("no log_idx"))?,
                index,
                status,
            })
        })
        .collect()
}

/// The status each `(registry, version)` of one record currently holds, from its
/// status events in log order: the newest wins.
pub type Statuses = BTreeMap<(String, u64), String>;

pub fn statuses_of(events: &[StatusEvent]) -> Statuses {
    events
        .iter()
        .map(|e| ((e.registry.to_lowercase(), e.index), e.status.clone()))
        .collect()
}

/// One record at its newest version, with the status held against that
/// version if there is one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    /// The id the contract stopped assigning, from [`parse_record_ids`]. `None`
    /// when the two queries disagree, which is worth seeing rather than hiding
    /// behind a zero — and in the cross-registry lookup, which is filtered on one
    /// hash and never walks any registry's whole ordering to number it.
    pub number: Option<u64>,
    pub checksum_hash: String,
    /// The newest version index. Earlier versions are earlier leaves.
    pub version: u64,
    pub uri: String,
    pub checksum: String,
    pub checksum_algo: String,
    pub metadata: String,
    /// The contract's `RecordCategory` as its uint8; the names are only in the source.
    pub category: u8,
    /// Identifies the data, where `checksum` identifies the bytes.
    pub data_pointer: String,
    /// Who wrote this version. The precompile's caller is the registry contract, so the
    /// envelope is the only place this exists.
    pub author: String,
    pub timestamp: u64,
    pub status: Option<String>,
}

/// A registry's records, from its leaves in log order: the newest version of each
/// checksum, with the status held against that version.
///
/// A leaf that is not an envelope is not an error here, and the count of them
/// comes back beside the records: a registry-scoped writer may append a bare
/// leaf committing to anything, and that is a leaf, not a record. Statuses
/// attach only to the version they name — one against version 2 of a record now
/// at 3 is not its status.
pub fn parse_records(
    leaves: &[Leaf],
    numbers: &BTreeMap<String, u64>,
) -> Result<(Vec<Record>, usize)> {
    let mut records: BTreeMap<String, Record> = BTreeMap::new();
    let mut statuses: BTreeMap<(String, u64), String> = BTreeMap::new();
    let mut other = 0;

    for leaf in leaves {
        let Some(envelope) = decode_envelope(&leaf.metadata) else {
            other += 1;
            continue;
        };
        let hash = envelope.checksum_hash();
        match envelope.kind {
            "record" => {
                let mut record = record_from(leaf, &envelope)?;
                record.number = numbers.get(&hash).copied();
                records.insert(hash, record);
            }
            "status" => {
                statuses.insert(
                    (hash, field_u64(leaf, &envelope, "index")?),
                    envelope.field("status").to_string(),
                );
            }
            kind => anyhow::bail!(
                "leaf {}/{}: unknown envelope kind {kind}",
                leaf.namespace,
                leaf.index
            ),
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
    Ok((out, other))
}

fn field_u64(leaf: &Leaf, envelope: &Envelope, field: &str) -> Result<u64> {
    envelope.field(field).parse().with_context(|| {
        format!(
            "leaf {}/{}: {field} {:?}",
            leaf.namespace,
            leaf.index,
            envelope.field(field)
        )
    })
}

/// One `record` envelope as a record. Unnumbered: a number is a property of a
/// whole registry's ordering, which the caller attaches when it has one.
fn record_from(leaf: &Leaf, envelope: &Envelope) -> Result<Record> {
    Ok(Record {
        number: None,
        checksum_hash: envelope.checksum_hash(),
        version: field_u64(leaf, envelope, "index")?,
        uri: envelope.field("uri").to_string(),
        checksum: envelope.field("checksum").to_string(),
        checksum_algo: envelope.field("checksum_algo").to_string(),
        metadata: envelope.field("metadata").to_string(),
        category: envelope
            .field("category")
            .parse()
            .with_context(|| format!("leaf {}/{}: category", leaf.namespace, leaf.index))?,
        data_pointer: envelope.field("data_pointer").to_string(),
        author: envelope.field("author").to_string(),
        timestamp: field_u64(leaf, envelope, "timestamp")?,
        status: None,
    })
}

/// One registry's record for a checksum: what a registry listing carries, with
/// the address it was appended under beside it.
#[derive(Debug, Clone, Serialize)]
pub struct RecordAt {
    pub registry: String,
    #[serde(flatten)]
    pub record: Record,
}

/// The leaf a registry event refers to: the one the precompile logged just before
/// it, in the same transaction. `addRecord` appends and then announces, and the
/// precompile emits exactly one log per append, so the leaf's `log_idx` is the
/// event's less one, taking `log_idx` for the receipt's `logIndex`, numbered across
/// the block. An event with no leaf beside it — some other contract's `RecordAdded`,
/// or an index missing a row — pairs with `None`.
pub fn pair_leaves<'a>(
    events: &'a [RecordEvent],
    leaves: &'a [Leaf],
) -> Vec<(&'a RecordEvent, Option<&'a Leaf>)> {
    let by_place: BTreeMap<(String, u64, u64), &Leaf> = leaves
        .iter()
        .map(|leaf| {
            (
                (leaf.namespace.to_lowercase(), leaf.block_num, leaf.log_idx),
                leaf,
            )
        })
        .collect();
    events
        .iter()
        .map(|event| {
            let beside = event
                .log_idx
                .checked_sub(1)
                .and_then(|idx| {
                    by_place.get(&(event.registry.to_lowercase(), event.block_num, idx))
                })
                .copied();
            (event, beside)
        })
        .collect()
}

/// Every registry holding a record under one checksum, at its newest version —
/// the successor to the module's `records(registry_id = 0, checksum, …)`.
///
/// Events come in log order, so a registry's later version replaces its earlier
/// one. An event that pairs with no leaf, or with a leaf that is not a record
/// envelope, is left out and counted rather than failing the lookup: anyone may
/// emit a `RecordAdded`, and a stranger's must not take the answer away from the
/// registries that share the checksum.
pub fn records_at(
    paired: &[(&RecordEvent, Option<&Leaf>)],
    statuses: &Statuses,
) -> Result<(Vec<RecordAt>, usize)> {
    let (mut newest, mut foreign): (BTreeMap<String, RecordAt>, usize) = (BTreeMap::new(), 0);
    for (event, leaf) in paired {
        let envelope = leaf.and_then(|leaf| decode_envelope(&leaf.metadata));
        match (leaf, envelope) {
            (Some(leaf), Some(envelope)) if envelope.kind == "record" => {
                let mut record = record_from(leaf, &envelope)?;
                record.status = statuses
                    .get(&(event.registry.to_lowercase(), record.version))
                    .cloned();
                newest.insert(
                    event.registry.to_lowercase(),
                    RecordAt {
                        registry: event.registry.clone(),
                        record,
                    },
                );
            }
            _ => foreign += 1,
        }
    }
    Ok((newest.into_values().collect(), foreign))
}

/// One version of a record, as the log has it.
///
/// Every field a [`Record`] decodes except `number`, which belongs to a registry's
/// whole ordering rather than to one version of one record. `category`,
/// `data_pointer` and `author` are per version and only here: the listing shows
/// the newest version's, so a version's own is visible nowhere else.
#[derive(Debug, Clone, Serialize)]
pub struct Version {
    pub version: u64,
    /// The leaf this version is, so it can be proven against the root.
    pub leaf: u64,
    pub uri: String,
    pub checksum: String,
    pub checksum_algo: String,
    pub metadata: String,
    pub category: u8,
    pub data_pointer: String,
    pub author: String,
    pub timestamp: u64,
    /// The status held against *this* version, if there is one. Statuses are
    /// per version, so the newest version carries none of an older one's.
    pub status: Option<String>,
    pub block_num: u64,
}

/// One record's versions, oldest first, from its `RecordAdded` events paired with
/// the leaf beside each — a lookup on an indexed topic, where walking the
/// registry's leaves and filtering would cost the whole registry to answer for
/// one record.
///
/// Version order is the log's own order rather than the `index` inside the
/// envelope — which is asserted against it, because a stream whose indexes do
/// not run 1..n is a contract that changed under the decoder, and reading it as
/// a history would quietly renumber it.
///
/// An event with no record leaf beside it is skipped and counted: the query
/// filters on a topic anyone may emit, so a stranger's `RecordAdded` must not
/// renumber this record's versions or fail the request.
pub fn versions_of(paired: &[(&RecordEvent, Option<&Leaf>)]) -> Result<(Vec<Version>, usize)> {
    let (mut versions, mut foreign) = (Vec::new(), 0);
    for (event, leaf) in paired {
        let envelope = leaf.and_then(|leaf| decode_envelope(&leaf.metadata));
        let (Some(leaf), Some(envelope)) = (leaf, envelope) else {
            foreign += 1;
            continue;
        };
        if envelope.kind != "record" {
            foreign += 1;
            continue;
        }
        let record = record_from(leaf, &envelope)?;
        let expected = versions.len() as u64 + 1;
        if record.version != expected || record.version != event.index {
            anyhow::bail!(
                "leaf {}/{}: version {} is the {expected} version of this record, announced as {}",
                leaf.namespace,
                leaf.index,
                record.version,
                event.index
            );
        }
        versions.push(Version {
            version: record.version,
            leaf: leaf.index,
            uri: record.uri,
            checksum: record.checksum,
            checksum_algo: record.checksum_algo,
            metadata: record.metadata,
            category: record.category,
            data_pointer: record.data_pointer,
            author: record.author,
            timestamp: record.timestamp,
            status: None,
            block_num: leaf.block_num,
        });
    }
    Ok((versions, foreign))
}
