//! `AnchoringRegistry`'s own events — the second source the projection reads.
//!
//! Grants and revokes anchor as `acl` envelopes, so the `Anchored` log alone
//! rebuilds "who could write this record". The revision that emitted these
//! events without anchoring them was never deployed, so there is no partial
//! history for this source to complete.
//!
//! It stays because `roles` is the one projection these events serve
//! *completely* — every field the retired queries returned is in them, so it
//! folds in SQL over tidx with no payload decoded. The other three are lossy
//! here: `RegistryAdded` carries neither description, metadata nor timestamp,
//! and `RecordAdded` carries neither uri, checksum algorithm, metadata nor
//! timestamp. Those live only in the envelope.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::envelope::decode_envelope;
use crate::eth::{address_from_topic, normalize_hex, strip_hex};
use crate::tidx::{number, text, Engine, Head, Key, Table};

/// `keccak256("")` — the `checksumHash` a registry-scoped role is announced
/// under, which is what an empty checksum hashes to.
pub const REGISTRY_SCOPE: &str =
    "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

/// `"admin"` as the right-padded `bytes32` the contract compares.
pub const ROLE_ADMIN: &str = "0x61646d696e000000000000000000000000000000000000000000000000000000";

/// `(topic0, signature)` for every event the wrapper emits, canonical form.
/// `tests/signatures.rs` checks the hashes against these signatures and the
/// signatures against the contract, so neither can sit here quietly matching
/// nothing — a signature tidx cannot match decodes to an empty table just as
/// surely as a mistyped topic used to scan an empty range.
pub const REGISTRY_TOPICS: &[(&str, &str)] = &[
    (
        "0x3ce4563d134e2bed44925e6752673cb055ab97f4e4e9b1af57b1d10154f6a1a4",
        "RegistryAdded(uint256,string,address)",
    ),
    (
        "0x0a4df583ca8b06d3dca2af4cc0dc36563bd219e42732e15b156c95aee0e07f28",
        "RecordAdded(uint256,uint256,uint256,string)",
    ),
    (
        "0x989fc3f482c08205f3318acb67405437e026aa2b3ded15a815813fff11fa37c6",
        "RecordStatusUpdated(uint256,uint256,uint256,string)",
    ),
    (
        "0xec288ea680fc912ecd077dc712f1347911ee4709aff396bf18fd9d74e2a71eb3",
        "RoleGranted(uint256,bytes32,address,bytes32)",
    ),
    (
        "0x257eb2ed659fb75385b608c05a73049fa8c6b406644b5bd6933950a933b36e39",
        "RoleRevoked(uint256,bytes32,address,bytes32)",
    ),
];

/// The events the projections are sent with, in the form `?signature=` takes:
/// argument names become result columns, `indexed` says which come from the
/// topics.
///
/// The same events as [`REGISTRY_TOPICS`] said twice — those are what a topic0
/// hashes from, these are what tidx parses — so `tests/signatures.rs` checks one
/// against the other. A drift decodes an empty table rather than failing.
pub const REGISTRY_ADDED: &str =
    "RegistryAdded(uint256 indexed id, string name, address indexed creator)";

/// Three, not two. `addRegistry` writes the creator's registry `admin` into
/// `member` directly and announces it only as a `RegistryAdded`, so the
/// grant/revoke pair alone answers every registry one admin short.
pub const ROLE_EVENTS: &[&str] = &[
    "RoleGranted(uint256 indexed registryId, bytes32 checksumHash, address indexed account, bytes32 role)",
    "RoleRevoked(uint256 indexed registryId, bytes32 checksumHash, address indexed account, bytes32 role)",
    REGISTRY_ADDED,
];

/// What [`registries_sql`] pages on — its own place in the log, since a
/// registry id is assigned in that order anyway.
pub const REGISTRIES_KEY: Key<'static> = &[("block_num", "block_num"), ("log_idx", "log_idx")];

/// What [`roles_sql`] pages on, which is the role key its window partitions by.
pub const ROLES_KEY: Key<'static> = &[
    ("checksumHash", "\"checksumHash\""),
    ("account", "account"),
    ("role", "role"),
];

/// Every registry the wrapper announced, in the order it assigned their ids.
///
/// Over the table `?signature=` generates rather than raw `data`: `name` is the
/// only argument outside the topics and it is a `string`, which tidx decodes.
/// Description, metadata and timestamp are not here at all — they exist only in
/// the `registry` envelope, which is why this projection is the lossy one.
pub fn registries_sql(engine: Engine, wrapper: &str, up_to: u64, after: &str) -> String {
    format!(
        "SELECT id, name, creator, block_num, log_idx FROM RegistryAdded \
         WHERE address = {} AND block_num <= {up_to}{after} \
         ORDER BY block_num, log_idx",
        engine.bytes_literal(wrapper),
    )
}

/// Every role held in one registry: newest row per `(checksumHash, account,
/// role)` wins, kept only if it granted.
///
/// Revokes are ordered against grants rather than subtracted from them — the
/// same key can be granted, revoked and granted again, so a set difference
/// answers that nobody holds it. The creator's admin joins as a third arm at its
/// own log position, ordered like any other.
///
/// The registry id narrows in SQL because it is `topic1` on every one of these
/// events; the wrapper's address alone would answer for every registry at once.
pub fn roles_sql(
    engine: Engine,
    wrapper: &str,
    registry_id: u64,
    up_to: u64,
    after: &str,
) -> String {
    let filter = |id_column: &str| {
        format!(
            "address = {} AND {id_column} = {registry_id} AND block_num <= {up_to}{after}",
            engine.bytes_literal(wrapper),
        )
    };
    let key = "\"checksumHash\", account, role";
    let arm = |table, granted| {
        format!(
            "SELECT block_num, log_idx, {key}, {granted} AS granted FROM {table} WHERE {}",
            filter("\"registryId\"")
        )
    };
    // Built before the outer format!, which clippy would otherwise read as a
    // nested one -- and it is easier to follow named than inline anyway.
    let seed = format!(
        "SELECT block_num, log_idx, {} AS \"checksumHash\", creator AS account, \
         {} AS role, TRUE AS granted FROM RegistryAdded WHERE {}",
        engine.bytes_literal(REGISTRY_SCOPE),
        engine.bytes_literal(ROLE_ADMIN),
        filter("id")
    );
    format!(
        "WITH acl AS ({granted} UNION ALL {revoked} UNION ALL {seed}) \
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

/// One registry, as the wrapper announced it.
#[derive(Debug, Clone, Serialize)]
pub struct Announced {
    pub id: u64,
    pub name: String,
    pub creator: String,
    pub block_num: u64,
}

/// [`registries_sql`]'s rows.
pub fn parse_registries(table: &Table) -> Result<Vec<Announced>> {
    let (id, name, creator, block) = (
        table.index_of("id")?,
        table.index_of("name")?,
        table.index_of("creator")?,
        table.index_of("block_num")?,
    );
    table
        .rows
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let at = |what| format!("row {i}: no {what}");
            Ok(Announced {
                id: number(row, id).with_context(|| at("id"))?,
                name: text(row, name).to_string(),
                creator: address_from_topic(text(row, creator))
                    .unwrap_or_else(|| normalize_hex(text(row, creator))),
                block_num: number(row, block).with_context(|| at("block_num"))?,
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
                role: bytes32_label_of(text(row, role)),
                block_num: number(row, block).with_context(|| format!("row {i}: no block_num"))?,
            })
        })
        .collect()
}

/// One record at its newest version, with the status anchored against that
/// version if there is one.
#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub record_id: u64,
    /// The newest version index. The head holds only this one — earlier versions
    /// are in the log, not in state.
    pub version: u64,
    pub uri: String,
    pub checksum: String,
    pub checksum_algo: String,
    pub metadata: String,
    pub timestamp: u64,
    pub status: Option<String>,
}

/// One registry's records, from the wrapper's heads.
///
/// Every registry shares the wrapper's namespace, so the heads arrive together
/// and the registry id is read out of each envelope rather than filtered in SQL
/// — the key a record is anchored under hashes that id in, so there is nothing
/// for a `WHERE` to match on. A head that will not decode is an error: only the
/// wrapper anchors here, and skipping one would drop a record while still
/// looking like a full list.
///
/// Statuses attach only to the version they name. A status against version 2 of
/// a record now at version 3 is not the current status.
pub fn parse_records(heads: &[Head], registry_id: u64) -> Result<Vec<Record>> {
    let mut records: BTreeMap<u64, Record> = BTreeMap::new();
    let mut statuses: BTreeMap<(u64, u64), String> = BTreeMap::new();

    for head in heads {
        let envelope = decode_envelope(&head.key, &head.metadata)
            .with_context(|| format!("key {}: not a registry envelope", head.key))?;
        let field = |name: &str| -> Result<u64> {
            envelope
                .field(name)
                .parse()
                .with_context(|| format!("key {}: {name} {:?}", head.key, envelope.field(name)))
        };
        // `registry` and `acl` envelopes describe the registry, not its records.
        if !matches!(envelope.kind, "record" | "status") {
            continue;
        }
        if field("registry_id")? != registry_id {
            continue;
        }
        let (record_id, index) = (field("record_id")?, field("index")?);
        match envelope.kind {
            "record" => {
                records.insert(
                    record_id,
                    Record {
                        record_id,
                        version: index,
                        uri: envelope.field("uri").to_string(),
                        checksum: envelope.field("checksum").to_string(),
                        checksum_algo: envelope.field("checksum_algo").to_string(),
                        metadata: envelope.field("metadata").to_string(),
                        timestamp: field("timestamp")?,
                        status: None,
                    },
                );
            }
            _ => {
                statuses.insert((record_id, index), envelope.field("status").to_string());
            }
        }
    }

    Ok(records
        .into_values()
        .map(|mut record| {
            record.status = statuses.get(&(record.record_id, record.version)).cloned();
            record
        })
        .collect())
}

/// A right-padded `bytes32` string ("admin") as text, anything else as the hex
/// it came in as — how Solidity writes role names.
fn bytes32_label_of(hexed: &str) -> String {
    let Ok(raw) = hex::decode(strip_hex(hexed)) else {
        return normalize_hex(hexed);
    };
    let text = raw.split(|b| *b == 0).next().unwrap_or(&[]);
    match std::str::from_utf8(text) {
        Ok(label) if !label.is_empty() && label.chars().all(|c| c.is_ascii_graphic()) => {
            label.to_string()
        }
        _ => normalize_hex(hexed),
    }
}
