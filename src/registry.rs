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

use crate::tidx::Engine;

/// `RecordAdded`'s topic0, the selector [`record_ids_sql`] filters on. Named so
/// the query and the [`REGISTRY_TOPICS`] row checked against the contract cannot
/// come apart.
pub const RECORD_ADDED_TOPIC: &str =
    "0xb4aaf705a3bf1baf4b094ef32b3517c8df84a8766f0d751a0c85aa41b63be45c";

/// `(topic0, signature)` for every event a registry emits, canonical form.
/// `tests/signatures.rs` checks the hashes against these signatures and the
/// signatures against the contract, so neither can sit here quietly matching
/// nothing — a signature that drifts builds its table off some other topic0
/// and decodes empty rather than failing.
pub const REGISTRY_TOPICS: &[(&str, &str)] = &[
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
pub fn roles_sql(engine: Engine, registry: &str, up_to: u64) -> String {
    // Repeated into both arms on purpose. tidx pushes these predicates into the
    // CTEs it generates, and PostgreSQL inlines those CTEs and pushes them again;
    // the copies here are what filters if either ever stops.
    let filter = format!(
        "address = {} AND block_num <= {up_to}",
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
         ) held WHERE rn = 1 AND granted",
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
/// Two windows, not one. The inner keeps each checksum's *first* appearance, the
/// outer numbers those; numbering the rows would give every version an id, so
/// re-anchoring an early record would shift every record after it. Ascending,
/// where [`crate::tidx::heads_sql`] is descending — that wants the newest row
/// per key, this one the oldest.
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
/// A full recomputation, with no cheap single-record path — a number is a
/// property of the whole ordering. Materialize it for a large registry rather
/// than answering a page load with it.
pub fn record_ids_sql(engine: Engine, registry: &str, up_to: u64) -> String {
    format!(
        "SELECT checksum_hash, ROW_NUMBER() OVER (ORDER BY block_num, log_idx) AS record_id \
         FROM (\
           SELECT topic1 AS checksum_hash, block_num, log_idx, \
                  ROW_NUMBER() OVER (PARTITION BY topic1 \
                                     ORDER BY block_num, log_idx) AS rn \
           FROM logs WHERE address = {} AND selector = {} AND block_num <= {up_to}\
         ) firsts WHERE rn = 1",
        engine.bytes_literal(registry),
        engine.bytes_literal(RECORD_ADDED_TOPIC),
    )
}
