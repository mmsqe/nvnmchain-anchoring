//! `Registry`'s own events — where role history lives.
//!
//! Role changes are not anchored: membership is each registry's state, read with
//! `hasRole`, and history is these events, which carry every field they need. A
//! third copy in the anchored log would only be something to drift.
//!
//! `roles` folds in SQL over an index where records do not: every argument
//! outside the topics is `bytes32`, which tidx decodes itself, where a dynamic
//! one comes back as its ABI offset word ([`crate::tidx::heads_sql`] reads raw
//! `data` for that reason).
//!
//! It is also the one query this crate does not run: [`roles_sql`] is what a
//! caller sends tidx, and nothing here reads the answer.

use crate::tidx::Engine;

/// `(topic0, signature)` for every event a registry emits, canonical form.
/// `tests/signatures.rs` checks the hashes against these signatures and the
/// signatures against the contract, so neither can sit here quietly matching
/// nothing — a signature that drifts builds its table off some other topic0
/// and decodes empty rather than failing.
pub const REGISTRY_TOPICS: &[(&str, &str)] = &[
    (
        "0x5fea036c56a9fe203110015d4d45fde7ec91f39e84507f4ffd536c61ed0b27ea",
        "RecordAdded(uint256,uint256,string)",
    ),
    (
        "0x3a95bced669bc2f225a75f44a7f9e4e43bf64f0b7e31b27aa93aee661eec3a9a",
        "RecordStatusUpdated(uint256,uint256,string)",
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
