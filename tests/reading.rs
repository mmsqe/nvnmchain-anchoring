//! What tidx answers becomes a head, and the slot that head is checked at.
//! No network: the responses are the shapes tidx's `/query` returns.

mod common;

use common::{bytes, RECORD_COMMITMENT, RECORD_KEY, RECORD_METADATA};
use nvnmchain_anchoring::eth::{checksum_address, keccak_hex};
use nvnmchain_anchoring::precompile::{head_slot, ADDRESS as ANCHORING_ADDRESS, ANCHORED_TOPIC};
use nvnmchain_anchoring::registry::{record_ids_sql, roles_sql, RECORD_ADDED_TOPIC, ROLE_EVENTS};
use nvnmchain_anchoring::tidx::{heads_sql, parse_coverage, parse_heads, Engine, Table};
use serde_json::json;

const NAMESPACE: &str = "0x44DA54d3f5416A9Ae699d54EcB83c3043c41319E";
/// A registry, which is a deployment rather than an enshrined address — every
/// roles query names one, and that name is the whole partition.
const REGISTRY: &str = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0";

fn table(body: serde_json::Value) -> Table {
    Table::from_response(&body).expect("a query tidx accepted")
}

/// `abi.encode(bytes32 commitment, bytes metadata)` — the `Anchored` log's
/// `data` column, as tidx hands it back.
fn anchored_data(commitment: &str, metadata: &str) -> String {
    let payload = hex::encode(bytes(metadata));
    let padded = format!(
        "{payload:0<width$}",
        width = payload.len().div_ceil(64) * 64
    );
    format!(
        "0x{}{:064x}{:064x}{padded}",
        commitment.trim_start_matches("0x"),
        0x40,
        bytes(metadata).len(),
    )
}

fn topic(word: &str) -> String {
    format!("0x{:0>64}", word.trim_start_matches("0x"))
}

#[test]
fn a_log_row_becomes_a_head() {
    let heads = parse_heads(&table(json!({
        "ok": true,
        "columns": ["namespace", "key", "data"],
        "rows": [[
            topic(&NAMESPACE.to_lowercase()),
            RECORD_KEY,
            anchored_data(RECORD_COMMITMENT, RECORD_METADATA),
        ]],
        "row_count": 1,
    })))
    .expect("parsed");

    assert_eq!(heads.len(), 1);
    // Checksummed on the way in, whatever case the index returned.
    assert_eq!(heads[0].namespace, NAMESPACE);
    assert_eq!(heads[0].key, RECORD_KEY);
    assert_eq!(heads[0].commitment, RECORD_COMMITMENT);
    assert_eq!(heads[0].metadata, bytes(RECORD_METADATA));
}

#[test]
fn a_row_whose_payload_does_not_decode_is_an_error() {
    // Every row the heads query returns was written by the precompile, so one
    // that does not read as an Anchored payload is the index's copy gone bad —
    // and the query keeps only each pair's newest row, so dropping it would
    // take the whole (namespace, key) out of the audit silently.
    let corrupt = parse_heads(&table(json!({
        "ok": true,
        "columns": ["namespace", "key", "data"],
        "rows": [[topic(NAMESPACE), RECORD_KEY, "0x00"]],
    })));
    assert!(corrupt.is_err());
    assert!(corrupt.unwrap_err().to_string().contains(RECORD_KEY));
}

#[test]
fn a_refused_query_is_not_an_empty_result() {
    // tidx answers 200 with ok:false. Read as success, a rejected query is an
    // index with no heads — which is what a clean audit looks like.
    let refused = Table::from_response(&json!({"ok": false, "error": "invalid signature"}));
    assert!(refused.is_err());
    let message = refused.unwrap_err().to_string();
    assert!(message.contains("invalid signature"), "{message}");
}

#[test]
fn a_column_the_query_did_not_return_is_an_error() {
    // Not silently absent: a head missing its metadata would audit as
    // unverifiable rather than as a query that came back wrong.
    let short = parse_heads(&table(json!({
        "ok": true,
        "columns": ["namespace", "key"],
        "rows": [[topic(NAMESPACE), RECORD_KEY]],
    })));
    assert!(short.is_err());
    assert!(short.unwrap_err().to_string().contains("data"));
}

/// A `/status` body carrying one chain. Coverage comes from here and not from
/// `SELECT … FROM sync_state`, which `/query` refuses with a 422.
fn status(tip: u64, backfill: serde_json::Value, head: u64) -> serde_json::Value {
    json!({
        "ok": true,
        "chains": [{
            "chain_id": 1337,
            "tip_num": tip,
            "synced_num": 0,  // left behind by realtime sync; deliberately not read
            "backfill_num": backfill,
            "head_num": head,
        }],
    })
}

#[test]
fn coverage_says_how_far_back_the_index_reaches() {
    let full = parse_coverage(&status(1_000, json!(0), 1_003), 1337).expect("parsed");
    assert_eq!(full.tip_num, 1_000, "the realtime marker, not synced_num");
    assert!(full.reaches(0), "backfilled to genesis covers every anchor");
    assert_eq!(full.lag(), 3);

    // Backfill not started: nothing below the tip is indexed, so a key
    // anchored only down there cannot be audited.
    let partial = parse_coverage(&status(1_000, json!(null), 1_000), 1337).expect("parsed");
    assert_eq!(partial.backfill_num, None);
    assert!(!partial.reaches(0));

    // Started but still above the precompile's first block.
    let short = parse_coverage(&status(1_000, json!(500), 1_000), 1337).expect("parsed");
    assert!(!short.reaches(100));
    assert!(short.reaches(500));
}

#[test]
fn a_status_missing_tip_num_is_an_error() {
    // tip_num is always serialized, so absence is schema drift. Defaulted to
    // zero it would bound the heads query at block 0 — and an audit over zero
    // heads reports clean.
    let drifted = parse_coverage(
        &json!({"ok": true, "chains": [{"chain_id": 1337, "head_num": 5}]}),
        1337,
    );
    assert!(drifted.is_err());
    assert!(drifted.unwrap_err().to_string().contains("tip_num"));
}

#[test]
fn a_status_without_our_chain_is_an_error() {
    // tidx serves several chains from one endpoint. Picking the wrong entry, or
    // defaulting to zero, would audit a block this chain never reached.
    let other = parse_coverage(&status(1_000, json!(0), 1_000), 4217);
    assert!(other.is_err());
    assert!(other.unwrap_err().to_string().contains("4217"));
}

#[test]
fn the_address_literal_is_spelled_for_its_engine() {
    // The trap: PostgreSQL takes a bytea literal, ClickHouse a string, and a
    // predicate carried between them matches nothing — an empty projection,
    // not an error.
    let hexed = ANCHORING_ADDRESS.trim_start_matches("0x").to_lowercase();
    assert_eq!(
        Engine::Postgres.bytes_literal(ANCHORING_ADDRESS),
        format!("'\\x{hexed}'")
    );
    assert_eq!(
        Engine::ClickHouse.bytes_literal(ANCHORING_ADDRESS),
        format!("'0x{hexed}'")
    );

    assert!(heads_sql(Engine::Postgres, 7).contains(&format!("'\\x{hexed}'")));
    assert!(heads_sql(Engine::ClickHouse, 7).contains(&format!("'0x{hexed}'")));

    // The topic goes through the same spelling — it is a bytea column too.
    let topic0 = ANCHORED_TOPIC.trim_start_matches("0x");
    assert!(heads_sql(Engine::Postgres, 7).contains(&format!("'\\x{topic0}'")));

    // Uncast, everywhere: tidx's pushdown extractor reads a bare literal and
    // not a cast expression.
    assert!(!roles_sql(Engine::Postgres, REGISTRY, 7).contains("::bytea"));
    assert!(!heads_sql(Engine::Postgres, 7).contains("::bytea"));
}

#[test]
fn heads_are_bounded_at_the_audited_block() {
    // tidx's realtime sync runs ahead of its contiguous interval; a head newer
    // than the block state is read at would report as a false mismatch.
    assert!(heads_sql(Engine::Postgres, 123).contains("block_num <= 123"));
}

#[test]
fn the_roles_query_orders_revokes_against_grants() {
    // Not "granted minus revoked": the same key can be granted, revoked and
    // granted again, and a set difference answers that nobody holds it. The
    // partition is every field of the key the wrapper hashes an `acl` envelope
    // under, so two roles for one account stay apart.
    let sql = roles_sql(Engine::Postgres, REGISTRY, 99);
    assert!(sql.contains(
        "PARTITION BY \"checksumHash\", account, role \
         ORDER BY block_num DESC, log_idx DESC"
    ));
    assert!(sql.contains("WHERE rn = 1 AND granted"));

    // Every event the query is sent with has an arm, or the ordering has
    // nothing to order against. Read off ROLE_EVENTS rather than spelled again,
    // so a fourth signature cannot be added without one.
    for named in ROLE_EVENTS {
        let event = named.split('(').next().expect("a signature has a name");
        assert!(sql.contains(&format!("FROM {event} ")), "no {event} arm");
    }
}

#[test]
fn the_roles_query_needs_no_seed_for_the_creators_admin() {
    // The old wrapper wrote `member` directly in addRegistry and announced the creator's
    // admin only in RegistryAdded, so the fold needed that event as a third arm. A registry
    // announces it as an ordinary RoleGranted at deployment, so two arms answer in full.
    let sql = roles_sql(Engine::Postgres, REGISTRY, 99);
    assert!(!sql.contains("RegistryAdded"), "{sql}");
    assert_eq!(ROLE_EVENTS.len(), 2, "{ROLE_EVENTS:?}");
}

#[test]
fn record_numbering_counts_records_and_not_versions() {
    // The whole reason for the inner window. Numbering the rows themselves would
    // give every version its own id, so re-anchoring an early record would
    // renumber it and shift every record after it.
    let sql = record_ids_sql(Engine::Postgres, REGISTRY, 99);
    assert!(
        sql.contains("ROW_NUMBER() OVER (PARTITION BY topic1 ORDER BY block_num, log_idx) AS rn")
    );
    assert!(sql.contains("WHERE rn = 1"));
    assert!(sql.contains("ROW_NUMBER() OVER (ORDER BY block_num, log_idx) AS record_id"));

    // Ascending in both, where the head queries are descending: this one wants
    // the oldest row per key, not the newest.
    assert!(!sql.contains("DESC"), "{sql}");
}

#[test]
fn record_numbering_reads_topics_and_not_the_data_section() {
    // Why it can fold at all where a whole records projection cannot: the
    // checksum hash is indexed, so the query never meets the dynamic argument
    // tidx would hand back as an ABI offset word.
    let sql = record_ids_sql(Engine::Postgres, REGISTRY, 99);
    assert!(sql.contains("topic1 AS checksum_hash"));
    assert!(sql.contains("FROM logs "), "{sql}");
    assert!(
        !sql.contains("RecordAdded"),
        "reads the base table, not a generated one"
    );
    assert!(!sql.contains("data"), "{sql}");
}

#[test]
fn record_numbering_is_scoped_to_one_deployment_and_bounded() {
    // The same trap as the roles query: tidx's tables filter on topic0 alone, so
    // without the address any registry's records would be numbered together.
    let hexed = REGISTRY.trim_start_matches("0x").to_lowercase();
    let topic0 = RECORD_ADDED_TOPIC.trim_start_matches("0x");
    let sql = record_ids_sql(Engine::Postgres, REGISTRY, 7);
    assert!(sql.contains(&format!("address = '\\x{hexed}'")));
    assert!(sql.contains(&format!("selector = '\\x{topic0}'")));
    assert!(sql.contains("AND block_num <= 7"));
    assert!(record_ids_sql(Engine::ClickHouse, REGISTRY, 7).contains(&format!("'0x{hexed}'")));
    assert!(!sql.contains("::bytea"));
}

#[test]
fn the_roles_query_is_scoped_to_one_deployment() {
    // tidx's generated CTEs filter on topic0 alone — the wrapper is a
    // deployment, not a genesis address, so any contract emitting the same
    // event answers too unless the query says which one. Bounded in the same
    // breath, since both predicates ride the pushdown together.
    let hexed = REGISTRY.trim_start_matches("0x").to_lowercase();
    let bound = "AND block_num <= 7";
    assert!(roles_sql(Engine::Postgres, REGISTRY, 7)
        .contains(&format!("address = '\\x{hexed}' {bound}")));
    assert!(roles_sql(Engine::ClickHouse, REGISTRY, 7)
        .contains(&format!("address = '0x{hexed}' {bound}")));
}

#[test]
fn head_slot_derivation_matches_the_node_suite() {
    // keccak256(0x01 ‖ pad32(ns) ‖ key), the derivation tempo's
    // test_head_slot_derivation_is_reproducible_off_chain pins. The audit reads
    // this slot instead of calling latest().
    let key = format!("0x{}", "cc".repeat(32));
    let mut preimage = vec![0x01u8];
    preimage.extend_from_slice(&[0u8; 12]);
    preimage.extend_from_slice(&bytes(&checksum_address(NAMESPACE)));
    preimage.extend_from_slice(&bytes(&key));
    assert_eq!(head_slot(NAMESPACE, &key), Some(keccak_hex(&preimage)));

    assert_eq!(head_slot("0xnothex", &key), None);
    assert_eq!(head_slot(NAMESPACE, "0x1234"), None);
}
