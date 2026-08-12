//! What tidx answers becomes a head, and the slot that head is checked at.
//! No network: the responses are the shapes tidx's `/query` returns.

mod common;

use common::{bytes, REGISTRY_KEY, TAGGED_REGISTRY_COMMITMENT, TAGGED_REGISTRY_METADATA};
use nvnmchain_anchoring::eth::{checksum_address, keccak_hex};
use nvnmchain_anchoring::precompile::{head_slot, ADDRESS as ANCHORING_ADDRESS, ANCHORED_TOPIC};
use nvnmchain_anchoring::tidx::{
    cursor_after, heads_sql, parse_coverage, parse_heads, reject_truncated, Engine, Table,
    HARD_LIMIT, HEADS_KEY,
};
use serde_json::json;

const NAMESPACE: &str = "0x44DA54d3f5416A9Ae699d54EcB83c3043c41319E";

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
            REGISTRY_KEY,
            anchored_data(TAGGED_REGISTRY_COMMITMENT, TAGGED_REGISTRY_METADATA),
        ]],
        "row_count": 1,
    })))
    .expect("parsed");

    assert_eq!(heads.len(), 1);
    // Checksummed on the way in, whatever case the index returned.
    assert_eq!(heads[0].namespace, NAMESPACE);
    assert_eq!(heads[0].key, REGISTRY_KEY);
    assert_eq!(heads[0].commitment, TAGGED_REGISTRY_COMMITMENT);
    assert_eq!(heads[0].metadata, bytes(TAGGED_REGISTRY_METADATA));
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
        "rows": [[topic(NAMESPACE), REGISTRY_KEY, "0x00"]],
    })));
    assert!(corrupt.is_err());
    assert!(corrupt.unwrap_err().to_string().contains(REGISTRY_KEY));
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
        "rows": [[topic(NAMESPACE), REGISTRY_KEY]],
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
        format!("'\\x{hexed}'::bytea")
    );
    assert_eq!(
        Engine::ClickHouse.bytes_literal(ANCHORING_ADDRESS),
        format!("'0x{hexed}'")
    );

    assert!(heads_sql(Engine::Postgres, 7, "").contains(&format!("'\\x{hexed}'::bytea")));
    assert!(heads_sql(Engine::ClickHouse, 7, "").contains(&format!("'0x{hexed}'")));

    // The topic goes through the same spelling — it is a bytea column too.
    let topic0 = ANCHORED_TOPIC.trim_start_matches("0x");
    assert!(heads_sql(Engine::Postgres, 7, "").contains(&format!("'\\x{topic0}'::bytea")));
}

#[test]
fn heads_are_bounded_at_the_audited_block() {
    // tidx's realtime sync runs ahead of its contiguous interval; a head newer
    // than the block state is read at would report as a false mismatch.
    assert!(heads_sql(Engine::Postgres, 123, "").contains("block_num <= 123"));
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

#[test]
fn a_full_page_is_refused_because_it_may_be_short() {
    // tidx truncates at its row cap and says nothing. A projection missing rows
    // reads exactly like a complete one, and an audit over a truncated head list
    // reports clean — so a full page is an error, not an answer.
    let full = table(serde_json::json!({
        "ok": true,
        "columns": ["a"],
        "rows": [[1], [2], [3]],
    }));
    assert!(
        reject_truncated(full, 3).is_err(),
        "a full page must not pass"
    );

    let short = table(serde_json::json!({
        "ok": true,
        "columns": ["a"],
        "rows": [[1], [2]],
    }));
    assert!(
        reject_truncated(short, 3).is_ok(),
        "a short page is the answer"
    );
}

#[test]
fn the_row_cap_is_the_one_tidx_enforces() {
    // Pinned against tidx's `HARD_LIMIT_MAX`. If they diverge, the check fires
    // late or never — and never is a silent short answer.
    assert_eq!(HARD_LIMIT, 10_000);
}

#[test]
fn a_cursor_is_lexicographic_over_its_key_and_spelled_for_its_engine() {
    // (a, b) > (x, y) written out, because not every engine takes a row-value
    // comparison. Bytea literals go through the engine's spelling — carried
    // between them, a predicate matches nothing rather than erroring.
    let rows = table(serde_json::json!({
        "ok": true,
        "columns": ["namespace", "key", "block_num"],
        "rows": [[topic("aa"), topic("bb"), 12]],
    }));
    let row = rows.rows[0].clone();

    // Built from `bytes_literal` rather than spelled out, so the shape is what
    // is under test and not whichever literal syntax the engine wants today.
    let ns = Engine::Postgres.bytes_literal(&topic("aa"));
    let key = Engine::Postgres.bytes_literal(&topic("bb"));
    let pg = cursor_after(Engine::Postgres, &rows, HEADS_KEY, &row).expect("a cursor");
    assert_eq!(
        pg,
        format!(" AND (topic1 > {ns} OR (topic1 = {ns} AND (topic2 > {key})))")
    );

    let ch = cursor_after(Engine::ClickHouse, &rows, HEADS_KEY, &row).expect("a cursor");
    assert!(ch.contains("topic1 > '0x"), "{ch}");

    // A numeric column is written bare, not as a byte string.
    let by_block: nvnmchain_anchoring::tidx::Key = &[("block_num", "block_num")];
    let n = cursor_after(Engine::Postgres, &rows, by_block, &row).expect("a cursor");
    assert_eq!(n, " AND (block_num > 12)");
}
