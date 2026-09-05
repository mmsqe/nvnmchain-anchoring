//! What tidx answers becomes a leaf, a namespace's MMR, or a registry event — and
//! what those fold and pair into. No network: the responses are the shapes tidx's
//! `/query` returns.

mod common;

use common::{
    bytes, leaf_data, leaves_data, topic, AUTHOR, FIXTURE_HASH, RECORD_COMMITMENT, RECORD_METADATA,
    STATUS_COMMITMENT, STATUS_METADATA,
};
use nvnmchain_anchoring::audit::fold;
use nvnmchain_anchoring::eth::{checksum_address, hex0x, keccak_hex, parse_address};
use nvnmchain_anchoring::mmr::{hash_leaf, hash_merge, Mmr};
use nvnmchain_anchoring::precompile::{
    count_slot, ADDRESS as ANCHORING_ADDRESS, LEAF_APPENDED_TOPIC, LEAVES_APPENDED_TOPIC,
};
use nvnmchain_anchoring::registry::{
    deployment_sql, pair_leaves, parse_record_events, parse_record_ids, parse_records,
    parse_registries, parse_roles, parse_status_events, record_added_sql, record_ids_sql,
    records_at, registries_sql, roles_sql, status_updated_sql, statuses_of, versions_of,
    NameFilter, RecordEvent, RECORD_ADDED_TOPIC, RECORD_STATUS_UPDATED_TOPIC,
    REGISTRY_DEPLOYED_TOPIC, ROLE_EVENTS,
};
use nvnmchain_anchoring::rpc::decode_state;
use nvnmchain_anchoring::tidx::{
    appends_sql, cursor_after, group_by_namespace, histories_sql, leaves_in_sql, leaves_sql,
    parse_appends, parse_coverage, parse_leaves, reject_truncated, Appended, Edge, Engine, Leaf,
    Table, APPENDS_KEY, HARD_LIMIT, HISTORIES_KEY, LEAVES_KEY,
};
use serde_json::json;
use std::collections::BTreeMap;

const NAMESPACE: &str = "0x44DA54d3f5416A9Ae699d54EcB83c3043c41319E";
/// A registry, which is a deployment rather than an enshrined address — every
/// roles query names one, and that name is the whole partition.
const REGISTRY: &str = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0";
const FACTORY: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

fn table(body: serde_json::Value) -> Table {
    Table::from_response(&body).expect("a query tidx accepted")
}

fn c(i: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&i.to_be_bytes());
    word
}

/// One `LeafAppended` row as tidx returns it, with whatever root and peaks.
fn leaf_row(
    index: u64,
    commitment: &str,
    metadata: &str,
    block: u64,
    log_idx: u64,
) -> serde_json::Value {
    json!([
        topic(&REGISTRY.to_lowercase()),
        topic(&format!("{index:x}")),
        leaf_data(
            commitment,
            &hex0x(&[0x11u8; 32]),
            &[&hex0x(&[0x22u8; 32])],
            &bytes(metadata)
        ),
        block,
        log_idx,
    ])
}

fn leaves_table(rows: Vec<serde_json::Value>) -> Table {
    table(json!({
        "ok": true,
        "columns": ["namespace", "index", "data", "block_num", "log_idx"],
        "rows": rows,
    }))
}

#[test]
fn a_log_row_becomes_a_leaf() {
    let leaves = parse_leaves(&leaves_table(vec![leaf_row(
        4,
        RECORD_COMMITMENT,
        RECORD_METADATA,
        12,
        3,
    )]))
    .expect("parsed");

    assert_eq!(leaves.len(), 1);
    // Checksummed on the way in, whatever case the index returned.
    assert_eq!(leaves[0].namespace, REGISTRY);
    assert_eq!(leaves[0].index, 4);
    assert_eq!(leaves[0].commitment, RECORD_COMMITMENT);
    assert_eq!(leaves[0].metadata, bytes(RECORD_METADATA));
    assert_eq!((leaves[0].block_num, leaves[0].log_idx), (12, 3));
}

#[test]
fn a_row_whose_payload_does_not_decode_is_an_error() {
    // Every row the leaves query returns was written by the precompile, so one
    // that does not read as a LeafAppended payload is the index's copy gone bad —
    // dropping it would take the leaf out of every fold and listing silently.
    let corrupt = parse_leaves(&leaves_table(vec![json!([
        topic(REGISTRY),
        topic("4"),
        "0x00",
        1,
        0
    ])]));
    assert!(corrupt.is_err());
    assert!(corrupt.unwrap_err().to_string().contains("LeafAppended"));
}

#[test]
fn a_refused_query_is_not_an_empty_result() {
    // tidx answers 200 with ok:false. Read as success, a rejected query is an
    // index with no leaves — which is what a clean audit looks like.
    let refused = Table::from_response(&json!({"ok": false, "error": "invalid signature"}));
    assert!(refused.is_err());
    let message = refused.unwrap_err().to_string();
    assert!(message.contains("invalid signature"), "{message}");
}

#[test]
fn a_column_the_query_did_not_return_is_an_error() {
    // Not silently absent: a leaf missing its data would fold as nothing rather
    // than as a query that came back wrong.
    let short = parse_leaves(&table(json!({
        "ok": true,
        "columns": ["namespace", "index"],
        "rows": [[topic(REGISTRY), topic("4")]],
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
    assert!(full.reaches(0), "backfilled to genesis covers every append");
    assert_eq!(full.lag(), 3);

    // Backfill not started: nothing below the tip is indexed, so a namespace
    // appended to only down there cannot be audited.
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
    // zero it would bound every query at block 0 — and an audit over nothing
    // reports clean.
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

    let all: [String; 0] = [];
    assert!(leaves_sql(Engine::Postgres, &all, 7, "").contains(&format!("'\\x{hexed}'")));
    assert!(leaves_sql(Engine::ClickHouse, &all, 7, "").contains(&format!("'0x{hexed}'")));

    // The topic goes through the same spelling — it is a bytea column too.
    let topic0 = LEAF_APPENDED_TOPIC.trim_start_matches("0x");
    assert!(leaves_sql(Engine::Postgres, &all, 7, "").contains(&format!("'\\x{topic0}'")));

    // Uncast, everywhere: tidx's pushdown extractor reads a bare literal and
    // not a cast expression. `tempo-e2e` sends the same spelling to a running
    // tidx, so this is the form with a live proof behind it.
    assert!(!roles_sql(Engine::Postgres, REGISTRY, 7, "").contains("::bytea"));
    assert!(!leaves_sql(Engine::Postgres, &all, 7, "").contains("::bytea"));
}

#[test]
fn every_walk_is_bounded_at_the_audited_block_and_in_log_order() {
    // tidx's realtime sync runs ahead of its contiguous interval; a leaf newer
    // than the block state is read at would fold into a false mismatch.
    for sql in [
        leaves_sql(Engine::Postgres, &[REGISTRY.to_string()], 123, ""),
        histories_sql(Engine::Postgres, 123, ""),
        appends_sql(Engine::Postgres, &[], 123, "", Edge::Newest),
    ] {
        assert!(sql.contains("block_num <= 123"), "{sql}");
    }
    assert!(leaves_sql(Engine::Postgres, &[], 1, "").ends_with("ORDER BY block_num, log_idx"));
    assert!(histories_sql(Engine::Postgres, 1, "").ends_with("ORDER BY topic1, block_num, log_idx"));
}

#[test]
fn a_scoped_leaves_query_narrows_on_the_namespace_topic() {
    // `topic1` is the namespace, and one registry's projection wants only its own
    // leaves. Padded to a full word: `topic1` is 32 bytes with the address
    // right-aligned, and the bare 20-byte form matches nothing — which reads as a
    // registry that appended nothing rather than as a broken query.
    let hexed = REGISTRY.trim_start_matches("0x").to_lowercase();
    let word = format!("{hexed:0>64}");
    let scoped = leaves_sql(Engine::Postgres, &[REGISTRY.to_string()], 7, "");
    assert!(
        scoped.contains(&format!("topic1 = '\\x{word}'")),
        "{scoped}"
    );
    assert!(
        !scoped.contains(&format!("topic1 = '\\x{hexed}'")),
        "{scoped}"
    );
    // ...and the chain-wide one still is not scoped, or `kinds` would only ever
    // see one namespace.
    assert!(!leaves_sql(Engine::Postgres, &[], 7, "").contains("topic1 = "));

    // Several at once, for the bulk projection: `IN`, each padded.
    let registries = [REGISTRY.to_string(), format!("0x{}", "ab".repeat(20))];
    let many = leaves_sql(Engine::Postgres, &registries, 7, "");
    assert!(many.contains("topic1 IN ("), "{many}");
    assert!(many.contains(&word), "{many}");

    // And narrowed to blocks as well, for the leaves beside a checksum's events.
    let beside = leaves_in_sql(Engine::Postgres, &registries, &[5, 9], 7, "");
    assert!(beside.contains("block_num IN (5, 9)"), "{beside}");
}

#[test]
fn the_mmr_head_query_keeps_the_newest_append_of_either_shape() {
    // Both events carry the count and peaks they left, so the newest one per
    // namespace *is* the MMR. Partitioned by the namespace it pages on.
    let sql = appends_sql(
        Engine::Postgres,
        &[REGISTRY.to_string()],
        99,
        "",
        Edge::Newest,
    );
    assert!(
        sql.contains("PARTITION BY topic1 ORDER BY block_num DESC, log_idx DESC"),
        "{sql}"
    );
    assert!(sql.contains("WHERE rn = 1"), "{sql}");
    for topic0 in [LEAF_APPENDED_TOPIC, LEAVES_APPENDED_TOPIC] {
        assert!(sql.contains(topic0.trim_start_matches("0x")), "{sql}");
    }
    assert!(sql.contains("selector IN ("), "{sql}");

    // The other end of the window: what a registry was first loaded with.
    let first = appends_sql(
        Engine::Postgres,
        &[REGISTRY.to_string()],
        99,
        "",
        Edge::Oldest,
    );
    assert!(
        first.contains("PARTITION BY topic1 ORDER BY block_num ASC, log_idx ASC"),
        "{first}"
    );
    assert!(first.contains("WHERE rn = 1"), "{first}");
}

#[test]
fn the_audit_walk_is_one_query_namespace_by_namespace() {
    // One walk ordered by namespace, then log position; consecutive rows share a
    // namespace, so grouping needs no map.
    let walk = histories_sql(Engine::Postgres, 99, "");
    assert!(
        walk.ends_with("ORDER BY topic1, block_num, log_idx"),
        "{walk}"
    );
    assert!(walk.contains("selector IN ("), "{walk}");
    assert!(!walk.contains("PARTITION BY"), "{walk}");

    let peaks = [hex0x(&[0x22u8; 32])];
    let peak_refs: Vec<&str> = peaks.iter().map(String::as_str).collect();
    let row = |ns: &str, index: &str, block: u64| {
        json!([
            topic(ns),
            topic(index),
            LEAF_APPENDED_TOPIC,
            leaf_data(RECORD_COMMITMENT, &hex0x(&[0x11u8; 32]), &peak_refs, b""),
            block,
            0,
        ])
    };
    let appends = parse_appends(&table(json!({
        "ok": true,
        "columns": ["namespace", "index", "selector", "data", "block_num", "log_idx"],
        "rows": [row(NAMESPACE, "0", 3), row(REGISTRY, "0", 4), row(REGISTRY, "1", 9)],
    })))
    .expect("three appends");
    let histories = group_by_namespace(appends);
    assert_eq!(histories.len(), 2);
    assert_eq!(
        (histories[0].0.as_str(), histories[0].1.len()),
        (NAMESPACE, 1)
    );
    assert_eq!(
        (histories[1].0.as_str(), histories[1].1.len()),
        (REGISTRY, 2)
    );
    assert!(matches!(
        histories[1].1[1].what,
        Appended::Leaf { index: 1, .. }
    ));
}

#[test]
fn the_roles_query_orders_revokes_against_grants() {
    // Not "granted minus revoked": the same key can be granted, revoked and
    // granted again, and a set difference answers that nobody holds it.
    let sql = roles_sql(Engine::Postgres, REGISTRY, 99, "");
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
    // A registry announces its creator's admin as an ordinary RoleGranted at
    // deployment, so two arms answer in full.
    let sql = roles_sql(Engine::Postgres, REGISTRY, 99, "");
    assert!(!sql.contains("RegistryAdded"), "{sql}");
    assert_eq!(ROLE_EVENTS.len(), 2, "{ROLE_EVENTS:?}");
}

#[test]
fn record_numbering_counts_records_and_not_versions() {
    // The window keeps each checksum's *first* appearance; anything looser would
    // give every version its own id, so re-adding an early record would
    // renumber it and shift every record after it.
    let sql = record_ids_sql(Engine::Postgres, REGISTRY, 99, "");
    assert!(
        sql.contains("ROW_NUMBER() OVER (PARTITION BY topic1 ORDER BY block_num, log_idx) AS rn")
    );
    assert!(sql.contains("WHERE rn = 1"));
    assert!(!sql.contains("DESC"), "{sql}");
    assert!(!sql.contains("record_id"), "{sql}");
}

#[test]
fn record_numbering_reads_topics_and_not_the_data_section() {
    let sql = record_ids_sql(Engine::Postgres, REGISTRY, 99, "");
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
    let hexed = REGISTRY.trim_start_matches("0x").to_lowercase();
    let topic0 = RECORD_ADDED_TOPIC.trim_start_matches("0x");
    let sql = record_ids_sql(Engine::Postgres, REGISTRY, 7, "");
    assert!(sql.contains(&format!("address = '\\x{hexed}'")));
    assert!(sql.contains(&format!("selector = '\\x{topic0}'")));
    assert!(sql.contains("AND block_num <= 7"));
    assert!(record_ids_sql(Engine::ClickHouse, REGISTRY, 7, "").contains(&format!("'0x{hexed}'")));
    assert!(!sql.contains("::bytea"));
}

#[test]
fn the_roles_query_is_scoped_to_one_deployment() {
    let hexed = REGISTRY.trim_start_matches("0x").to_lowercase();
    let bound = "AND block_num <= 7";
    assert!(roles_sql(Engine::Postgres, REGISTRY, 7, "")
        .contains(&format!("address = '\\x{hexed}' {bound}")));
    assert!(roles_sql(Engine::ClickHouse, REGISTRY, 7, "")
        .contains(&format!("address = '0x{hexed}' {bound}")));
}

#[test]
fn the_count_slot_derivation_matches_the_node_suite() {
    // keccak256(0x01 ‖ pad32(ns)), the base tempo's `slot_layout_is_pinned` pins
    // for namespace 0x1111…; the peaks follow it one slot per height. The audit
    // reads this slot beside `state()` to calibrate the layout.
    let pinned = format!("0x{}", "11".repeat(20));
    assert_eq!(
        count_slot(&pinned).as_deref(),
        Some("0xb33ae4174b6ee0d698ac7fb0b98c2e8dd60d6062831f17c8355acb09a12e0c4f")
    );
    let mut preimage = vec![0x01u8];
    preimage.extend_from_slice(&[0u8; 12]);
    preimage.extend_from_slice(&bytes(&checksum_address(NAMESPACE)));
    assert_eq!(count_slot(NAMESPACE), Some(keccak_hex(&preimage)));
    assert_eq!(count_slot("0xnothex"), None);
}

#[test]
fn state_decodes_count_and_peaks() {
    // `(uint256 count, bytes32[] peaks)` as eth_call returns it.
    let returned = format!(
        "0x{:064x}{:064x}{:064x}{}{}",
        3,
        0x40,
        2,
        "aa".repeat(32),
        "bb".repeat(32)
    );
    let state = decode_state(&returned).expect("decodes");
    assert_eq!(state.count, 3);
    assert_eq!(
        state.peaks,
        [
            format!("0x{}", "aa".repeat(32)),
            format!("0x{}", "bb".repeat(32))
        ]
    );
    assert!(decode_state("0x").is_none());
}

/// `abi.encode(string, string, string)` — `RegistryDeployed`'s data section,
/// built the way the ABI says rather than pasted, so a test that fails names a
/// decoder bug and not a typo in a literal.
fn deployed_data(strings: [&str; 3]) -> String {
    let (mut head, mut tail) = (String::new(), String::new());
    let mut offset = 3 * 32;
    for value in strings {
        head.push_str(&format!("{offset:064x}"));
        let raw = value.as_bytes();
        let words = raw.len().div_ceil(32);
        tail.push_str(&format!("{:064x}", raw.len()));
        if words > 0 {
            tail.push_str(&format!(
                "{:0<width$}",
                hex::encode(raw),
                width = words * 64
            ));
        }
        offset += 32 + words * 32;
    }
    format!("0x{head}{tail}")
}

#[test]
fn a_literal_cannot_carry_a_quote_out_of_its_string() {
    // The queries are string interpolation, and one caller is an HTTP path
    // segment now. Non-hex is dropped rather than escaped, so there is nothing
    // to escape wrong.
    for hostile in ["aa' OR 1=1--", "aa\\x27; DROP TABLE logs; --", "0xaa'"] {
        let literal = Engine::Postgres.bytes_literal(hostile);
        assert_eq!(literal.matches('\'').count(), 2, "{literal}");
        assert!(!literal.contains("OR"), "{literal}");
        assert!(!literal.contains(';'), "{literal}");
    }
}

#[test]
fn an_address_is_rejected_rather_than_filtered_into_another_one() {
    assert!(parse_address(REGISTRY).is_some());
    assert!(parse_address(&REGISTRY.to_lowercase()).is_some());
    for bad in [
        "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6",     // 19 bytes
        "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0e0", // 21 bytes
        "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6g0",   // not hex
        "",
    ] {
        assert!(parse_address(bad).is_none(), "{bad}");
    }
}

#[test]
fn the_registries_query_is_scoped_to_one_factory_and_ordered_by_deployment() {
    let hexed = FACTORY.trim_start_matches("0x").to_lowercase();
    let topic0 = REGISTRY_DEPLOYED_TOPIC.trim_start_matches("0x");
    let sql = registries_sql(Engine::Postgres, FACTORY, 7, "");
    assert!(sql.contains(&format!("address = '\\x{hexed}'")), "{sql}");
    assert!(sql.contains(&format!("selector = '\\x{topic0}'")), "{sql}");
    assert!(sql.contains("AND block_num <= 7"), "{sql}");
    assert!(sql.contains("ORDER BY block_num, log_idx"), "{sql}");
    assert!(!sql.contains("::bytea"), "{sql}");
}

#[test]
fn registries_are_numbered_by_the_order_they_were_deployed_in() {
    let rows = parse_registries(&table(json!({
        "ok": true,
        "columns": ["registry", "creator", "data", "block_num"],
        "rows": [
            [topic("aa"), topic("bb"), deployed_data(["docs", "", "{}"]), 11],
            [topic("cc"), topic("bb"), deployed_data(["photos", "mine", ""]), 12],
        ],
    })))
    .expect("two RegistryDeployed rows");

    assert_eq!(rows.len(), 2);
    assert_eq!((rows[0].number, rows[1].number), (1, 2));
    assert_eq!(rows[0].name, "docs");
    assert_eq!(rows[0].metadata, "{}");
    assert_eq!(rows[1].name, "photos");
    assert_eq!(rows[1].description, "mine");
    assert_eq!(rows[1].block_num, 12);
    assert!(
        rows[0].address.to_lowercase().ends_with("aa"),
        "{}",
        rows[0].address
    );
}

#[test]
fn a_row_that_is_not_a_deployment_payload_is_an_error() {
    let bad = parse_registries(&table(json!({
        "ok": true,
        "columns": ["registry", "creator", "data", "block_num"],
        "rows": [[topic("aa"), topic("bb"), "0xdeadbeef", 11]],
    })));
    assert!(bad.is_err(), "{bad:?}");
}

#[test]
fn roles_come_back_with_their_names_rather_than_padded_words() {
    let admin = format!("0x{:0<64}", hex::encode("admin"));
    let rows = parse_roles(&table(json!({
        "ok": true,
        "columns": ["checksumHash", "account", "role", "block_num"],
        "rows": [[topic("11"), "0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0", admin, 9]],
    })))
    .expect("one held role");

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].role, "admin");
    assert_eq!(rows[0].block_num, 9);
}

#[test]
fn a_numeric_column_reads_on_either_engine() {
    // tidx serializes integers as JSON numbers on one engine and strings on the
    // other; reading only one drops block_num to zero without saying so.
    for block in [json!(12), json!("12")] {
        let rows = parse_registries(&table(json!({
            "ok": true,
            "columns": ["registry", "creator", "data", "block_num"],
            "rows": [[topic("aa"), topic("bb"), deployed_data(["docs", "", ""]), block]],
        })))
        .expect("a row");
        assert_eq!(rows[0].block_num, 12);
    }
}

fn leaf(index: u64, metadata: &str, block_num: u64) -> Leaf {
    Leaf {
        namespace: REGISTRY.to_string(),
        index,
        commitment: keccak_hex(&bytes(metadata)),
        metadata: bytes(metadata),
        block_num,
        log_idx: 2,
    }
}

#[test]
fn a_record_carries_the_status_appended_against_its_own_version() {
    // Both fixtures are version 1 of the same checksum, so the status belongs to
    // the version the record is at and shows up on it.
    let numbers = BTreeMap::from([(FIXTURE_HASH.to_string(), 1)]);
    let (records, other) = parse_records(
        &[leaf(0, RECORD_METADATA, 11), leaf(1, STATUS_METADATA, 12)],
        &numbers,
    )
    .expect("a record and its status");

    assert_eq!(other, 0);
    assert_eq!(records.len(), 1, "the status is not a record of its own");
    let record = &records[0];
    assert_eq!(record.number, Some(1));
    assert_eq!(record.checksum_hash, FIXTURE_HASH);
    assert_eq!(record.version, 1);
    assert_eq!(record.checksum, "0xabc");
    assert_eq!(record.uri, "ipfs://cid");
    assert_eq!(record.status.as_deref(), Some("approved"));
}

#[test]
fn a_status_without_its_record_is_not_a_record() {
    let (records, _) = parse_records(&[leaf(0, STATUS_METADATA, 11)], &BTreeMap::new())
        .expect("a status leaf alone is not an error");
    assert!(records.is_empty(), "{records:?}");
}

#[test]
fn a_leaf_that_is_not_an_envelope_is_counted_rather_than_fatal() {
    // A registry-scoped writer may append a bare leaf committing to anything. It
    // is a leaf and not a record — left out, and said to have been left out, since
    // silence would look like a registry with fewer leaves than it has.
    let (records, other) = parse_records(
        &[leaf(0, "0xdeadbeef", 11), leaf(1, RECORD_METADATA, 12)],
        &BTreeMap::new(),
    )
    .expect("the record");
    assert_eq!((records.len(), other), (1, 1));
}

#[test]
fn a_record_the_numbering_did_not_reach_keeps_its_place_and_says_so() {
    // The two queries are bounded at the same block, so a gap means they
    // disagree — worth seeing as a null rather than sorting as record 0.
    let (records, _) = parse_records(&[leaf(0, RECORD_METADATA, 11)], &BTreeMap::new())
        .expect("a record with no number");
    assert_eq!(records[0].number, None);
}

#[test]
fn a_record_carries_its_category_pointer_and_author() {
    // Decoded from the envelope, the only place they exist: the precompile's own caller is
    // the registry contract, so an author is unrecoverable from the log's topics.
    let (records, _) = parse_records(&[leaf(0, RECORD_METADATA, 11)], &BTreeMap::new())
        .expect("a classified record");
    assert_eq!(
        records[0].category, 0,
        "Unspecified: the fixture claims no category"
    );
    assert_eq!(records[0].data_pointer, "");
    assert_eq!(records[0].author, AUTHOR);
}

/// The fixture record payload with its version index moved: the envelope the
/// contract emits for the next version of the same record — one word apart.
fn record_at_version(index: u64) -> String {
    let mut raw = bytes(RECORD_METADATA);
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&index.to_be_bytes());
    raw[64..96].copy_from_slice(&word);
    format!("0x{}", hex::encode(raw))
}

/// A `RecordAdded` for this record at `index`, and the leaf logged just before it.
fn announced(index: u64, block: u64, metadata: &str) -> (RecordEvent, Leaf) {
    let mut beside = leaf(index - 1, metadata, block);
    beside.log_idx = 2;
    (
        RecordEvent {
            registry: REGISTRY.to_string(),
            block_num: block,
            log_idx: 3,
            index,
        },
        beside,
    )
}

#[test]
fn a_records_versions_come_back_in_log_order_with_their_leaves() {
    // Every version is a leaf, found through the event that announced it rather
    // than by walking the registry. Each carries its own envelope, so the fields
    // are per version rather than the newest one's repeated.
    let (first, first_leaf) = announced(1, 11, &record_at_version(1));
    let (second, second_leaf) = announced(2, 22, &record_at_version(2));
    let (events, leaves) = ([first, second], [first_leaf, second_leaf]);
    let (versions, other) = versions_of(&pair_leaves(&events, &leaves)).expect("two versions");

    assert_eq!(other, 0);
    assert_eq!(
        versions.iter().map(|v| v.version).collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(versions.iter().map(|v| v.leaf).collect::<Vec<_>>(), [0, 1]);
    assert_eq!(
        versions.iter().map(|v| v.block_num).collect::<Vec<_>>(),
        [11, 22]
    );
    assert!(versions.iter().all(|v| v.checksum == "0xabc"));
    assert!(
        versions.iter().all(|v| v.status.is_none()),
        "attached after"
    );
    assert!(versions.iter().all(|v| v.author.starts_with("0x")));
}

#[test]
fn an_event_with_no_record_leaf_beside_it_is_counted_not_renumbered() {
    // Anyone may emit a `RecordAdded` under this topic, so a stranger's must not
    // shift the versions of the record that owns it.
    let (mine, my_leaf) = announced(1, 11, &record_at_version(1));
    let stranger = RecordEvent {
        registry: NAMESPACE.to_string(),
        block_num: 11,
        log_idx: 0,
        index: 1,
    };
    let (events, leaves) = ([stranger, mine], [my_leaf]);
    let (versions, other) = versions_of(&pair_leaves(&events, &leaves)).expect("mine");

    assert_eq!((versions.len(), other), (1, 1));
    assert_eq!(versions[0].version, 1);
}

#[test]
fn a_version_index_that_is_not_its_place_in_the_log_is_an_error() {
    // Three ways of saying the same thing: the event's index, the envelope's, and
    // the position in the log. Reading a history where they disagree would
    // renumber somebody's versions silently.
    let (first, first_leaf) = announced(1, 11, &record_at_version(1));
    let (third, third_leaf) = announced(3, 22, &record_at_version(3));
    let (events, leaves) = ([first, third], [first_leaf, third_leaf]);
    let gap = versions_of(&pair_leaves(&events, &leaves));
    assert!(gap.is_err(), "{gap:?}");
    assert!(gap.unwrap_err().to_string().contains("version 3"));
}

#[test]
fn the_newest_append_per_namespace_is_the_mmr() {
    // Either shape carries the count and peaks it left: a leaf at index 4 means
    // five leaves, a batch says its count outright.
    let peaks = [hex0x(&[0x22u8; 32])];
    let peak_refs: Vec<&str> = peaks.iter().map(String::as_str).collect();
    let heads = parse_appends(&table(json!({
        "ok": true,
        "columns": ["namespace", "index", "selector", "data", "block_num", "log_idx"],
        "rows": [
            [
                topic(REGISTRY),
                topic("4"),
                LEAF_APPENDED_TOPIC,
                leaf_data(RECORD_COMMITMENT, &hex0x(&[0x11u8; 32]), &peak_refs, b"provenance"),
                12,
                1,
            ],
            [
                topic(NAMESPACE),
                topic("0"),
                LEAVES_APPENDED_TOPIC,
                leaves_data(13, &[(&hex0x(&[0x33u8; 32]), 3)], &hex0x(&[0x44u8; 32]), &peak_refs, b"{}"),
                13,
                0,
            ],
        ],
    })))
    .expect("two MMRs");

    assert_eq!(heads.len(), 2);
    assert_eq!(
        (heads[0].namespace.as_str(), heads[0].count()),
        (REGISTRY, 5)
    );
    assert_eq!(heads[0].root, hex0x(&[0x11u8; 32]));
    assert_eq!(heads[0].peaks, peaks);
    assert_eq!(heads[0].metadata, b"provenance");
    assert_eq!(
        (heads[1].namespace.as_str(), heads[1].count()),
        (NAMESPACE, 13)
    );
    assert_eq!(heads[1].root, hex0x(&[0x44u8; 32]));
}

/// A namespace's history: a batch of three from empty, then one leaf, each row
/// carrying the root and peaks the precompile would have emitted.
fn history_rows(tamper: bool) -> Table {
    let mut mmr = Mmr::default();
    let pair = hash_merge(&hash_leaf(&c(1)), &hash_leaf(&c(2)));
    mmr.push(1, pair).unwrap();
    mmr.push(0, hash_leaf(&c(3))).unwrap();
    let batch_root = hex0x(&mmr.root());
    let batch_peaks: Vec<String> = mmr.peaks.iter().map(|p| hex0x(p)).collect();
    let batch_peaks: Vec<&str> = batch_peaks.iter().map(String::as_str).collect();

    mmr.append(&c(4)).unwrap();
    let leaf_root = hex0x(&mmr.root());
    let leaf_peaks: Vec<String> = mmr.peaks.iter().map(|p| hex0x(p)).collect();
    let leaf_peaks: Vec<&str> = leaf_peaks.iter().map(String::as_str).collect();

    let claimed = if tamper {
        hex0x(&[0xee; 32])
    } else {
        leaf_root
    };
    table(json!({
        "ok": true,
        "columns": ["namespace", "index", "selector", "data", "block_num", "log_idx"],
        "rows": [
            [
                topic(REGISTRY), topic("0"), LEAVES_APPENDED_TOPIC,
                leaves_data(3, &[(&hex0x(&pair), 1), (&hex0x(&hash_leaf(&c(3))), 0)], &batch_root, &batch_peaks, b"{}"),
                5, 0,
            ],
            [
                topic(REGISTRY), topic("3"), LEAF_APPENDED_TOPIC,
                leaf_data(&hex0x(&c(4)), &claimed, &leaf_peaks, b"four"),
                6, 1,
            ],
        ],
    }))
}

#[test]
fn a_namespaces_history_folds_to_the_root_its_events_carry() {
    let appends = parse_appends(&history_rows(false)).expect("two appends");
    assert!(matches!(
        appends[0].what,
        Appended::Leaves {
            first: 0,
            count: 3,
            ..
        }
    ));
    assert!(matches!(appends[1].what, Appended::Leaf { index: 3, .. }));

    let folded = fold(REGISTRY, &appends);
    assert_eq!(folded.mmr.count, 4);
    assert_eq!(folded.leaves, 4, "three in the batch, one after");
    assert!(folded.inconsistent.is_empty(), "{:?}", folded.inconsistent);
    assert_eq!(
        hex0x(&folded.mmr.root()),
        appends[1].root,
        "the event's root is the fold's"
    );
    // The pinned root after four leaves of bytes32(1..4): the same as the precompile's.
    assert_eq!(
        hex0x(&folded.mmr.root()),
        "0x9a444d98cfab773b89efcfe3749342cd1b072e8f2276f9f822fb1e19edabb77b"
    );
    assert_eq!(folded.unverifiable, 1, "`four` is not keccak(\"four\")");
}

#[test]
fn an_event_whose_root_disagrees_with_the_fold_is_inconsistent() {
    // The index's own copy of the log contradicting itself — which is not the
    // chain being wrong, and is reported apart from a mismatch against it.
    let appends = parse_appends(&history_rows(true)).expect("two appends");
    let folded = fold(REGISTRY, &appends);
    assert_eq!(folded.inconsistent.len(), 1, "{:?}", folded.inconsistent);
    assert!(folded.inconsistent[0]
        .detail
        .contains("the event says root"));
    assert_eq!(folded.inconsistent[0].block_num, 6);
}

#[test]
fn an_event_the_precompile_would_have_refused_ends_the_fold_as_inconsistent() {
    // A pair at count 1 is misaligned: the chain never wrote it. Noted like any other
    // inconsistency, and the fold stops there rather than failing the whole audit.
    let mut mmr = Mmr::default();
    mmr.append(&c(1)).unwrap();
    let root = hex0x(&mmr.root());
    let peaks: Vec<String> = mmr.peaks.iter().map(|p| hex0x(p)).collect();
    let peaks: Vec<&str> = peaks.iter().map(String::as_str).collect();
    let bogus = hex0x(&[0xee; 32]);
    let appends = parse_appends(&table(json!({
        "ok": true,
        "columns": ["namespace", "index", "selector", "data", "block_num", "log_idx"],
        "rows": [
            [
                topic(REGISTRY), topic("0"), LEAF_APPENDED_TOPIC,
                leaf_data(&hex0x(&c(1)), &root, &peaks, b"one"),
                5, 0,
            ],
            [
                topic(REGISTRY), topic("1"), LEAVES_APPENDED_TOPIC,
                leaves_data(3, &[(&hex0x(&[0x77; 32]), 1)], &bogus, &peaks, b"{}"),
                6, 0,
            ],
            [
                topic(REGISTRY), topic("3"), LEAF_APPENDED_TOPIC,
                leaf_data(&hex0x(&c(4)), &bogus, &peaks, b"four"),
                7, 0,
            ],
        ],
    })))
    .expect("three appends");

    let folded = fold(REGISTRY, &appends);
    assert_eq!(folded.inconsistent.len(), 1, "{:?}", folded.inconsistent);
    assert_eq!(folded.inconsistent[0].block_num, 6);
    assert!(
        folded.inconsistent[0]
            .detail
            .contains("not a multiple of 2"),
        "{}",
        folded.inconsistent[0].detail
    );
    assert_eq!(
        folded.mmr.count, 1,
        "the fold stops where the log stops making sense"
    );
    assert_eq!(folded.leaves, 1);
    assert_eq!(hex0x(&folded.mmr.root()), root);
}

/// `RecordAdded`'s data section: `abi.encode(uint256 index, string checksum, uint8 category,
/// string dataPointer)`, of which only the first word is read.
fn record_added_data(index: u64) -> String {
    format!(
        "0x{index:064x}{:064x}{:064x}{:064x}{:064x}{:0<64}{:064x}",
        0x80,
        0,
        0xc0,
        5,
        hex::encode("0xabc"),
        0
    )
}

#[test]
fn a_record_event_reads_its_version_off_the_data_section() {
    let events = parse_record_events(&table(json!({
        "ok": true,
        "columns": ["address", "block_num", "log_idx", "data"],
        "rows": [[REGISTRY.to_lowercase(), 5, 3, record_added_data(2)]],
    })))
    .expect("one event");
    assert_eq!(
        events[0],
        RecordEvent {
            registry: REGISTRY.to_string(),
            block_num: 5,
            log_idx: 3,
            index: 2
        },
        "checksummed, and the version is the first word"
    );

    let sql = record_added_sql(Engine::Postgres, None, FIXTURE_HASH, 7, "");
    assert!(sql.contains(&format!(
        "topic1 = '\\x{}'",
        FIXTURE_HASH.trim_start_matches("0x")
    )));
    assert!(!sql.contains("address ="), "every emitter: {sql}");
    let one = record_added_sql(Engine::Postgres, Some(REGISTRY), FIXTURE_HASH, 7, "");
    assert!(one.contains("AND address = "), "{one}");
    assert!(one.contains(RECORD_ADDED_TOPIC.trim_start_matches("0x")));
    assert!(
        status_updated_sql(Engine::Postgres, None, FIXTURE_HASH, 7, "")
            .contains(RECORD_STATUS_UPDATED_TOPIC.trim_start_matches("0x"))
    );
}

#[test]
fn a_status_event_decodes_and_the_newest_wins() {
    let status_data = |index: u64, status: &str| {
        format!(
            "0x{index:064x}{:064x}{:064x}{:0<64}",
            0x40,
            status.len(),
            hex::encode(status)
        )
    };
    let events = parse_status_events(&table(json!({
        "ok": true,
        "columns": ["address", "block_num", "log_idx", "data"],
        "rows": [
            [REGISTRY.to_lowercase(), 5, 3, status_data(1, "approved")],
            [REGISTRY.to_lowercase(), 6, 0, status_data(1, "redacted")],
        ],
    })))
    .expect("two events");
    assert_eq!(events[0].status, "approved");
    let statuses = statuses_of(&events);
    assert_eq!(
        statuses
            .get(&(REGISTRY.to_lowercase(), 1))
            .map(String::as_str),
        Some("redacted"),
        "log order, newest wins"
    );
}

#[test]
fn an_event_pairs_with_the_leaf_logged_just_before_it() {
    // `addRecord` appends and then announces, in one transaction, so the leaf's
    // log_idx is the event's less one. An event with no leaf beside it is some
    // other contract's, or an index missing a row — counted, not fatal.
    let mine = RecordEvent {
        registry: REGISTRY.to_string(),
        block_num: 5,
        log_idx: 3,
        index: 1,
    };
    let stranger = RecordEvent {
        registry: NAMESPACE.to_string(),
        block_num: 5,
        log_idx: 0,
        index: 1,
    };
    let mut beside = leaf(0, RECORD_METADATA, 5);
    beside.log_idx = 2;
    let events = [mine, stranger];
    let leaves = [beside];
    let paired = pair_leaves(&events, &leaves);
    assert!(paired[0].1.is_some(), "the leaf logged just before it");
    assert!(paired[1].1.is_none(), "nothing before log 0");

    let statuses = BTreeMap::from([((REGISTRY.to_lowercase(), 1), "approved".to_string())]);
    let (records, other) = records_at(&paired, &statuses).expect("one registry");
    assert_eq!(other, 1);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].registry, REGISTRY);
    assert_eq!(records[0].record.checksum, "0xabc");
    assert_eq!(records[0].record.status.as_deref(), Some("approved"));
    // A number is a property of one registry's whole ordering, which a lookup
    // filtered on a single hash never walks.
    assert!(records[0].record.number.is_none());
}

#[test]
fn a_name_filter_matches_bytes_and_nothing_near_them() {
    let exact = NameFilter {
        name: Some("docs".into()),
        ..Default::default()
    };
    assert!(exact.matches("docs"));
    for near in ["Docs", "docs ", " docs", "doc", "docs2"] {
        assert!(!exact.matches(near), "{near}");
    }

    let prefix = NameFilter {
        prefix: Some("doc".into()),
        ..Default::default()
    };
    assert!(prefix.matches("docs") && prefix.matches("doc"));
    assert!(!prefix.matches("the-docs"), "a prefix stays anchored");

    let suffix = NameFilter {
        suffix: Some("-eu".into()),
        ..Default::default()
    };
    assert!(suffix.matches("docs-eu"));
    assert!(!suffix.matches("docs-eu-1"), "a suffix stays anchored");

    let contains = NameFilter {
        contains: Some("oc".into()),
        ..Default::default()
    };
    assert!(contains.matches("docs") && contains.matches("the-docs-eu"));
    assert!(!contains.matches("dcs"));
}

#[test]
fn name_filters_all_have_to_match() {
    let both = NameFilter {
        prefix: Some("docs".into()),
        suffix: Some("-eu".into()),
        ..Default::default()
    };
    assert!(both.matches("docs-eu"));
    assert!(!both.matches("docs-us"));
    assert!(!both.matches("the-docs-eu"));

    let contradiction = NameFilter {
        name: Some("docs".into()),
        suffix: Some("-eu".into()),
        ..Default::default()
    };
    assert!(!contradiction.matches("docs"));
    assert!(!contradiction.matches("docs-eu"));
    assert!(NameFilter::default().matches("anything"));
}

#[test]
fn one_deployment_is_looked_up_rather_than_walked_for() {
    let sql = deployment_sql(Engine::Postgres, NAMESPACE, REGISTRY, 7);
    let factory = NAMESPACE.trim_start_matches("0x").to_lowercase();
    let word = format!("{:0>64}", REGISTRY.trim_start_matches("0x").to_lowercase());
    assert!(sql.contains(&format!("address = '\\x{factory}'")), "{sql}");
    assert!(sql.contains(&format!("topic1 = '\\x{word}'")), "{sql}");
    assert!(
        sql.contains(&format!(
            "selector = '\\x{}'",
            REGISTRY_DEPLOYED_TOPIC.trim_start_matches("0x")
        )),
        "{sql}"
    );
    assert!(sql.contains("block_num <= 7"), "bounded like every other");
}

#[test]
fn a_full_page_is_refused_because_it_may_be_short() {
    let full = table(json!({"ok": true, "columns": ["a"], "rows": [[1], [2], [3]]}));
    assert!(
        reject_truncated(full, 3).is_err(),
        "a full page must not pass"
    );
    let short = table(json!({"ok": true, "columns": ["a"], "rows": [[1], [2]]}));
    assert!(
        reject_truncated(short, 3).is_ok(),
        "a short page is the answer"
    );
}

#[test]
fn the_row_cap_is_the_one_tidx_enforces() {
    assert_eq!(HARD_LIMIT, 10_000);
}

#[test]
fn records_are_numbered_in_first_anchor_order_whatever_order_they_arrive_in() {
    let ids = parse_record_ids(&table(json!({
        "ok": true,
        "columns": ["checksum_hash", "block_num", "log_idx"],
        "rows": [
            [topic("cc"), 9, 1],   // hash order puts this first...
            [topic("aa"), 4, 2],   // ...but this record is older
            [topic("bb"), 4, 7],   // same block, later in it
        ],
    })))
    .expect("three first-appearances");

    assert_eq!(ids[&topic("aa")], 1);
    assert_eq!(ids[&topic("bb")], 2, "same block, ordered by log_idx");
    assert_eq!(ids[&topic("cc")], 3);
}

#[test]
fn a_cursor_is_lexicographic_over_its_key_and_spelled_for_its_engine() {
    // (a, b) > (x, y) written out, because not every engine takes a row-value
    // comparison. A walk in log order pages on two numbers; the MMR-head query
    // on a byte string, which goes through the engine's spelling.
    let rows = table(json!({
        "ok": true,
        "columns": ["namespace", "block_num", "log_idx"],
        "rows": [[topic("aa"), 12, 7]],
    }));
    let row = rows.rows[0].clone();

    let by_place = cursor_after(Engine::Postgres, &rows, LEAVES_KEY, &row).expect("a cursor");
    assert_eq!(
        by_place,
        " AND (block_num > 12 OR (block_num = 12 AND (log_idx > 7)))"
    );

    let ns = Engine::Postgres.bytes_literal(&topic("aa"));
    let by_namespace = cursor_after(Engine::Postgres, &rows, APPENDS_KEY, &row).expect("a cursor");
    assert_eq!(by_namespace, format!(" AND (topic1 > {ns})"));
    // The audit's walk pages on all three, namespace first.
    let by_history = cursor_after(Engine::Postgres, &rows, HISTORIES_KEY, &row).expect("a cursor");
    assert_eq!(
        by_history,
        format!(
            " AND (topic1 > {ns} OR (topic1 = {ns} AND \
             (block_num > 12 OR (block_num = 12 AND (log_idx > 7)))))"
        )
    );
    let ch = cursor_after(Engine::ClickHouse, &rows, APPENDS_KEY, &row).expect("a cursor");
    assert!(ch.contains("topic1 > '0x"), "{ch}");
}

#[test]
fn the_fixture_commitments_are_the_envelopes_digests() {
    // What makes a record leaf self-verifying, and what the audit counts against.
    assert_eq!(keccak_hex(&bytes(RECORD_METADATA)), RECORD_COMMITMENT);
    assert_eq!(keccak_hex(&bytes(STATUS_METADATA)), STATUS_COMMITMENT);
}
