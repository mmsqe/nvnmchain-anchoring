//! What tidx answers becomes a head, and the slot that head is checked at.
//! No network: the responses are the shapes tidx's `/query` returns.

mod common;

use common::{bytes, RECORD_COMMITMENT, RECORD_KEY, RECORD_METADATA, STATUS_KEY, STATUS_METADATA};
use nvnmchain_anchoring::eth::{checksum_address, keccak_hex, parse_address};
use nvnmchain_anchoring::precompile::{head_slot, ADDRESS as ANCHORING_ADDRESS, ANCHORED_TOPIC};
use std::collections::BTreeMap;

use nvnmchain_anchoring::envelope::{record_key, status_key};
use nvnmchain_anchoring::registry::{
    deployment_sql, parse_record_ids, parse_records, parse_records_at, parse_registries,
    parse_roles, parse_statuses, parse_versions, record_ids_sql, registries_sql, roles_sql,
    RECORD_ADDED_TOPIC, REGISTRY_DEPLOYED_TOPIC, ROLE_EVENTS,
};
use nvnmchain_anchoring::tidx::{
    anchors_sql, cursor_after, heads_sql, parse_coverage, parse_heads, reject_truncated,
    scoped_heads_sql, Anchor, Engine, Head, Scope, Table, HARD_LIMIT, HEADS_KEY,
};
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

    assert!(heads_sql(Engine::Postgres, 7, "").contains(&format!("'\\x{hexed}'")));
    assert!(heads_sql(Engine::ClickHouse, 7, "").contains(&format!("'0x{hexed}'")));

    // The topic goes through the same spelling — it is a bytea column too.
    let topic0 = ANCHORED_TOPIC.trim_start_matches("0x");
    assert!(heads_sql(Engine::Postgres, 7, "").contains(&format!("'\\x{topic0}'")));

    // Uncast, everywhere: tidx's pushdown extractor reads a bare literal and
    // not a cast expression. `tempo-e2e` sends the same spelling to a running
    // tidx, so this is the form with a live proof behind it.
    assert!(!roles_sql(Engine::Postgres, REGISTRY, 7, "").contains("::bytea"));
    assert!(!heads_sql(Engine::Postgres, 7, "").contains("::bytea"));
}

#[test]
fn heads_are_bounded_at_the_audited_block() {
    // tidx's realtime sync runs ahead of its contiguous interval; a head newer
    // than the block state is read at would report as a false mismatch.
    assert!(heads_sql(Engine::Postgres, 123, "").contains("block_num <= 123"));
}

#[test]
fn the_roles_query_orders_revokes_against_grants() {
    // Not "granted minus revoked": the same key can be granted, revoked and
    // granted again, and a set difference answers that nobody holds it. The
    // partition is every field of the key the wrapper hashes an `acl` envelope
    // under, so two roles for one account stay apart.
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
    // The old wrapper wrote `member` directly in addRegistry and announced the creator's
    // admin only in RegistryAdded, so the fold needed that event as a third arm. A registry
    // announces it as an ordinary RoleGranted at deployment, so two arms answer in full.
    let sql = roles_sql(Engine::Postgres, REGISTRY, 99, "");
    assert!(!sql.contains("RegistryAdded"), "{sql}");
    assert_eq!(ROLE_EVENTS.len(), 2, "{ROLE_EVENTS:?}");
}

#[test]
fn record_numbering_counts_records_and_not_versions() {
    // The window keeps each checksum's *first* appearance; anything looser would
    // give every version its own id, so re-anchoring an early record would
    // renumber it and shift every record after it.
    let sql = record_ids_sql(Engine::Postgres, REGISTRY, 99, "");
    assert!(
        sql.contains("ROW_NUMBER() OVER (PARTITION BY topic1 ORDER BY block_num, log_idx) AS rn")
    );
    assert!(sql.contains("WHERE rn = 1"));

    // Ascending, where the head queries are descending: this one wants the
    // oldest row per key, not the newest.
    assert!(!sql.contains("DESC"), "{sql}");

    // The numbering itself is no longer in SQL, and cannot be: the query pages
    // on the checksum hash, and no page knows how many records preceded it.
    assert!(!sql.contains("record_id"), "{sql}");
}

#[test]
fn record_numbering_reads_topics_and_not_the_data_section() {
    // Why it can fold at all where a whole records projection cannot: the
    // checksum hash is indexed, so the query never meets the dynamic argument
    // tidx would hand back as an ABI offset word.
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
    // The same trap as the roles query: tidx's tables filter on topic0 alone, so
    // without the address any registry's records would be numbered together.
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
    // tidx's generated CTEs filter on topic0 alone — the wrapper is a
    // deployment, not a genesis address, so any contract emitting the same
    // event answers too unless the query says which one. Bounded in the same
    // breath, since both predicates ride the pushdown together.
    let hexed = REGISTRY.trim_start_matches("0x").to_lowercase();
    let bound = "AND block_num <= 7";
    assert!(roles_sql(Engine::Postgres, REGISTRY, 7, "")
        .contains(&format!("address = '\\x{hexed}' {bound}")));
    assert!(roles_sql(Engine::ClickHouse, REGISTRY, 7, "")
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

const FACTORY: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

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
    // Dropping non-hex would turn `0xAB!CD…` into a different, real-looking
    // address and answer "nothing here" — so callers check before building SQL.
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
    // Ordered because deployment order *is* the numbering: an index into the
    // answer is what an on-chain counter would have assigned. Scoped because
    // tidx's tables filter on topic0 alone, so every factory would answer.
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
    let rows = parse_registries(&table(serde_json::json!({
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
    assert_eq!(rows[0].description, "");
    assert_eq!(rows[0].metadata, "{}");
    assert_eq!(rows[1].name, "photos");
    assert_eq!(rows[1].description, "mine");
    assert_eq!(rows[1].block_num, 12);
    // Checksummed on the way out, as every address in this crate is.
    assert!(
        rows[0].address.to_lowercase().ends_with("aa"),
        "{}",
        rows[0].address
    );
}

#[test]
fn a_row_that_is_not_a_deployment_payload_is_an_error() {
    // The query names one factory and one topic0, so a payload that will not
    // decode means the event moved — not that someone anchored something odd.
    // Empty strings would read as a registry with no name.
    let bad = parse_registries(&table(serde_json::json!({
        "ok": true,
        "columns": ["registry", "creator", "data", "block_num"],
        "rows": [[topic("aa"), topic("bb"), "0xdeadbeef", 11]],
    })));
    assert!(bad.is_err(), "{bad:?}");
}

#[test]
fn roles_come_back_with_their_names_rather_than_padded_words() {
    // `admin` is a right-padded bytes32 on the wire. A caller comparing against
    // the string would never match the padding.
    let admin = format!("0x{:0<64}", hex::encode("admin"));
    let rows = parse_roles(&table(serde_json::json!({
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
    for block in [serde_json::json!(12), serde_json::json!("12")] {
        let rows = parse_registries(&table(serde_json::json!({
            "ok": true,
            "columns": ["registry", "creator", "data", "block_num"],
            "rows": [[topic("aa"), topic("bb"), deployed_data(["docs", "", ""]), block]],
        })))
        .expect("a row");
        assert_eq!(rows[0].block_num, 12);
    }
}

/// The checksum hash the vendored fixtures are anchored under: `keccak256("0xabc")`.
const FIXTURE_HASH: &str = "0x851bb152e67e6c958ab7da1431fcaed09ce0efc598885f69a750b3b4b81fc1dc";

fn head(key: &str, metadata: &str) -> Head {
    Head {
        namespace: REGISTRY.to_string(),
        key: key.to_string(),
        commitment: String::new(),
        metadata: bytes(metadata),
    }
}

#[test]
fn a_record_carries_the_status_anchored_against_its_own_version() {
    // Both fixtures are version 1 of the same checksum, so the status belongs to
    // the version the record is at and shows up on it.
    let numbers = BTreeMap::from([(FIXTURE_HASH.to_string(), 1)]);
    let records = parse_records(
        &[
            head(RECORD_KEY, RECORD_METADATA),
            head(STATUS_KEY, STATUS_METADATA),
        ],
        &numbers,
    )
    .expect("a record and its status");

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
    // Statuses are keyed per version and only ever attach to one. Alone, it
    // describes nothing — inventing a record around it would be worse.
    let records = parse_records(&[head(STATUS_KEY, STATUS_METADATA)], &BTreeMap::new())
        .expect("a status head alone is not an error");
    assert!(records.is_empty(), "{records:?}");
}

#[test]
fn a_head_that_is_not_a_registry_envelope_is_an_error() {
    // Only the registry anchors under its own namespace, and only these two
    // shapes. Skipping one would drop a record and still look like a full list.
    let bad = parse_records(&[head(RECORD_KEY, "0xdeadbeef")], &BTreeMap::new());
    assert!(bad.is_err(), "{bad:?}");
}

#[test]
fn a_record_the_numbering_did_not_reach_keeps_its_place_and_says_so() {
    // The two queries are bounded at the same block, so a gap means they
    // disagree — worth seeing as a null rather than sorting as record 0.
    let records = parse_records(&[head(RECORD_KEY, RECORD_METADATA)], &BTreeMap::new())
        .expect("a record with no number");
    assert_eq!(records[0].number, None);
}

/// The fixture record payload with its version index moved. The key derives from
/// the checksum alone, so this is the envelope the contract emits for the next
/// version of the same record — one word apart, which is the whole difference.
fn record_at_version(index: u64) -> String {
    let mut raw = bytes(RECORD_METADATA);
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&index.to_be_bytes());
    raw[64..96].copy_from_slice(&word);
    format!("0x{}", hex::encode(raw))
}

fn anchor(metadata: &str, block_num: u64) -> Anchor {
    Anchor {
        head: head(RECORD_KEY, metadata),
        block_num,
    }
}

#[test]
fn a_records_versions_come_back_in_log_order() {
    // History lives only here: the chain keeps one word per key, so version 1 is
    // whatever the head replaced. Every version carries its own envelope, so the
    // fields are per version rather than the newest one's repeated.
    let versions = parse_versions(&[
        anchor(&record_at_version(1), 11),
        anchor(&record_at_version(2), 22),
    ])
    .expect("two versions");

    assert_eq!(
        versions.iter().map(|v| v.version).collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(
        versions.iter().map(|v| v.block_num).collect::<Vec<_>>(),
        [11, 22]
    );
    assert!(versions.iter().all(|v| v.checksum == "0xabc"));
    assert!(
        versions.iter().all(|v| v.status.is_none()),
        "attached after"
    );
}

#[test]
fn a_version_index_that_is_not_its_place_in_the_log_is_an_error() {
    // The two orderings are the same fact twice: the contract increments the
    // index once per anchor. Reading a history where they disagree would
    // renumber somebody's versions silently.
    let gap = parse_versions(&[
        anchor(&record_at_version(1), 11),
        anchor(&record_at_version(3), 22),
    ]);
    assert!(gap.is_err(), "{gap:?}");
    assert!(gap.unwrap_err().to_string().contains("version 3"));
}

#[test]
fn the_anchors_query_returns_every_row_under_one_key_oldest_first() {
    // Not a heads query: this one keeps the rows the head replaced, which is the
    // only place a version before the newest exists.
    let sql = anchors_sql(Engine::Postgres, REGISTRY, RECORD_KEY, 7, "");
    let word = format!("{:0>64}", REGISTRY.trim_start_matches("0x").to_lowercase());
    assert!(sql.contains(&format!("topic1 = '\\x{word}'")), "{sql}");
    assert!(
        sql.contains(&format!(
            "topic2 = '\\x{}'",
            RECORD_KEY.trim_start_matches("0x")
        )),
        "{sql}"
    );
    assert!(!sql.contains("ROW_NUMBER"), "no fold to one row per key");
    assert!(sql.contains("ORDER BY block_num, log_idx"), "{sql}");
    assert!(sql.contains("block_num <= 7"), "{sql}");
}

#[test]
fn the_anchored_keys_derive_from_the_checksum_alone() {
    // What makes a lookup by checksum possible: the key is `keccak256(checksum)`
    // put through the contract's own derivation, with no registry in it. Checked
    // against payloads a forge run against the shipped contract emitted, so a
    // drift in either derivation fails here rather than answering empty.
    let hash = keccak_hex(b"0xabc");
    assert_eq!(hash, FIXTURE_HASH);
    assert_eq!(record_key(&hash).as_deref(), Some(RECORD_KEY));
    assert_eq!(status_key(&hash, 1).as_deref(), Some(STATUS_KEY));
    // A version that was never anchored still has a key; it just holds nothing.
    assert_ne!(status_key(&hash, 2).as_deref(), Some(STATUS_KEY));
}

#[test]
fn one_key_answers_for_every_registry_that_anchored_it() {
    // The successor to `records(registry_id = 0, checksum, …)`: two registries
    // holding the same checksum are two namespaces under one key.
    let elsewhere = "0x44DA54d3f5416A9Ae699d54EcB83c3043c41319E";
    let mut theirs = head(RECORD_KEY, RECORD_METADATA);
    theirs.namespace = elsewhere.to_string();

    let (records, other) =
        parse_records_at(&[head(RECORD_KEY, RECORD_METADATA), theirs]).expect("both registries");

    assert_eq!(other, 0);
    assert_eq!(
        records
            .iter()
            .map(|r| r.registry.as_str())
            .collect::<Vec<_>>(),
        [elsewhere, REGISTRY],
        "one row per registry, named by the address that anchored it"
    );
    assert!(records.iter().all(|r| r.record.checksum == "0xabc"));
    // A number is a property of one registry's whole ordering, which a lookup
    // filtered on a single key never walks.
    assert!(records.iter().all(|r| r.record.number.is_none()));
}

#[test]
fn a_strangers_anchor_under_the_same_key_is_counted_not_fatal() {
    // Anyone may anchor under any key, so this lookup cannot treat a payload it
    // does not recognise as its own copy gone bad — that would let one address
    // take the answer away from every registry sharing the key. Left out and
    // counted, where a registry's own namespace still errors.
    let mut stranger = head(RECORD_KEY, "0xdeadbeef");
    stranger.namespace = "0x44DA54d3f5416A9Ae699d54EcB83c3043c41319E".to_string();

    let (records, other) =
        parse_records_at(&[head(RECORD_KEY, RECORD_METADATA), stranger]).expect("the registry's");

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].registry, REGISTRY);
    assert_eq!(other, 1, "and the answer says what it left out");
}

#[test]
fn one_deployment_is_looked_up_rather_than_walked_for() {
    // "registry 999 does not exist" was a number held against a counter. The
    // address that replaced the id carries no such fact, so the deployment log
    // answers instead — on `topic1`, which is indexed, and scoped to the one
    // factory whose registries this service knows.
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
fn a_keyed_heads_query_narrows_on_the_key_topic() {
    // `topic2` is the key. One key across every namespace is the cross-registry
    // lookup; a set of them is one round trip for a record's statuses.
    let one = [RECORD_KEY.to_string()];
    let keyed = scoped_heads_sql(Engine::Postgres, Scope::keyed(&one), 7, "");
    let bare = RECORD_KEY.trim_start_matches("0x");
    assert!(keyed.contains(&format!("topic2 = '\\x{bare}'")), "{keyed}");
    assert!(!keyed.contains("topic1 ="), "every namespace answers");

    let both = [RECORD_KEY.to_string(), STATUS_KEY.to_string()];
    let scope = Scope {
        namespace: Some(REGISTRY),
        keys: &both,
    };
    let many = scoped_heads_sql(Engine::Postgres, scope, 7, "");
    assert!(many.contains("topic2 IN ("), "{many}");
    assert!(many.contains(STATUS_KEY.trim_start_matches("0x")), "{many}");
    assert!(many.contains("topic1 = "), "narrowed to one registry too");
}

#[test]
fn statuses_are_keyed_by_the_namespace_that_anchored_them() {
    // One status key is the same word in every registry holding that record at
    // that version, so the namespace is the only thing keeping two apart.
    let mut elsewhere = head(STATUS_KEY, STATUS_METADATA);
    elsewhere.namespace = "0x44DA54d3f5416A9Ae699d54EcB83c3043c41319E".to_string();
    let statuses = parse_statuses(&[head(STATUS_KEY, STATUS_METADATA), elsewhere.clone()])
        .expect("both statuses");

    assert_eq!(statuses.len(), 2);
    for namespace in [REGISTRY, elsewhere.namespace.as_str()] {
        assert_eq!(
            statuses
                .get(&(namespace.to_string(), FIXTURE_HASH.to_string(), 1))
                .map(String::as_str),
            Some("approved"),
        );
    }
}

#[test]
fn a_namespace_scoped_heads_query_narrows_on_the_caller_topic() {
    // `topic1` is the caller, and one registry's projection wants only its own
    // heads — the audit's chain-wide query would drag in every namespace.
    // Padded to a full word: `topic1` is 32 bytes with the address right-aligned,
    // and the bare 20-byte form matches nothing — which reads as a registry that
    // anchored nothing rather than as a broken query. The e2e caught this; this
    // is the assertion that would have.
    let hexed = REGISTRY.trim_start_matches("0x").to_lowercase();
    let word = format!("{hexed:0>64}");
    let scoped = scoped_heads_sql(Engine::Postgres, Scope::of(REGISTRY), 7, "");
    assert!(
        scoped.contains(&format!("topic1 = '\\x{word}'")),
        "{scoped}"
    );
    assert!(
        !scoped.contains(&format!("topic1 = '\\x{hexed}'")),
        "{scoped}"
    );
    assert!(scoped.contains("AND block_num <= 7"), "{scoped}");
    // ...and the chain-wide one still is not scoped, or the audit would only
    // ever check one namespace.
    assert!(!heads_sql(Engine::Postgres, 7, "").contains("topic1 = "));
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
fn records_are_numbered_in_first_anchor_order_whatever_order_they_arrive_in() {
    // The query pages on the checksum hash, so rows come back in hash order and
    // no page knows what preceded it. The id is the position once they are put
    // back in log order — which is the order the contract's counter used.
    let ids = parse_record_ids(&table(serde_json::json!({
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
