//! A log becomes a row, and the head the index derives is the one the chain
//! keeps. No network: the logs are the shapes a node returns.

mod common;

use common::{bytes, REGISTRY_KEY, UNTAGGED_REGISTRY_COMMITMENT, UNTAGGED_REGISTRY_METADATA};
use nvnmchain_anchoring::db::{self, Db};
use nvnmchain_anchoring::eth::{checksum_address, keccak_hex};
use nvnmchain_anchoring::indexer::parse_anchored;
use nvnmchain_anchoring::precompile::{head_slot, ADDRESS as ANCHORING_ADDRESS, ANCHORED_TOPIC};
use nvnmchain_anchoring::registry::REGISTRY_TOPICS;
use serde_json::json;

const NAMESPACE: &str = "0x44DA54d3f5416A9Ae699d54EcB83c3043c41319E";

fn temp_db(name: &str) -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = db::open(dir.path().join(name).to_str().unwrap()).expect("open");
    (dir, db)
}

/// An `Anchored` log as a node reports it: caller and key indexed, commitment
/// and payload ABI-encoded in `data`.
fn anchored_log(
    key: &str,
    commitment: &str,
    metadata: &[u8],
    block: u64,
    index: u64,
) -> serde_json::Value {
    let mut data = String::from("0x");
    data.push_str(commitment.strip_prefix("0x").unwrap_or(commitment));
    data.push_str(&format!("{:064x}", 0x40));
    data.push_str(&format!("{:064x}", metadata.len()));
    let mut padded = hex::encode(metadata);
    while !padded.len().is_multiple_of(64) {
        padded.push('0');
    }
    data.push_str(&padded);
    json!({
        "address": ANCHORING_ADDRESS,
        "topics": [
            ANCHORED_TOPIC,
            format!("0x{}{}", "00".repeat(12), NAMESPACE.trim_start_matches("0x").to_lowercase()),
            key,
        ],
        "data": data,
        "blockNumber": format!("0x{block:x}"),
        "logIndex": format!("0x{index:x}"),
        "transactionHash": format!("0x{}", "ab".repeat(32)),
    })
}

#[test]
fn registry_topics_match_their_signatures() {
    // A mistyped topic would match nothing and index silently empty.
    for (topic, signature) in REGISTRY_TOPICS {
        assert_eq!(&keccak_hex(signature.as_bytes()), topic, "{signature}");
    }
}

#[test]
fn an_anchored_log_becomes_a_row() {
    let (_dir, db) = temp_db("ingest.db");
    let log = anchored_log(
        REGISTRY_KEY,
        UNTAGGED_REGISTRY_COMMITMENT,
        &bytes(UNTAGGED_REGISTRY_METADATA),
        100,
        3,
    );
    let event = parse_anchored(&log).expect("parsed");
    assert_eq!(event.namespace, NAMESPACE);
    assert_eq!(event.key, REGISTRY_KEY);
    assert_eq!(event.commitment, UNTAGGED_REGISTRY_COMMITMENT);
    assert_eq!(event.metadata, bytes(UNTAGGED_REGISTRY_METADATA));

    let conn = db::lock(&db);
    db::insert_anchored(&conn, &event).expect("insert");
    // Re-scanning a range must not duplicate: (block, log index) is the identity.
    db::insert_anchored(&conn, &event).expect("insert again");
    assert_eq!(db::count_anchored(&conn).unwrap(), 1);

    let history = db::key_history(&conn, NAMESPACE, REGISTRY_KEY).expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].metadata, bytes(UNTAGGED_REGISTRY_METADATA));
}

#[test]
fn the_head_is_the_newest_revision() {
    let (_dir, db) = temp_db("heads.db");
    let key = format!("0x{}", "55".repeat(32));
    let conn = db::lock(&db);
    for (block, byte) in [(200u64, "01"), (201, "02")] {
        let commitment = format!("0x{}", byte.repeat(32));
        let log = anchored_log(&key, &commitment, b"v", block, 0);
        db::insert_anchored(&conn, &parse_anchored(&log).expect("parsed")).expect("insert");
    }
    let history = db::key_history(&conn, NAMESPACE, &key).expect("history");
    assert_eq!(
        history.iter().map(|r| r.block_number).collect::<Vec<_>>(),
        vec![201, 200]
    );
    let heads = db::heads(&conn).expect("heads");
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].commitment, format!("0x{}", "02".repeat(32)));
}

#[test]
fn malformed_logs_are_refused() {
    // Truncated data: no commitment to store, so no row rather than a wrong head.
    let short = json!({
        "address": ANCHORING_ADDRESS,
        "topics": [ANCHORED_TOPIC, format!("0x{}", "00".repeat(32)), format!("0x{}", "11".repeat(32))],
        "data": "0x00",
        "blockNumber": "0x1",
        "logIndex": "0x0",
        "transactionHash": format!("0x{}", "ab".repeat(32)),
    });
    assert!(parse_anchored(&short).is_none());

    // A different event at the same address is not ours.
    let foreign = json!({
        "address": ANCHORING_ADDRESS,
        "topics": [format!("0x{}", "de".repeat(32))],
        "data": "0x",
        "blockNumber": "0x1",
        "logIndex": "0x0",
        "transactionHash": format!("0x{}", "ab".repeat(32)),
    });
    assert!(parse_anchored(&foreign).is_none());
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
fn a_reorg_drops_everything_above_the_fork() {
    let (_dir, db) = temp_db("reorg.db");
    let conn = db::lock(&db);
    let key = format!("0x{}", "66".repeat(32));
    for block in [10u64, 11, 12] {
        let log = anchored_log(&key, &format!("0x{:064x}", block), b"", block, 0);
        db::insert_anchored(&conn, &parse_anchored(&log).expect("parsed")).expect("insert");
        db::save_checkpoint(&conn, block, &format!("0x{:064x}", block)).expect("checkpoint");
    }
    db::set_cursor(&conn, db::SOURCE_ANCHORED, 12).expect("cursor");

    db::rollback_to(&conn, 11).expect("rollback");

    assert_eq!(
        db::count_anchored(&conn).unwrap(),
        1,
        "only block 10 survives"
    );
    assert_eq!(db::cursor(&conn, db::SOURCE_ANCHORED), Some(10));
    assert_eq!(db::recent_checkpoints(&conn, 10).unwrap().len(), 1);
}

#[test]
fn a_source_added_later_starts_from_the_beginning() {
    // Configuring the registry after a sync has reached the head must not
    // inherit that cursor: its whole history would be skipped, silently.
    let (_dir, db) = temp_db("cursors.db");
    let conn = db::lock(&db);
    db::set_cursor(&conn, db::SOURCE_ANCHORED, 5_000).expect("cursor");

    let registry = db::registry_source("0x44DA54d3f5416A9Ae699d54EcB83c3043c41319E");
    assert_eq!(
        db::cursor(&conn, &registry),
        None,
        "a new source has no cursor"
    );
    assert_eq!(db::cursor(&conn, db::SOURCE_ANCHORED), Some(5_000));
    // Addresses are normalized, so case cannot fork one source into two.
    assert_eq!(
        registry,
        db::registry_source("0x44da54d3f5416a9ae699d54ecb83c3043c41319e")
    );
}

#[test]
fn a_scanned_range_with_no_checkpoint_is_reported() {
    let (_dir, db) = temp_db("gap.db");
    let conn = db::lock(&db);
    assert_eq!(
        db::uncheckpointed(&conn).unwrap(),
        None,
        "nothing scanned yet"
    );

    db::set_cursor(&conn, db::SOURCE_ANCHORED, 100).expect("cursor");
    assert_eq!(db::uncheckpointed(&conn).unwrap(), Some((0, 100)));

    db::save_checkpoint(&conn, 100, &format!("0x{:064x}", 1)).expect("checkpoint");
    assert_eq!(db::uncheckpointed(&conn).unwrap(), None);
}
