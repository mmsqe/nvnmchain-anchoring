//! Reading a `Registry` payload out of a leaf's metadata.
//!
//! Every envelope leads with a `bytes32` kind, so one word identifies the shape, and the
//! layout is then read strictly, which is what keeps a foreign payload from reading as a
//! record. Payloads are dumped from a forge run against the shipped contract — re-encoding
//! them here would only check the decoder against its own guess.

mod common;

use common::{
    bytes, AUTHOR, FIXTURE_HASH, RECORD_COMMITMENT, RECORD_METADATA, STATUS_COMMITMENT,
    STATUS_METADATA,
};
use nvnmchain_anchoring::envelope::{
    decode_envelope, decode_uint_string, is_self_verifying, read_payload, Payload,
};

fn decoded(metadata: &str) -> nvnmchain_anchoring::envelope::Envelope {
    decode_envelope(&bytes(metadata)).expect("decodes as an envelope")
}

#[test]
fn record_envelope_decodes() {
    let env = decoded(RECORD_METADATA);
    assert_eq!(env.kind, "record");
    assert_eq!(env.field("checksum_hash"), FIXTURE_HASH);
    assert_eq!(env.checksum_hash(), FIXTURE_HASH);
    assert_eq!(env.field("index"), "1");
    assert_eq!(env.field("uri"), "ipfs://cid");
    assert_eq!(env.field("checksum"), "0xabc");
    assert_eq!(env.field("checksum_algo"), "sha256");
    assert_eq!(env.field("metadata"), "{}");
    assert_eq!(
        env.field("category"),
        "0",
        "Unspecified: a record claiming no category"
    );
    assert_eq!(env.field("data_pointer"), "");
    // The precompile's own caller is the registry contract, so this is the only place the
    // author of a version exists.
    assert_eq!(env.field("author"), AUTHOR);
    assert!(env.field("timestamp").parse::<u128>().is_ok());
}

#[test]
fn status_envelope_decodes() {
    let env = decoded(STATUS_METADATA);
    assert_eq!(env.kind, "status");
    assert_eq!(env.field("checksum_hash"), FIXTURE_HASH);
    assert_eq!(env.field("index"), "1");
    assert_eq!(env.field("status"), "approved");
    assert_eq!(env.field("author"), AUTHOR);
    assert_eq!(env.field("seq"), "1");
}

#[test]
fn the_kind_word_decides_the_shape() {
    // One word, read before anything else: a record payload never reads as a status and
    // a status never as a record, so a leaf is classified from the log alone.
    assert_eq!(decoded(RECORD_METADATA).kind, "record");
    assert_eq!(decoded(STATUS_METADATA).kind, "status");
}

#[test]
fn a_registry_id_is_not_part_of_any_envelope() {
    // The registry is the namespace the leaf was appended under, not a field.
    let env = decoded(RECORD_METADATA);
    assert!(
        env.fields.iter().all(|(name, _)| *name != "registry_id"),
        "{:?}",
        env.fields
    );
}

#[test]
fn foreign_payloads_are_not_envelopes() {
    // Anything may be a leaf — a registry-scoped writer appends whatever it commits to —
    // so a payload that is not ours reads as something else rather than being forced into
    // a schema. A record with a word of slack after its tail is not ours either.
    let mut padded = bytes(RECORD_METADATA);
    padded.extend_from_slice(&[0u8; 32]);
    for metadata in [
        bytes("0x"),
        bytes("0x00"),
        bytes(&format!("0x{}", "ab".repeat(64))),
        padded,
    ] {
        assert!(
            decode_envelope(&metadata).is_none(),
            "{}",
            hex::encode(metadata)
        );
    }
}

#[test]
fn record_leaves_are_self_verifying() {
    // The registry's own guarantee: a record leaf commits to the digest of its envelope,
    // which holds whatever the payload turns out to mean.
    assert!(is_self_verifying(
        RECORD_COMMITMENT,
        &bytes(RECORD_METADATA)
    ));
    assert!(is_self_verifying(
        STATUS_COMMITMENT,
        &bytes(STATUS_METADATA)
    ));
    assert!(!is_self_verifying(
        STATUS_COMMITMENT,
        &bytes(RECORD_METADATA)
    ));
}

#[test]
fn payloads_that_are_not_envelopes_still_read() {
    // A plain EOA appends whatever it likes; the reading degrades rather than failing.
    assert!(matches!(read_payload(br#"{"v":1}"#), Payload::Json(_)));
    assert!(matches!(read_payload(b"hello"), Payload::Text(_)));
    assert!(matches!(read_payload(&[0xff, 0xfe]), Payload::Opaque));
    assert!(matches!(
        read_payload(&bytes(RECORD_METADATA)),
        Payload::Envelope(_)
    ));
}

#[test]
fn a_status_event_decodes_its_index_and_text() {
    // `RecordStatusUpdated`'s data section: `abi.encode(uint256 index, string status)`.
    let data = format!(
        "0x{:064x}{:064x}{:064x}{:0<64}",
        2,
        0x40,
        8,
        hex::encode("approved")
    );
    assert_eq!(
        decode_uint_string(&bytes(&data)),
        Some((2, "approved".to_string()))
    );
    assert!(decode_uint_string(&bytes("0x00")).is_none());
}
