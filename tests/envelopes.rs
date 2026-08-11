//! Reading a `Registry` payload out of anchored metadata.
//!
//! Every envelope leads with a `bytes32` kind, so one word identifies the shape; the ids
//! inside must then reproduce the key it was anchored under, which catches a schema that has
//! drifted from the contract and binds the payload to its key. Payloads are dumped from a
//! forge run against the shipped contract — re-encoding them here would only check the
//! decoder against its own guess.

mod common;

use common::{
    bytes, RECORD_COMMITMENT, RECORD_KEY, RECORD_METADATA, STATUS_COMMITMENT, STATUS_KEY,
    STATUS_METADATA,
};
use nvnmchain_anchoring::envelope::{decode_envelope, is_self_verifying, read_payload, Payload};

fn decoded(key: &str, metadata: &str) -> nvnmchain_anchoring::envelope::Envelope {
    decode_envelope(key, &bytes(metadata)).expect("decodes as an envelope")
}

#[test]
fn record_envelope_decodes() {
    let env = decoded(RECORD_KEY, RECORD_METADATA);
    assert_eq!(env.kind, "record");
    assert_eq!(env.field("record_id"), "1");
    assert_eq!(env.field("index"), "1");
    assert_eq!(env.field("uri"), "ipfs://cid");
    assert_eq!(env.field("checksum"), "0xabc");
    assert_eq!(env.field("checksum_algo"), "sha256");
    assert_eq!(env.field("metadata"), "{}");
    assert!(env.field("timestamp").parse::<u128>().is_ok());
}

#[test]
fn status_envelope_decodes() {
    let env = decoded(STATUS_KEY, STATUS_METADATA);
    assert_eq!(env.kind, "status");
    assert_eq!(env.field("record_id"), "1");
    assert_eq!(env.field("index"), "1");
    assert_eq!(env.field("status"), "approved");
    assert_eq!(env.field("seq"), "1");
}

#[test]
fn envelopes_are_identified_by_the_key_they_are_anchored_under() {
    // The kind word says what shape to try; the key derivation says the ids inside are the
    // ones it was actually anchored under. A record payload under a status key is neither.
    assert!(decode_envelope(STATUS_KEY, &bytes(RECORD_METADATA)).is_none());
    assert!(decode_envelope(RECORD_KEY, &bytes(STATUS_METADATA)).is_none());
}

#[test]
fn a_payload_under_the_wrong_key_is_refused() {
    // Same shape, same kind, a key from another record: the ids no longer reproduce it.
    let elsewhere = format!("0x{}", "5c".repeat(32));
    assert!(decode_envelope(&elsewhere, &bytes(RECORD_METADATA)).is_none());
}

#[test]
fn a_registry_id_is_no_longer_part_of_any_key() {
    // recordKey(record_id) — one id, not two. Were the old two-id derivation still in use,
    // the shipped payload could not reproduce the key the contract anchored it under, and
    // the test above would be the one failing.
    let env = decoded(RECORD_KEY, RECORD_METADATA);
    assert!(
        env.fields.iter().all(|(name, _)| *name != "registry_id"),
        "the registry is the address it was anchored under, not a field: {:?}",
        env.fields
    );
}

#[test]
fn foreign_payloads_are_not_envelopes() {
    // Anything may be anchored, so a payload that is not ours reads as something else
    // rather than being forced into a schema.
    for metadata in ["0x", "0x00", &format!("0x{}", "ab".repeat(64))] {
        assert!(
            decode_envelope(RECORD_KEY, &bytes(metadata)).is_none(),
            "{metadata}"
        );
    }
}

#[test]
fn anchor_and_hash_payloads_are_self_verifying() {
    // The precompile's own guarantee: anchorAndHash commits to the digest of its metadata,
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
    // A plain EOA anchors whatever it likes; the reading degrades rather than failing.
    let key = format!("0x{}", "11".repeat(32));
    assert!(matches!(
        read_payload(&key, br#"{"v":1}"#),
        Payload::Json(_)
    ));
    assert!(matches!(read_payload(&key, b"hello"), Payload::Text(_)));
    assert!(matches!(read_payload(&key, &[0xff, 0xfe]), Payload::Opaque));
}

#[test]
fn a_registry_payload_reads_as_an_envelope() {
    // ...and one that is ours takes the Envelope arm ahead of the fallbacks.
    assert!(matches!(
        read_payload(RECORD_KEY, &bytes(RECORD_METADATA)),
        Payload::Envelope(_)
    ));
}
