//! Reading `AnchoringRegistry` envelopes out of anchored metadata.
//!
//! The payloads below are what `AnchoringRegistry.sol` actually emits, dumped
//! from a forge run against the shipped contracts rather than re-encoded here;
//! a decoder checked against its own guess proves nothing. `tempo-e2e`'s
//! `test_anchoring_registry.py` decodes the same record shape from a live node.

use nvnmchain_anchoring::envelope::{decode_envelope, is_self_verifying, read_payload, Payload};
use nvnmchain_anchoring::eth::keccak_hex;
use nvnmchain_anchoring::precompile::{ANCHORED_SIGNATURE, ANCHORED_TOPIC};

mod common;
use common::*;

#[test]
fn anchored_topic_matches_the_signature() {
    assert_eq!(keccak_hex(ANCHORED_SIGNATURE.as_bytes()), ANCHORED_TOPIC);
}

#[test]
fn registry_envelope_decodes() {
    let env = decode_envelope(REGISTRY_KEY, &bytes(UNTAGGED_REGISTRY_METADATA))
        .expect("registry envelope");
    assert_eq!(env.kind, "registry");
    assert_eq!(env.field("id"), "1");
    assert_eq!(env.field("name"), "Docs");
    assert_eq!(env.field("description"), "internal docs");
    assert_eq!(
        env.field("creator"),
        "0x2190d584E30F4a2396C1487Aa784428f2068CBE8"
    );
    assert_eq!(env.summary(), "Registry #1 — Docs");
}

#[test]
fn record_envelope_decodes() {
    let env =
        decode_envelope(RECORD_KEY, &bytes(UNTAGGED_RECORD_METADATA)).expect("record envelope");
    assert_eq!(env.kind, "record");
    assert_eq!(env.field("uri"), "ipfs://cid");
    assert_eq!(env.field("checksum"), "0xabc");
    assert_eq!(env.field("checksum_algo"), "sha256");
    assert_eq!(env.summary(), "Record #1 v1 — 0xabc");
}

#[test]
fn status_envelope_decodes() {
    let env =
        decode_envelope(STATUS_KEY, &bytes(UNTAGGED_STATUS_METADATA)).expect("status envelope");
    assert_eq!(env.kind, "status");
    assert_eq!(env.field("status"), "approved");
    // The sequence number is what makes re-asserting the same status a fresh anchor.
    assert_eq!(env.field("seq"), "1");
}

#[test]
fn envelopes_are_identified_by_the_key_they_are_anchored_under() {
    // The payloads carry nothing naming their shape; the key does, and each is
    // keccak256(abi.encode(kind, ids…)) over ids the payload itself repeats.
    assert!(decode_envelope(RECORD_KEY, &bytes(UNTAGGED_REGISTRY_METADATA)).is_none());
    let wrong = format!("0x{}", "11".repeat(32));
    assert!(decode_envelope(&wrong, &bytes(UNTAGGED_STATUS_METADATA)).is_none());
}

#[test]
fn foreign_payloads_are_not_envelopes() {
    for payload in [
        "0x",
        "0xdeadbeef",
        &format!("0x{}", "ab".repeat(64)),
        &format!("0x{}", "00".repeat(32 * 6)),
    ] {
        assert!(
            decode_envelope(REGISTRY_KEY, &bytes(payload)).is_none(),
            "payload {payload} should not decode as an envelope"
        );
    }
}

#[test]
fn anchor_and_hash_payloads_are_self_verifying() {
    // Every registry write goes through anchorAndHash, so the event commits to
    // the digest of its own metadata.
    assert!(is_self_verifying(
        UNTAGGED_REGISTRY_COMMITMENT,
        &bytes(UNTAGGED_REGISTRY_METADATA)
    ));
    assert!(is_self_verifying(
        UNTAGGED_RECORD_COMMITMENT,
        &bytes(UNTAGGED_RECORD_METADATA)
    ));
    assert!(is_self_verifying(
        UNTAGGED_STATUS_COMMITMENT,
        &bytes(UNTAGGED_STATUS_METADATA)
    ));
    assert!(!is_self_verifying(
        UNTAGGED_REGISTRY_COMMITMENT,
        &bytes(UNTAGGED_RECORD_METADATA)
    ));
}

#[test]
fn payloads_that_are_not_envelopes_still_read() {
    // What tempo-e2e anchors from a plain EOA: self-describing JSON, under a
    // key derived by the application rather than by AnchoringRegistry.
    let key = format!("0x{}", "77".repeat(32));
    let json = br#"{"v":1,"kind":"content","data":{"uri":"ipfs://QmX"}}"#;
    match read_payload(&key, json) {
        Payload::Json(value) => assert_eq!(value["kind"], "content"),
        other => panic!("expected json, got {other:?}"),
    }
    match read_payload(&key, b"plain note") {
        Payload::Text(text) => assert_eq!(text, "plain note"),
        other => panic!("expected text, got {other:?}"),
    }
    assert!(matches!(
        read_payload(&key, &[0xff, 0xfe, 0x00]),
        Payload::Opaque
    ));
    // ...and a registry envelope still wins over the weaker readings.
    assert!(matches!(
        read_payload(REGISTRY_KEY, &bytes(UNTAGGED_REGISTRY_METADATA)),
        Payload::Envelope(_)
    ));
}

// ---------------------------------------------------------------------------
// The tagged format the contracts are moving to
// ---------------------------------------------------------------------------

#[test]
fn tagged_envelopes_decode() {
    // A registry is an upgradeable proxy, so one namespace emits both formats
    // across an upgrade and the indexer has to read either.
    let env = decode_envelope(REGISTRY_KEY, &bytes(TAGGED_REGISTRY_METADATA)).expect("registry");
    assert_eq!((env.kind, env.tagged), ("registry", true));
    assert_eq!(env.field("name"), "Docs");
    assert_eq!(env.summary(), "Registry #1 — Docs");

    let env = decode_envelope(RECORD_KEY, &bytes(TAGGED_RECORD_METADATA)).expect("record");
    assert_eq!((env.kind, env.tagged), ("record", true));
    assert_eq!(env.field("uri"), "ipfs://cid");

    let env = decode_envelope(STATUS_KEY, &bytes(TAGGED_STATUS_METADATA)).expect("status");
    assert_eq!((env.kind, env.tagged), ("status", true));
    assert_eq!(env.field("status"), "approved");

    // ...and the untagged ones still read, under the same keys.
    let env = decode_envelope(REGISTRY_KEY, &bytes(UNTAGGED_REGISTRY_METADATA)).expect("untagged");
    assert_eq!((env.kind, env.tagged), ("registry", false));
}

#[test]
fn acl_envelopes_decode_and_have_no_untagged_form() {
    // Grants and revokes are anchored only in the tagged format — before it,
    // role history was not in the log at all.
    let env = decode_envelope(ACL_KEY, &bytes(ACL_METADATA)).expect("acl envelope");
    assert_eq!((env.kind, env.tagged), ("acl", true));
    assert_eq!(env.field("registry_id"), "1");
    assert_eq!(env.field("account"), ACL_ACCOUNT);
    // bytes32 that is right-padded text reads as text, like Solidity wrote it.
    assert_eq!(env.field("role"), "editor");
    assert_eq!(env.field("granted"), "true");
    assert!(env.summary().contains("granted to"));
    assert!(is_self_verifying(ACL_COMMITMENT, &bytes(ACL_METADATA)));
}

#[test]
fn a_tagged_payload_under_the_wrong_key_is_still_refused() {
    // The tag says what it is; the key still has to agree, so a stale schema
    // cannot quietly read one shape as another.
    assert!(decode_envelope(RECORD_KEY, &bytes(TAGGED_REGISTRY_METADATA)).is_none());
    assert!(decode_envelope(REGISTRY_KEY, &bytes(ACL_METADATA)).is_none());
}
