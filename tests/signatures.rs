//! The topics this indexer filters on, checked against the contracts that emit them.
//!
//! `ingest.rs` and `envelopes.rs` assert each topic0 is the keccak of the signature beside it.
//! That catches a mistyped hash, not a signature that drifted from the contract: those two stay
//! consistent with each other while matching nothing on chain, and a filter matching nothing
//! indexes silently empty.
//!
//! So signatures are compared against the contracts' compiled event ABI, vendored by
//! `make fixtures`. Nothing offline can spot a stale fixture, so rerun it on any event change.

use nvnmchain_anchoring::eth::keccak_hex;
use nvnmchain_anchoring::precompile::{ANCHORED_SIGNATURE, ANCHORED_TOPIC};
use nvnmchain_anchoring::registry::REGISTRY_TOPICS;
use std::collections::BTreeSet;

const FIXTURE: &str = include_str!("fixtures/contract-events.json");

fn fixture() -> serde_json::Value {
    serde_json::from_str(FIXTURE).expect("fixture is valid JSON")
}

/// The contract revision the fixture came from, so a mismatch names what it compared against.
fn fixture_commit() -> String {
    fixture()["commit"]
        .as_str()
        .expect("fixture records its commit")
        .chars()
        .take(9)
        .collect()
}

/// Canonical `Name(type,…)` for every event the contracts compile to.
fn compiled_signatures() -> BTreeSet<String> {
    fixture()["events"]
        .as_array()
        .expect("fixture has an events array")
        .iter()
        .map(|e| {
            let types: Vec<&str> = e["inputs"]
                .as_array()
                .expect("inputs is an array")
                .iter()
                .map(|i| i["type"].as_str().expect("input has a type"))
                .collect();
            format!(
                "{}({})",
                e["name"].as_str().expect("event has a name"),
                types.join(",")
            )
        })
        .collect()
}

#[test]
fn every_filtered_signature_is_one_the_contracts_emit() {
    let (compiled, at) = (compiled_signatures(), fixture_commit());
    for (_, signature) in REGISTRY_TOPICS {
        assert!(
            compiled.contains(*signature),
            "{signature} is not emitted by the contracts at {at} — this filter matches nothing.\n\
             Emitted: {compiled:#?}"
        );
    }
    assert!(
        compiled.contains(ANCHORED_SIGNATURE),
        "{ANCHORED_SIGNATURE} is not in the precompile ABI at {at}"
    );
}

#[test]
fn every_domain_event_is_filtered() {
    // Inherited solady/UUPS events, plus the precompile's own. Named rather than silently
    // skipped, so a new contract event fails until someone picks a side for it.
    const NOT_INDEXED: &[&str] = &[
        "Anchored(address,bytes32,bytes32,bytes)", // the precompile's own, filtered separately
        "Initialized(uint64)",
        "OwnershipHandoverCanceled(address)",
        "OwnershipHandoverRequested(address)",
        "OwnershipTransferred(address,address)",
        "Upgraded(address)",
    ];

    let filtered: BTreeSet<&str> = REGISTRY_TOPICS.iter().map(|(_, sig)| *sig).collect();
    for signature in compiled_signatures() {
        if NOT_INDEXED.contains(&signature.as_str()) {
            continue;
        }
        assert!(
            filtered.contains(signature.as_str()),
            "{signature} is emitted at {} but neither filtered nor listed as deliberately skipped",
            fixture_commit()
        );
    }
}

#[test]
fn vendored_signatures_hash_to_the_topics_in_use() {
    // Closes the loop: the signatures come from the contract, these are the hashes sent to
    // `eth_getLogs`.
    for (topic, signature) in REGISTRY_TOPICS {
        assert_eq!(&keccak_hex(signature.as_bytes()), topic, "{signature}");
    }
    assert_eq!(keccak_hex(ANCHORED_SIGNATURE.as_bytes()), ANCHORED_TOPIC);
}
