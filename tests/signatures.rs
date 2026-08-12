//! The signatures this crate matches on, checked against the contracts that emit them.
//!
//! Asserting each topic0 is the keccak of the signature beside it catches a mistyped hash, not a
//! signature that drifted from the contract: those two stay consistent with each other while
//! matching nothing on chain, and a signature matching nothing decodes to an empty table.
//!
//! So signatures are compared against the contracts' compiled event ABI, vendored by
//! `make fixtures`. Nothing offline can spot a stale fixture, so rerun it on any event change.

use nvnmchain_anchoring::eth::keccak_hex;
use nvnmchain_anchoring::precompile::{ANCHORED_SIGNATURE, ANCHORED_TOPIC};
use nvnmchain_anchoring::registry::{REGISTRY_TOPICS, ROLE_EVENTS};
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

/// A named signature's arguments, e.g. `uint256 indexed registryId`.
fn arguments(named: &str) -> impl Iterator<Item = &str> {
    named
        .split_once('(')
        .and_then(|(_, rest)| rest.strip_suffix(')'))
        .expect("a signature has parentheses")
        .split(',')
        .map(str::trim)
        .filter(|a| !a.is_empty())
}

/// The canonical form of a named signature: types only, no names, no `indexed`.
fn canonicalize(named: &str) -> String {
    let name = named.split_once('(').expect("a signature has a name").0;
    let types: Vec<&str> = arguments(named)
        .map(|a| a.split_whitespace().next().expect("an argument has a type"))
        .collect();
    format!("{name}({})", types.join(","))
}

#[test]
fn every_named_signature_is_a_canonical_one_said_differently() {
    // Two spellings of the same events: these go to tidx as `?signature=`, the
    // table is what a topic0 hashes from. A drift between them builds the query
    // off some other topic0 and decodes an empty table rather than failing.
    let canonical: BTreeSet<&str> = REGISTRY_TOPICS.iter().map(|(_, sig)| *sig).collect();
    for named in ROLE_EVENTS {
        let form = canonicalize(named);
        assert!(
            canonical.contains(form.as_str()),
            "{named} canonicalizes to {form}, which no filtered topic matches"
        );
    }
}

#[test]
fn the_roles_fold_reads_three_events_to_answer_about_two() {
    // `addRegistry` writes the creator's registry admin into `member` directly
    // and announces it only as a `RegistryAdded`, so the grant/revoke pair alone
    // answers every registry one admin short.
    assert_eq!(ROLE_EVENTS.len(), 3, "{ROLE_EVENTS:?}");
    assert!(ROLE_EVENTS.iter().any(|e| e.starts_with("RegistryAdded(")));
}
