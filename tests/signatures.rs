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
    let (compiled, at) = (compiled_signatures(), fixture_commit());
    // Inherited solady/UUPS events, plus the precompile's own. Named rather than silently
    // skipped, so a new contract event fails until someone picks a side for it.
    const NOT_INDEXED: &[&str] = &[
        "Anchored(address,bytes32,bytes32,bytes)", // the precompile's own, filtered separately
        "OwnershipHandoverCanceled(address)",
        "OwnershipHandoverRequested(address)",
        "OwnershipTransferred(address,address)",
    ];

    // A skip that names nothing stops skipping anything, and would wave through
    // an event of the same name if one came back. The three that went with the
    // proxies were caught this way.
    for skipped in NOT_INDEXED {
        assert!(
            compiled.contains(*skipped),
            "{skipped} is skipped but no contract at {at} emits it"
        );
    }

    let filtered: BTreeSet<&str> = REGISTRY_TOPICS.iter().map(|(_, sig)| *sig).collect();
    for signature in &compiled {
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

/// A named signature's arguments, e.g. `uint256 indexed id`.
fn arguments(named: &str) -> impl Iterator<Item = &str> {
    named
        .split_once('(')
        .expect("a signature has arguments")
        .1
        .trim_end_matches(')')
        .split(',')
        .map(str::trim)
}

/// `Name(uint256 indexed a, bytes32 b)` → `Name(uint256,bytes32)`, the way tidx
/// canonicalizes a `?signature=` before hashing it to a topic0.
fn canonicalize(named: &str) -> String {
    let name = named.split_once('(').expect("a signature has a name").0;
    let types: Vec<&str> = arguments(named)
        .map(|arg| {
            arg.split_whitespace()
                .next()
                .expect("an argument has a type")
        })
        .collect();
    format!("{name}({})", types.join(","))
}

#[test]
fn the_roles_query_names_the_events_the_topics_pin() {
    // Two spellings of one event: these go to tidx, REGISTRY_TOPICS is what a
    // topic0 hashes from. Drifted apart, the query builds its table off some
    // other topic0 — no rows rather than an error.
    let canonical: BTreeSet<&str> = REGISTRY_TOPICS.iter().map(|(_, sig)| *sig).collect();
    for named in ROLE_EVENTS {
        let form = canonicalize(named);
        assert!(
            canonical.contains(form.as_str()),
            "{named} canonicalizes to {form}, which is not a signature this crate pins"
        );
    }

    // And that no seed crept back: a registry announces its creator's admin as an
    // ordinary RoleGranted, so the grant/revoke pair answers in full.
    assert_eq!(ROLE_EVENTS.len(), 2, "{ROLE_EVENTS:?}");
}

#[test]
fn the_roles_query_reads_events_whose_scope_is_topic1() {
    // `roles_sql` partitions by checksumHash, which it reads as a decoded column but which
    // an index also seeks on as topic1. Reordered, a scoped answer would silently select on
    // an account instead.
    for named in ROLE_EVENTS {
        let first = arguments(named)
            .find(|arg| arg.contains(" indexed "))
            .unwrap_or_else(|| panic!("{named} indexes nothing, so it has no topic1"));
        assert_eq!(
            first, "bytes32 indexed checksumHash",
            "{named} puts {first:?} in topic1, not the role scope"
        );
    }
}

#[test]
fn vendored_signatures_hash_to_the_topics_in_use() {
    // Closes the loop: the signatures come from the contract, and these hashes are what an
    // indexer filters the log on.
    for (topic, signature) in REGISTRY_TOPICS {
        assert_eq!(&keccak_hex(signature.as_bytes()), topic, "{signature}");
    }
    assert_eq!(keccak_hex(ANCHORED_SIGNATURE.as_bytes()), ANCHORED_TOPIC);
}
