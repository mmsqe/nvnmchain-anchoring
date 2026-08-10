//! `AnchoringRegistry`'s own events — the second log source.
//!
//! Grants and revokes anchor as `acl` envelopes, so the `Anchored` log alone
//! rebuilds "who could write this record". The revision that emitted these
//! events without anchoring them was never deployed, so there is no partial
//! history for this source to complete.
//!
//! It stays because it is a cheaper projection than decoding envelopes, and
//! cross-checks the anchored ACL against what the wrapper said it did.

/// `(topic0, signature)` for every event the wrapper emits. `tests/signatures.rs`
/// checks the hashes against these signatures and the signatures against the
/// contract, so neither can sit here quietly matching nothing.
pub const REGISTRY_TOPICS: &[(&str, &str)] = &[
    (
        "0x3ce4563d134e2bed44925e6752673cb055ab97f4e4e9b1af57b1d10154f6a1a4",
        "RegistryAdded(uint256,string,address)",
    ),
    (
        "0x0a4df583ca8b06d3dca2af4cc0dc36563bd219e42732e15b156c95aee0e07f28",
        "RecordAdded(uint256,uint256,uint256,string)",
    ),
    (
        "0x989fc3f482c08205f3318acb67405437e026aa2b3ded15a815813fff11fa37c6",
        "RecordStatusUpdated(uint256,uint256,uint256,string)",
    ),
    (
        "0xec288ea680fc912ecd077dc712f1347911ee4709aff396bf18fd9d74e2a71eb3",
        "RoleGranted(uint256,bytes32,address,bytes32)",
    ),
    (
        "0x257eb2ed659fb75385b608c05a73049fa8c6b406644b5bd6933950a933b36e39",
        "RoleRevoked(uint256,bytes32,address,bytes32)",
    ),
];
