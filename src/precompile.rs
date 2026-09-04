//! The anchoring precompile: what it is, and how to read its log and its state.
//!
//! One Merkle Mountain Range per caller, enshrined at T10. State per namespace is
//! the leaf count and one slot per peak height; payloads live only in the two
//! events, which also carry the peaks, so a proof needs the log and nothing else.

use crate::eth::{hex0x, keccak256, strip_hex, word_to_usize};

/// Fixed at genesis (`IAnchoring.sol`).
pub const ADDRESS: &str = "0x0000000000000000000000000000000000000A00";

pub const LEAF_APPENDED_SIGNATURE: &str =
    "LeafAppended(address,uint256,bytes32,bytes32,bytes32[],bytes)";
/// `keccak256(LEAF_APPENDED_SIGNATURE)`, asserted in the tests so it cannot drift.
pub const LEAF_APPENDED_TOPIC: &str =
    "0x299ee3fc8eecbb10ce273b5329c6e4f095c550dc1bc7e1756bd6303da53cf12a";

pub const LEAVES_APPENDED_SIGNATURE: &str =
    "LeavesAppended(address,uint256,uint256,bytes32[],uint8[],bytes32,bytes32[],bytes)";
pub const LEAVES_APPENDED_TOPIC: &str =
    "0x07d3a61ef7a792265f84d9a96ef8168c654dd0d610d83034971ce6c68c30a378";

/// `(topic0, signature)` for both events, the way [`crate::registry::REGISTRY_TOPICS`]
/// lists the contracts', so `tests/signatures.rs` checks them against the compiled ABI.
pub const PRECOMPILE_TOPICS: &[(&str, &str)] = &[
    (LEAF_APPENDED_TOPIC, LEAF_APPENDED_SIGNATURE),
    (LEAVES_APPENDED_TOPIC, LEAVES_APPENDED_SIGNATURE),
];

/// `root(address)`.
pub const ROOT_SELECTOR: &str = "0x6e5ac882";
/// `state(address)` — `(uint256 count, bytes32[] peaks)`.
pub const STATE_SELECTOR: &str = "0x31e658a5";

/// `keccak256(0x01 ‖ pad32(namespace))` — the slot holding the leaf count. The peak
/// of height `h` sits at `base + 1 + h`. The node's suite pins the layout as
/// reproducible off-chain, which is what lets the audit read the count with one
/// `eth_getStorageAt` beside the `state()` it compares against.
pub fn count_slot(namespace: &str) -> Option<String> {
    let ns = hex::decode(strip_hex(namespace)).ok()?;
    if ns.len() != 20 {
        return None;
    }
    let mut preimage = Vec::with_capacity(33);
    preimage.push(0x01);
    preimage.extend_from_slice(&[0u8; 12]);
    preimage.extend_from_slice(&ns);
    Some(hex0x(&keccak256(&preimage)))
}

/// What a `LeafAppended` row's `data` decodes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafData {
    pub commitment: String,
    pub root: String,
    pub peaks: Vec<String>,
    pub metadata: Vec<u8>,
}

/// What a `LeavesAppended` row's `data` decodes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeavesData {
    pub count: u64,
    pub chunk_roots: Vec<String>,
    pub chunk_heights: Vec<u8>,
    pub root: String,
    pub peaks: Vec<String>,
    pub metadata: Vec<u8>,
}

/// `abi.encode(bytes32 commitment, bytes32 root, bytes32[] peaks, bytes metadata)`.
///
/// Read here rather than by the index that stored the log, because tidx decodes a
/// dynamic argument as the 32-byte head word — the ABI *offset* to the payload, not
/// the payload. So the queries select the raw `data` column and this reads it.
pub fn decode_leaf_appended(data: &[u8]) -> Option<LeafData> {
    let words = Words(data);
    Some(LeafData {
        commitment: hex0x(words.word(0)?),
        root: hex0x(words.word(1)?),
        peaks: words.words_at(words.offset(2)?)?,
        metadata: words.bytes_at(words.offset(3)?)?,
    })
}

/// `abi.encode(uint256 count, bytes32[] chunkRoots, uint8[] chunkHeights, bytes32 root,
/// bytes32[] peaks, bytes metadata)`.
pub fn decode_leaves_appended(data: &[u8]) -> Option<LeavesData> {
    let words = Words(data);
    let heights = words.words_at(words.offset(2)?)?;
    Some(LeavesData {
        count: u64::try_from(word_to_usize(words.word(0)?)?).ok()?,
        chunk_roots: words.words_at(words.offset(1)?)?,
        chunk_heights: heights
            .iter()
            .map(|h| u8::try_from(word_to_usize(&hex::decode(strip_hex(h)).ok()?)?).ok())
            .collect::<Option<_>>()?,
        root: hex0x(words.word(3)?),
        peaks: words.words_at(words.offset(4)?)?,
        metadata: words.bytes_at(words.offset(5)?)?,
    })
}

/// ABI words over a data section. Bounds are checked on every read, so a short
/// or malformed row is `None` rather than a panic.
struct Words<'a>(&'a [u8]);

impl Words<'_> {
    fn word(&self, at: usize) -> Option<&[u8]> {
        self.0.get(at * 32..at * 32 + 32)
    }

    /// The byte offset a head word points at.
    fn offset(&self, at: usize) -> Option<usize> {
        word_to_usize(self.word(at)?)
    }

    fn length_at(&self, offset: usize) -> Option<usize> {
        word_to_usize(self.0.get(offset..offset.checked_add(32)?)?)
    }

    /// A `bytes32[]` at `offset`, each word as hex.
    fn words_at(&self, offset: usize) -> Option<Vec<String>> {
        let len = self.length_at(offset)?;
        let start = offset.checked_add(32)?;
        let end = start.checked_add(len.checked_mul(32)?)?;
        Some(self.0.get(start..end)?.chunks(32).map(hex0x).collect())
    }

    /// A `bytes` at `offset`.
    fn bytes_at(&self, offset: usize) -> Option<Vec<u8>> {
        let len = self.length_at(offset)?;
        let start = offset.checked_add(32)?;
        Some(self.0.get(start..start.checked_add(len)?)?.to_vec())
    }
}
