//! The anchoring precompile: what it is, and how to read its log and its state.
//!
//! One Merkle Mountain Range per caller, enshrined at T10. State per namespace is
//! the leaf count and one slot per peak height; payloads live only in the two
//! events, which also carry the peaks, so a proof needs the log and nothing else.

use crate::eth::{hex0x, keccak256, strip_hex, word_to_usize};

/// Fixed at genesis (`IAnchoring.sol`).
pub const ADDRESS: &str = "0x0000000000000000000000000000000000000A00";

pub const LEAF_APPENDED_SIGNATURE: &str = "LeafAppended(address,uint256,bytes32,bytes32[],bytes)";
/// `keccak256(LEAF_APPENDED_SIGNATURE)`, asserted in the tests so it cannot drift.
pub const LEAF_APPENDED_TOPIC: &str =
    "0x43a24f34ff55c61c25ca8f226ce1e940c9bc4ca4ef98253d9780a3cf29aa2262";

pub const LEAVES_APPENDED_SIGNATURE: &str =
    "LeavesAppended(address,uint256,uint256,(bytes32,uint8)[],bytes32[],bytes)";
pub const LEAVES_APPENDED_TOPIC: &str =
    "0xa643a7916be4114a8d4f887b0606856c1f49b02a0a4374c775283987c1e12c2c";

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

/// What a `LeafAppended` row's `data` decodes to. The event carries the peaks; `root` is
/// what they bag to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafData {
    pub commitment: String,
    pub root: String,
    pub peaks: Vec<String>,
    pub metadata: Vec<u8>,
}

/// What a `LeavesAppended` row's `data` decodes to, `root` bagged from the peaks as above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeavesData {
    pub count: u64,
    pub chunk_roots: Vec<String>,
    pub chunk_heights: Vec<u8>,
    pub root: String,
    pub peaks: Vec<String>,
    pub metadata: Vec<u8>,
}

/// `abi.encode(bytes32 commitment, bytes32[] peaks, bytes metadata)`.
///
/// Read here rather than by the index that stored the log, because tidx decodes a
/// dynamic argument as the 32-byte head word — the ABI *offset* to the payload, not
/// the payload. So the queries select the raw `data` column and this reads it.
pub fn decode_leaf_appended(data: &[u8]) -> Option<LeafData> {
    let words = Words(data);
    let peaks = words.words_at(words.offset(1)?, 1)?;
    Some(LeafData {
        commitment: hex0x(words.word(0)?),
        root: root_of(&peaks)?,
        peaks,
        metadata: words.bytes_at(words.offset(2)?)?,
    })
}

/// `abi.encode(uint256 count, (bytes32 root, uint8 height)[] chunks, bytes32[] peaks,
/// bytes metadata)`. A chunk is a static pair, so the array is its length word and then two
/// words per chunk.
pub fn decode_leaves_appended(data: &[u8]) -> Option<LeavesData> {
    let words = Words(data);
    let (mut chunk_roots, mut chunk_heights) = (Vec::new(), Vec::new());
    for pair in words.words_at(words.offset(1)?, 2)?.chunks(2) {
        chunk_roots.push(pair[0].clone());
        chunk_heights
            .push(u8::try_from(word_to_usize(&hex::decode(strip_hex(&pair[1])).ok()?)?).ok()?);
    }
    let peaks = words.words_at(words.offset(2)?, 1)?;
    Some(LeavesData {
        count: u64::try_from(word_to_usize(words.word(0)?)?).ok()?,
        chunk_roots,
        chunk_heights,
        root: root_of(&peaks)?,
        peaks,
        metadata: words.bytes_at(words.offset(3)?)?,
    })
}

/// What `peaks` bag to: the root an event no longer carries, being one fold away.
fn root_of(peaks: &[String]) -> Option<String> {
    let peaks: Option<Vec<[u8; 32]>> = peaks
        .iter()
        .map(|peak| hex::decode(strip_hex(peak)).ok()?.try_into().ok())
        .collect();
    Some(hex0x(&crate::mmr::bag(&peaks?)))
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

    /// An array at `offset` of elements `width` words wide, each word as hex.
    fn words_at(&self, offset: usize, width: usize) -> Option<Vec<String>> {
        let len = self.length_at(offset)?.checked_mul(width)?;
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
