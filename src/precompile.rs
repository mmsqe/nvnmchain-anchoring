//! The anchoring precompile: what it is, and how to read it directly.
//!
//! A caller-partitioned commitment log enshrined at T10. It keeps one word per
//! `(namespace, key)`; history and payloads live in the `Anchored` log.

use crate::eth::{hex0x, keccak_hex, strip_hex, word_to_usize};

/// Fixed at genesis (`IAnchoring.sol`).
pub const ADDRESS: &str = "0x0000000000000000000000000000000000000A00";

pub const ANCHORED_SIGNATURE: &str = "Anchored(address,bytes32,bytes32,bytes)";
/// `keccak256(ANCHORED_SIGNATURE)`, asserted in the tests so it cannot drift.
pub const ANCHORED_TOPIC: &str =
    "0x778db4d46fc7a84c4e5105dcb250cb47092b78648868d3efaf18e1205b25801d";

/// `latest(address,bytes32)`.
pub const LATEST_SELECTOR: &str = "0x68205bc3";

/// `keccak256(0x01 ‖ pad32(namespace) ‖ key)` — where the head for a pair is
/// stored. The node's suite pins this as reproducible off-chain, which is what
/// lets the audit read chain state with one `eth_getStorageAt`.
pub fn head_slot(namespace: &str, key: &str) -> Option<String> {
    let ns = hex::decode(strip_hex(namespace)).ok()?;
    let key = hex::decode(strip_hex(key)).ok()?;
    if ns.len() != 20 || key.len() != 32 {
        return None;
    }
    let mut preimage = Vec::with_capacity(1 + 32 + 32);
    preimage.push(0x01);
    preimage.extend_from_slice(&[0u8; 12]);
    preimage.extend_from_slice(&ns);
    preimage.extend_from_slice(&key);
    Some(keccak_hex(&preimage))
}

/// The `Anchored` payload: `abi.encode(bytes32 commitment, bytes metadata)`.
/// Hand-read rather than run through a general decoder: one fixed shape, and a
/// strict reading is what keeps a malformed log out of the index.
pub fn decode_anchored_data(data: &[u8]) -> Option<(String, Vec<u8>)> {
    if data.len() < 96 || !data.len().is_multiple_of(32) {
        return None;
    }
    let commitment = hex0x(&data[..32]);
    // The tail of a two-field encoding always starts immediately after the head.
    if word_to_usize(&data[32..64])? != 64 {
        return None;
    }
    let len = word_to_usize(&data[64..96])?;
    let end = 96usize.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some((commitment, data[96..end].to_vec()))
}
