//! Envelope payloads dumped from a forge run against the shipped `Registry`, so the
//! decoder is checked against what the contract emits rather than against a re-encoding
//! of the test author's guess. They were appended by registry
//! `0xffD4505B3452Dc22f8473616d50503bA9E1710Ac` from [`AUTHOR`] — the namespace is not needed
//! to decode one, but it is what a payload means something *with*, so regenerating them means
//! regenerating from there. The layout is `abi.encode` in `Registry.sol`, unchanged by the
//! move from heads to leaves.
#![allow(dead_code)]

/// The account every vector was written by, as the decoder renders it: checksummed.
pub const AUTHOR: &str = "0x0000000000000000000000000000000000C0FFEE";

/// addRecord("ipfs://cid", "0xabc", "sha256", "{}", Unspecified, ""): the leaf's commitment is
/// `keccak256(envelope)`, and the envelope is its metadata.
pub const RECORD_COMMITMENT: &str =
    "0xa444eb2eef3f25d43826cd15dcef4445fb870b9de739da0e7ae38c0a8f6c647d";
pub const RECORD_METADATA: &str = "0x\
7265636f72640000000000000000000000000000000000000000000000000000\
851bb152e67e6c958ab7da1431fcaed09ce0efc598885f69a750b3b4b81fc1dc\
0000000000000000000000000000000000000000000000000000000000000001\
0000000000000000000000000000000000000000000000000000000000000160\
00000000000000000000000000000000000000000000000000000000000001a0\
00000000000000000000000000000000000000000000000000000000000001e0\
0000000000000000000000000000000000000000000000000000000000000220\
0000000000000000000000000000000000000000000000000000000000000000\
0000000000000000000000000000000000000000000000000000000000000260\
0000000000000000000000000000000000000000000000000000000000c0ffee\
0000000000000000000000000000000000000000000000000000000000000001\
000000000000000000000000000000000000000000000000000000000000000a\
697066733a2f2f63696400000000000000000000000000000000000000000000\
0000000000000000000000000000000000000000000000000000000000000005\
3078616263000000000000000000000000000000000000000000000000000000\
0000000000000000000000000000000000000000000000000000000000000006\
7368613235360000000000000000000000000000000000000000000000000000\
0000000000000000000000000000000000000000000000000000000000000002\
7b7d000000000000000000000000000000000000000000000000000000000000\
0000000000000000000000000000000000000000000000000000000000000000";

/// updateRecordStatus("0xabc", 1, "approved")
pub const STATUS_COMMITMENT: &str =
    "0x12496fef0a79f105aac77ccad9e63e6989a94a066abe0c85361f4014513fe203";
pub const STATUS_METADATA: &str = "0x\
7374617475730000000000000000000000000000000000000000000000000000\
851bb152e67e6c958ab7da1431fcaed09ce0efc598885f69a750b3b4b81fc1dc\
0000000000000000000000000000000000000000000000000000000000000001\
00000000000000000000000000000000000000000000000000000000000000c0\
0000000000000000000000000000000000000000000000000000000000c0ffee\
0000000000000000000000000000000000000000000000000000000000000001\
0000000000000000000000000000000000000000000000000000000000000008\
617070726f766564000000000000000000000000000000000000000000000000";

/// The checksum hash both fixtures carry: `keccak256("0xabc")`.
pub const FIXTURE_HASH: &str = "0x851bb152e67e6c958ab7da1431fcaed09ce0efc598885f69a750b3b4b81fc1dc";

pub fn bytes(hexed: &str) -> Vec<u8> {
    hex::decode(hexed.strip_prefix("0x").unwrap_or(hexed)).expect("hex")
}

/// `abi.encode(bytes32 commitment, bytes32[] peaks, bytes metadata)` — a `LeafAppended` row's
/// `data` column, as tidx hands it back. Built the way the ABI says rather than pasted, so a
/// test that fails names a decoder bug and not a typo.
pub fn leaf_data(commitment: &str, peaks: &[&str], metadata: &[u8]) -> String {
    let mut out = String::from("0x");
    out.push_str(&format!("{:0>64}", commitment.trim_start_matches("0x")));
    let peaks_at = 3 * 32;
    let metadata_at = peaks_at + 32 + peaks.len() * 32;
    out.push_str(&format!("{peaks_at:064x}"));
    out.push_str(&format!("{metadata_at:064x}"));
    out.push_str(&format!("{:064x}", peaks.len()));
    for peak in peaks {
        out.push_str(&format!("{:0>64}", peak.trim_start_matches("0x")));
    }
    out.push_str(&format!("{:064x}", metadata.len()));
    out.push_str(&format!(
        "{:0<width$}",
        hex::encode(metadata),
        width = metadata.len().div_ceil(32) * 64
    ));
    out
}

/// `abi.encode(uint256 count, (bytes32 root, uint8 height)[] chunks, bytes32[] peaks,
/// bytes metadata)` — a `LeavesAppended` row's `data`. A chunk is a static pair, so the
/// array is its length and then two words per chunk.
pub fn leaves_data(count: u64, chunks: &[(&str, u8)], peaks: &[&str], metadata: &[u8]) -> String {
    let words = |items: &[String]| {
        let mut s = String::new();
        for item in items {
            s.push_str(&format!("{:0>64}", item.trim_start_matches("0x")));
        }
        s
    };
    let pairs: Vec<String> = chunks
        .iter()
        .flat_map(|(r, h)| [r.to_string(), format!("{h:x}")])
        .collect();
    let peaks: Vec<String> = peaks.iter().map(|p| p.to_string()).collect();
    let chunks = format!("{:064x}{}", chunks.len(), words(&pairs));
    let peaks = format!("{:064x}{}", peaks.len(), words(&peaks));
    let head = 4 * 32;
    let chunks_at = head;
    let peaks_at = chunks_at + chunks.len() / 2;
    let metadata_at = peaks_at + peaks.len() / 2;
    let mut out = format!("0x{count:064x}{chunks_at:064x}{peaks_at:064x}{metadata_at:064x}");
    out.push_str(&chunks);
    out.push_str(&peaks);
    out.push_str(&format!("{:064x}", metadata.len()));
    out.push_str(&format!(
        "{:0<width$}",
        hex::encode(metadata),
        width = metadata.len().div_ceil(32) * 64
    ));
    out
}

/// A 32-byte topic holding `word`, left-padded.
pub fn topic(word: &str) -> String {
    format!("0x{:0>64}", word.trim_start_matches("0x"))
}
