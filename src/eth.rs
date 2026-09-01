//! Chain-generic primitives: keccak, EIP-55, and reading ABI words.

use sha3::{Digest, Keccak256};

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    hasher.finalize().into()
}

pub fn keccak_hex(input: &[u8]) -> String {
    hex0x(&keccak256(input))
}

/// Bytes as a `0x…` string. The one place that spelling is written.
pub fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// EIP-55 checksummed address from any 40-hex-digit input (with or without 0x).
pub fn checksum_address(addr: &str) -> String {
    let lowered = addr.to_lowercase();
    let lower = strip_hex(&lowered);
    if lower.len() != 40 || !lower.chars().all(|c| c.is_ascii_hexdigit()) {
        return addr.trim().to_string();
    }
    let hash = keccak256(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 }) & 0x0f;
        if c.is_ascii_alphabetic() && nibble >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Lowercase `0x…` form, so hex from the chain and hex we derive compare equal.
pub fn normalize_hex(value: &str) -> String {
    format!("0x{}", strip_hex(value).to_lowercase())
}

pub fn strip_hex(value: &str) -> &str {
    value.trim().strip_prefix("0x").unwrap_or(value.trim())
}

/// A word as an integer. Rejects above 2^128: the fields this decodes are
/// counters, ids and timestamps, and a payload claiming more is not ours.
pub fn word_to_u128(word: &[u8; 32]) -> Option<u128> {
    if word[..16].iter().any(|b| *b != 0) {
        return None;
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&word[16..]);
    Some(u128::from_be_bytes(buf))
}

/// A word as a checksummed address. The upper twelve bytes must be zero: that is
/// what distinguishes an address from a word that merely sits where one is expected.
pub fn word_to_address(word: &[u8; 32]) -> Option<String> {
    if word[..12].iter().any(|b| *b != 0) {
        return None;
    }
    Some(checksum_address(&hex0x(&word[12..])))
}

/// A 20-byte hex address, checksummed, or `None`. Strict on length and on every
/// character: an address reaches SQL through string interpolation, so anything
/// looser would query a different address and report it as empty.
pub fn parse_address(value: &str) -> Option<String> {
    let hexed = strip_hex(value.trim());
    (hexed.len() == 40 && hexed.chars().all(|c| c.is_ascii_hexdigit()))
        .then(|| checksum_address(&normalize_hex(hexed)))
}

/// The address in an indexed topic, right-aligned in its word.
pub fn address_from_topic(topic: &str) -> Option<String> {
    let hexed = strip_hex(topic);
    if hexed.len() != 64 {
        return None;
    }
    Some(checksum_address(&hexed[24..]))
}

/// A word as a length or offset, or `None` when it is too large to be one.
pub fn word_to_usize(word: &[u8]) -> Option<usize> {
    if word.len() != 32 || word[..24].iter().any(|b| *b != 0) {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&word[24..]);
    usize::try_from(u64::from_be_bytes(buf)).ok()
}
