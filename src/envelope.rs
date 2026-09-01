//! Reading a `Registry` payload out of anchored metadata.

use crate::eth::{
    hex0x, keccak_hex, normalize_hex, strip_hex, word_to_address, word_to_u128, word_to_usize,
};

// Every envelope leads with a `bytes32` kind, so one word identifies the shape.
// The ids in the payload must then reproduce the key it was anchored under,
// `keccak256(abi.encode(kind, ids…))` — which catches a schema that has drifted
// from the contract, and binds the payload to the key rather than letting one
// from elsewhere read as an envelope.
//
// There was an untagged format once, identified by that key derivation alone.
// It never shipped: one contract per registry is a fresh deployment, so no
// build predating the kind tags can ever have emitted one.
//
// No registryId in any key. The registry is the address the envelope was
// anchored under, so a payload only means something with its namespace beside
// it — the same commitment under two registries is two different records.

#[derive(Debug, Clone, Copy, PartialEq)]
enum Ty {
    Uint,
    /// A right-padded label ("record", "admin") if it reads as one, hex otherwise.
    Bytes32,
    /// Always hex: a keccak hash is never a label, and does not fit the `u128`
    /// [`Ty::Uint`] parses through -- reading one that way fails the decode.
    Hash,
    /// Checksummed, so it compares equal to every other address this app produces.
    Address,
    Str,
}

struct Schema {
    kind: &'static str,
    fields: &'static [(&'static str, Ty)],
    /// Field positions of the ids that make up the anchored key, in the order
    /// the contract hashes them.
    key_ids: &'static [usize],
}

/// Each schema is one `abi.encode` call in `Registry.sol`, paired with the
/// `*Key()` helper naming the slot it is anchored at.
///
/// Two kinds, not four. `registry` went with the wrapper: name, description and
/// metadata ride in the factory's deployment event now, descriptive and set
/// once, so there is nothing to prove and no envelope to decode. `acl` went with
/// the anchoring of role changes: membership is the registry's own state and its
/// history is its own events, which carry every field.
const SCHEMAS: &[Schema] = &[
    Schema {
        // addRecord → recordKey(checksum_hash)
        kind: "record",
        fields: &[
            ("checksum_hash", Ty::Hash),
            ("index", Ty::Uint),
            ("uri", Ty::Str),
            ("checksum", Ty::Str),
            ("checksum_algo", Ty::Str),
            ("metadata", Ty::Str),
            // The contract's `RecordCategory` enum as a uint8; its names are only in the source.
            ("category", Ty::Uint),
            ("data_pointer", Ty::Str),
            ("author", Ty::Address),
            ("timestamp", Ty::Uint),
        ],
        key_ids: &[0],
    },
    Schema {
        // updateRecordStatus → statusKey(checksum_hash, index)
        kind: "status",
        fields: &[
            ("checksum_hash", Ty::Hash),
            ("index", Ty::Uint),
            ("status", Ty::Str),
            ("author", Ty::Address),
            ("seq", Ty::Uint),
        ],
        key_ids: &[0, 1],
    },
];

#[derive(Debug, Clone)]
pub struct Envelope {
    /// `record` or `status`.
    pub kind: &'static str,
    pub fields: Vec<(&'static str, String)>,
}

impl Envelope {
    pub fn field(&self, name: &str) -> &str {
        self.fields
            .iter()
            .find(|(n, _)| *n == name)
            .map_or("", |(_, v)| v.as_str())
    }
}

/// How a payload reads, in descending order of confidence.
#[derive(Debug, Clone)]
pub enum Payload {
    /// A `Registry` envelope, identified by the key it is under.
    Envelope(Envelope),
    /// Self-describing text — what plain EOA anchors carry in practice.
    Json(serde_json::Value),
    /// Printable text that is not JSON.
    Text(String),
    /// Anything else. The bytes are all anyone can say about it.
    Opaque,
}

/// Read a payload, most meaningful reading first. Anything may be anchored, so
/// `Opaque` is a normal answer.
pub fn read_payload(key: &str, metadata: &[u8]) -> Payload {
    if let Some(envelope) = decode_envelope(key, metadata) {
        return Payload::Envelope(envelope);
    }
    let Ok(text) = std::str::from_utf8(metadata) else {
        return Payload::Opaque;
    };
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
        if value.is_object() || value.is_array() {
            return Payload::Json(value);
        }
    }
    if !text.is_empty() && text.chars().all(|c| !c.is_control() || c == '\n') {
        return Payload::Text(text.to_string());
    }
    Payload::Opaque
}

/// The strings an all-`string` ABI payload carries, in order -- what
/// `RegistryDeployed` puts in its data section.
///
/// Goes through the same strict decode an envelope does: offsets must be the
/// canonical ones and nothing may be left over, so a payload of another shape
/// is refused rather than read as text from the wrong place.
pub fn decode_strings(names: &[&'static str], data: &[u8]) -> Option<Vec<(&'static str, String)>> {
    let layout: Vec<(&str, Ty)> = names.iter().map(|name| (*name, Ty::Str)).collect();
    let (values, _) = decode_strict(&layout, data)?;
    Some(names.iter().copied().zip(values).collect())
}

/// Decode the `Registry` envelope anchored at `key`, or `None` when
/// `metadata` is not one.
pub fn decode_envelope(key: &str, metadata: &[u8]) -> Option<Envelope> {
    let key = normalize_hex(key);
    SCHEMAS
        .iter()
        .find_map(|schema| decode_as(schema, metadata, &key))
}

/// One attempt, kept only if the ids reproduce the anchored key.
fn decode_as(schema: &'static Schema, metadata: &[u8], key: &str) -> Option<Envelope> {
    let mut layout: Vec<(&'static str, Ty)> = Vec::with_capacity(schema.fields.len() + 1);
    layout.push(("kind", Ty::Bytes32));
    layout.extend_from_slice(schema.fields);

    let (values, words) = decode_strict(&layout, metadata)?;
    // The leading kind rejects a wrong shape on one word, before the key is derived.
    if bytes32_label(&words[0]) != schema.kind {
        return None;
    }
    let ids: Vec<[u8; 32]> = schema.key_ids.iter().map(|i| words[*i + 1]).collect();
    if derive_key(schema.kind, &ids) != key {
        return None;
    }
    Some(Envelope {
        kind: schema.kind,
        fields: schema
            .fields
            .iter()
            .zip(values.into_iter().skip(1))
            .map(|((name, _), value)| (*name, value))
            .collect(),
    })
}

/// A right-padded `bytes32` string ("admin") as text, anything else as hex —
/// how Solidity writes kind tags and role names.
pub fn bytes32_label(word: &[u8; 32]) -> String {
    let text = word.split(|b| *b == 0).next().unwrap_or(&[]);
    let padded = word[text.len()..].iter().all(|b| *b == 0);
    match std::str::from_utf8(text) {
        Ok(text) if padded && !text.is_empty() && text.chars().all(|c| c.is_ascii_graphic()) => {
            text.to_string()
        }
        _ => hex0x(word),
    }
}

/// The key a record stream is anchored under, from its checksum hash —
/// `Registry.recordKey`, derived rather than read from the contract.
///
/// Deriving it is what makes a lookup *by checksum* possible at all: the key is
/// the only thing the index is filtered on, and it comes from the checksum and
/// nothing else. Which is also why the same checksum in two registries is the
/// same key under two namespaces.
pub fn record_key(checksum_hash: &str) -> Option<String> {
    Some(derive_key("record", &[word(checksum_hash)?]))
}

/// The key one version's status is anchored under — `Registry.statusKey`.
pub fn status_key(checksum_hash: &str, index: u64) -> Option<String> {
    Some(derive_key(
        "status",
        &[word(checksum_hash)?, usize_word(index as usize)],
    ))
}

/// A 32-byte hex string as the word the contract hashed.
fn word(hexed: &str) -> Option<[u8; 32]> {
    hex::decode(strip_hex(hexed)).ok()?.try_into().ok()
}

/// `keccak256(abi.encode(kind, ids…))`, over the ids as their raw words so no
/// re-encoding can misrepresent them.
fn derive_key(kind: &str, ids: &[[u8; 32]]) -> String {
    let mut encoded = Vec::with_capacity(32 * (ids.len() + 3));
    // Head: the offset of the dynamic `kind` string, then the static ids.
    encoded.extend_from_slice(&usize_word(32 * (1 + ids.len())));
    for id in ids {
        encoded.extend_from_slice(id);
    }
    // Tail: the string's length and its right-padded bytes (all kinds are short).
    encoded.extend_from_slice(&usize_word(kind.len()));
    let mut padded = [0u8; 32];
    padded[..kind.len()].copy_from_slice(kind.as_bytes());
    encoded.extend_from_slice(&padded);
    keccak_hex(&encoded)
}

/// Decode a fixed field list, accepting only the exact layout `abi.encode`
/// produces: tails packed in field order with nothing left over. That tightness
/// is what keeps a foreign payload from reading as an envelope.
fn decode_strict(fields: &[(&str, Ty)], data: &[u8]) -> Option<(Vec<String>, Vec<[u8; 32]>)> {
    if !data.len().is_multiple_of(32) {
        return None;
    }
    let head_len = fields.len() * 32;
    if data.len() < head_len {
        return None;
    }
    let mut values = Vec::with_capacity(fields.len());
    let mut words = Vec::with_capacity(fields.len());
    // Where the next dynamic value has to start; tails follow the head in field
    // order, so this is the only offset a canonical encoding can name.
    let mut tail = head_len;
    for (i, (_, ty)) in fields.iter().enumerate() {
        let word: [u8; 32] = data[i * 32..(i + 1) * 32].try_into().ok()?;
        words.push(word);
        match ty {
            Ty::Uint => values.push(word_to_u128(&word)?.to_string()),
            Ty::Bytes32 => values.push(bytes32_label(&word)),
            Ty::Hash => values.push(hex0x(&word)),
            Ty::Address => values.push(word_to_address(&word)?),
            Ty::Str => {
                if word_to_usize(&word)? != tail {
                    return None;
                }
                let len = word_to_usize(data.get(tail..tail + 32)?)?;
                let start = tail + 32;
                let end = start.checked_add(len)?;
                if end > data.len() {
                    return None;
                }
                values.push(String::from_utf8_lossy(&data[start..end]).into_owned());
                tail = start.checked_add(len.next_multiple_of(32))?;
            }
        }
    }
    // Slack after the last tail means these are not the fields that were encoded.
    if tail != data.len() {
        return None;
    }
    Some((values, words))
}

fn usize_word(value: usize) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&(value as u64).to_be_bytes());
    word
}

/// Whether the commitment is `keccak256(metadata)` — what `anchorAndHash`
/// writes, making the logged payload self-verifying.
pub fn is_self_verifying(commitment: &str, metadata: &[u8]) -> bool {
    keccak_hex(metadata) == normalize_hex(commitment)
}
