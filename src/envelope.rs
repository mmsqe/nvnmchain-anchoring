//! Reading a `Registry` payload out of a leaf's metadata.

use crate::eth::{hex0x, normalize_hex, word_to_address, word_to_u128, word_to_usize};

// Every envelope leads with a `bytes32` kind, so one word identifies the shape, and
// the layout is then read strictly: tails packed in field order with nothing left
// over. That keeps out a payload that merely resembles an envelope; a crafted one is
// kept out by `Registry.appendLeaf`, which refuses a bare leaf leading with `record`
// or `status`.
//
// No registry id in any envelope. The registry is the namespace the leaf was
// appended under, so a payload only means something with its namespace beside it —
// the same envelope under two registries is two different records.

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
}

/// Each schema is one `abi.encode` call in `Registry.sol`.
///
/// Two kinds. `registry` went with the wrapper: name, description and metadata
/// ride in the factory's deployment event, descriptive and set once, so there is
/// nothing to prove and no envelope to decode. `acl` went with the anchoring of
/// role changes: membership is the registry's own state and its history is its
/// own events, which carry every field. The MMR itself has no envelope either —
/// the precompile's events carry its count and peaks.
const SCHEMAS: &[Schema] = &[
    Schema {
        // addRecord
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
    },
    Schema {
        // updateRecordStatus
        kind: "status",
        fields: &[
            ("checksum_hash", Ty::Hash),
            ("index", Ty::Uint),
            ("status", Ty::Str),
            ("author", Ty::Address),
            ("seq", Ty::Uint),
        ],
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

    /// The `checksum_hash` both kinds lead with, lowercased.
    pub fn checksum_hash(&self) -> String {
        normalize_hex(self.field("checksum_hash"))
    }
}

/// How a payload reads, in descending order of confidence.
#[derive(Debug, Clone)]
pub enum Payload {
    /// A `Registry` envelope.
    Envelope(Envelope),
    /// Self-describing text — what a plain EOA's leaves carry in practice.
    Json(serde_json::Value),
    /// Printable text that is not JSON.
    Text(String),
    /// Anything else. The bytes are all anyone can say about it.
    Opaque,
}

/// Read a payload, most meaningful reading first. Anything may be a leaf, so
/// `Opaque` is a normal answer.
pub fn read_payload(metadata: &[u8]) -> Payload {
    if let Some(envelope) = decode_envelope(metadata) {
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

/// `abi.encode(uint256, string)` — what `RecordStatusUpdated` puts in its data
/// section after its indexed hash.
pub fn decode_uint_string(data: &[u8]) -> Option<(u64, String)> {
    let (values, _) = decode_strict(&[("n", Ty::Uint), ("s", Ty::Str)], data)?;
    Some((values[0].parse().ok()?, values[1].clone()))
}

/// Decode the `Registry` envelope in `metadata`, or `None` when it is not one.
pub fn decode_envelope(metadata: &[u8]) -> Option<Envelope> {
    SCHEMAS
        .iter()
        .find_map(|schema| decode_as(schema, metadata))
}

/// One attempt, kept only if the leading kind is this schema's and the layout is exact.
fn decode_as(schema: &'static Schema, metadata: &[u8]) -> Option<Envelope> {
    let mut layout: Vec<(&'static str, Ty)> = Vec::with_capacity(schema.fields.len() + 1);
    layout.push(("kind", Ty::Bytes32));
    layout.extend_from_slice(schema.fields);

    let (values, words) = decode_strict(&layout, metadata)?;
    // The leading kind rejects a wrong shape on one word, before anything else is read.
    if bytes32_label(&words[0]) != schema.kind {
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

/// Whether the commitment is `keccak256(metadata)` — what the registry commits
/// to, making every record leaf self-verifying.
pub fn is_self_verifying(commitment: &str, metadata: &[u8]) -> bool {
    crate::eth::keccak_hex(metadata) == normalize_hex(commitment)
}
