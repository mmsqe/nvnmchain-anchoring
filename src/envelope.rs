//! Reading `AnchoringRegistry` payloads out of anchored metadata.

use crate::eth::{checksum_address, hex0x, keccak_hex, normalize_hex, word_to_u128, word_to_usize};

// `AnchoringRegistry` anchors in two formats — a bare `abi.encode`, and a newer
// one leading with a `bytes32` kind — and a registry is an upgradeable proxy, so
// one namespace emits both across an upgrade.
//
// Either way the ids in the payload have to reproduce the key it was anchored
// under, `keccak256(abi.encode(kind, ids…))`. For untagged payloads that is the
// only thing identifying the shape; for tagged ones it still catches a schema
// that has drifted from the contract.

#[derive(Debug, Clone, Copy, PartialEq)]
enum Ty {
    Uint,
    Address,
    Bytes32,
    Bool,
    Str,
}

struct Schema {
    kind: &'static str,
    fields: &'static [(&'static str, Ty)],
    /// Field positions of the ids that make up the anchored key, in the order
    /// `AnchoringRegistry` hashes them.
    key_ids: &'static [usize],
    /// Whether the shape exists in the untagged format. `acl` arrived with the
    /// tag, so there is no untagged reading of it to attempt.
    untagged: bool,
}

/// Each schema is one `abi.encode` call in `AnchoringRegistry.sol`, paired with
/// the `*Key()` helper naming the slot it is anchored at.
const SCHEMAS: &[Schema] = &[
    Schema {
        // addRegistry → registryKey(id)
        kind: "registry",
        fields: &[
            ("id", Ty::Uint),
            ("name", Ty::Str),
            ("description", Ty::Str),
            ("metadata", Ty::Str),
            ("creator", Ty::Address),
            ("timestamp", Ty::Uint),
        ],
        key_ids: &[0],
        untagged: true,
    },
    Schema {
        // addRecord → recordKey(registry_id, record_id)
        kind: "record",
        fields: &[
            ("registry_id", Ty::Uint),
            ("record_id", Ty::Uint),
            ("index", Ty::Uint),
            ("uri", Ty::Str),
            ("checksum", Ty::Str),
            ("checksum_algo", Ty::Str),
            ("metadata", Ty::Str),
            ("timestamp", Ty::Uint),
        ],
        key_ids: &[0, 1],
        untagged: true,
    },
    Schema {
        // updateRecordStatus → statusKey(registry_id, record_id, index)
        kind: "status",
        fields: &[
            ("registry_id", Ty::Uint),
            ("record_id", Ty::Uint),
            ("index", Ty::Uint),
            ("status", Ty::Str),
            ("seq", Ty::Uint),
        ],
        key_ids: &[0, 1, 2],
        untagged: true,
    },
    Schema {
        // grantRole / revokeRole → aclKey(registry_id, checksum_hash, account, role)
        kind: "acl",
        fields: &[
            ("registry_id", Ty::Uint),
            ("checksum_hash", Ty::Bytes32),
            ("account", Ty::Address),
            ("role", Ty::Bytes32),
            ("granted", Ty::Bool),
        ],
        key_ids: &[0, 1, 2, 3],
        untagged: false,
    },
];

#[derive(Debug, Clone)]
pub struct Envelope {
    /// `registry`, `record`, `status` or `acl`.
    pub kind: &'static str,
    /// Whether the payload led with its kind, or had to be identified by key.
    pub tagged: bool,
    pub fields: Vec<(&'static str, String)>,
}

impl Envelope {
    pub fn field(&self, name: &str) -> &str {
        self.fields
            .iter()
            .find(|(n, _)| *n == name)
            .map_or("", |(_, v)| v.as_str())
    }

    /// One-line description, for listings.
    pub fn summary(&self) -> String {
        match self.kind {
            "registry" => format!("Registry #{} — {}", self.field("id"), self.field("name")),
            "record" => format!(
                "Record #{} v{} — {}",
                self.field("record_id"),
                self.field("index"),
                self.field("checksum")
            ),
            "status" => format!(
                "Status of record #{} v{} — {}",
                self.field("record_id"),
                self.field("index"),
                self.field("status")
            ),
            "acl" => format!(
                "Role {} {} {}",
                self.field("role"),
                if self.field("granted") == "true" {
                    "granted to"
                } else {
                    "revoked from"
                },
                self.field("account")
            ),
            other => other.to_string(),
        }
    }
}

/// How a payload reads, in descending order of confidence.
#[derive(Debug, Clone)]
pub enum Payload {
    /// An `AnchoringRegistry` envelope, identified by the key it is under.
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

/// Decode the `AnchoringRegistry` envelope anchored at `key`, or `None` when
/// `metadata` is not one.
pub fn decode_envelope(key: &str, metadata: &[u8]) -> Option<Envelope> {
    let key = normalize_hex(key);
    for schema in SCHEMAS {
        // Tagged first: the leading kind rejects a wrong shape on one word,
        // where the untagged reading has to decode the whole payload to fail.
        for tagged in [true, false] {
            if !tagged && !schema.untagged {
                continue;
            }
            if let Some(envelope) = decode_as(schema, metadata, tagged, &key) {
                return Some(envelope);
            }
        }
    }
    None
}

/// One attempt, kept only if the ids reproduce the anchored key.
fn decode_as(
    schema: &'static Schema,
    metadata: &[u8],
    tagged: bool,
    key: &str,
) -> Option<Envelope> {
    let mut layout: Vec<(&'static str, Ty)> = Vec::with_capacity(schema.fields.len() + 1);
    if tagged {
        layout.push(("kind", Ty::Bytes32));
    }
    layout.extend_from_slice(schema.fields);

    let (values, words) = decode_strict(&layout, metadata)?;
    let shift = usize::from(tagged);
    if tagged && bytes32_label(&words[0]) != schema.kind {
        return None;
    }
    let ids: Vec<[u8; 32]> = schema.key_ids.iter().map(|i| words[*i + shift]).collect();
    if derive_key(schema.kind, &ids) != key {
        return None;
    }
    Some(Envelope {
        kind: schema.kind,
        tagged,
        fields: schema
            .fields
            .iter()
            .zip(values.into_iter().skip(shift))
            .map(|((name, _), value)| (*name, value))
            .collect(),
    })
}

/// A right-padded `bytes32` string ("admin") as text, anything else as hex —
/// how Solidity writes kind tags and role names.
fn bytes32_label(word: &[u8; 32]) -> String {
    let text = word.split(|b| *b == 0).next().unwrap_or(&[]);
    let padded = word[text.len()..].iter().all(|b| *b == 0);
    match std::str::from_utf8(text) {
        Ok(text) if padded && !text.is_empty() && text.chars().all(|c| c.is_ascii_graphic()) => {
            text.to_string()
        }
        _ => hex0x(word),
    }
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
            Ty::Bool => match word[31] {
                // Solidity writes a bool as a full zero/one word; anything else
                // is not the field we think it is.
                b @ (0 | 1) if word[..31].iter().all(|x| *x == 0) => {
                    values.push((b == 1).to_string())
                }
                _ => return None,
            },
            Ty::Address => {
                // The 12 high bytes of an ABI-encoded address are zero.
                if word[..12].iter().any(|b| *b != 0) {
                    return None;
                }
                values.push(checksum_address(&hex::encode(&word[12..])));
            }
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
