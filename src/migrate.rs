//! Planning the `x/anchoring` corpus onto the registry contracts.
//!
//! The module's own migration seeded 2,114 registries and 11.9M records by
//! calling its keeper from an upgrade handler: no transactions, no gas, every
//! node writing the same state from a disk-staged export. None of that is
//! available here. A record now exists as a leaf in the precompile's log, logs
//! come from transactions, and genesis has none — so the same corpus 1:1 would
//! be a fresh version-count slot per record at TIP-1000's 250k each, about
//! 1.5e12 gas and 3.6 GB of log, permanently.
//!
//! So the plan splits the corpus. A registry small enough to be worth it is
//! replayed record by record and keeps every per-record lookup; a large one is
//! anchored as a single record whose checksum is a merkle root over its export
//! file, and individual rows are then proven against that root rather than
//! stored. The threshold is the operator's, and the distribution makes it a
//! cheap decision: the median registry holds 17 records, while five hold 2.5M
//! between them.
//!
//! This plans and verifies; it does not sign. The steps come out as ready-to-send
//! calldata in a fixed order, so whatever holds the key sends them — the same
//! reason there is no `tx` half to the command line.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::eth::{hex0x, keccak256, normalize_hex, strip_hex};
use crate::mmr::{bag, hash_leaf, hash_merge};
use crate::registry::{Deployed, NameFilter, Record};
use crate::service::{self, Ctx};
use crate::tidx::Edge;

/// What one call costs, for the summary an operator sizes the run with. Measured
/// against a dev node: a checksum's first version creates its version-count slot
/// and pays TIP-1000 for it, later versions only append.
const GAS_FIRST_VERSION: u64 = 280_000;
const GAS_LATER_VERSION: u64 = 40_000;
/// A fresh slot, TIP-1000's state creation: what the precompile pays once per peak
/// height a namespace reaches, and once for its count.
const GAS_FRESH_SLOT: u64 = 250_000;
/// The rest of one `appendLeaves`: the call, the hashing, the event.
const GAS_LEAVES_CALL: u64 = 80_000;

/// The registries the export names, in the shape the module's own loader read.
/// `id`, `created_at` and `creator` are deliberately absent there and here: the
/// chain assigns all three, and it did so in the module's migration too.
#[derive(Debug, Clone, Deserialize)]
pub struct RegistryImport {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub metadata: String,
}

/// One record line of a tranche file. `timestamp`, `record_id`, `index` and
/// `is_latest` were chain-assigned then and are derived now, so they are not read.
#[derive(Debug, Clone, Deserialize)]
pub struct RecordImport {
    pub registry: String,
    pub uri: String,
    pub checksum: String,
    #[serde(default, rename = "checksumAlgo")]
    pub checksum_algo: String,
    #[serde(default)]
    pub metadata: String,
    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub totals: Totals,
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Totals {
    pub registries: usize,
    pub records: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileEntry {
    pub registry: String,
    pub records: usize,
    pub file: String,
    #[serde(default)]
    pub tranche: u64,
    pub sha256_gz: String,
    pub sha256_uncompressed: String,
}

/// How a registry's corpus reaches the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Every record replayed, so every per-record lookup keeps working.
    Record,
    /// One record holding a merkle root over the export file. Rows are proven
    /// against it; the chain stores the root and nothing else.
    Root,
    /// The file's rows as leaves of the registry's MMR: one word of state, and a
    /// later record appends as one more leaf rather than a new key.
    Leaves,
}

/// One call to send, in the order it must be sent. A `deploy` goes to the
/// factory, everything else to the registry that deploy created.
///
/// `registry` is the legacy name rather than an address: the address exists once
/// the `deploy` step has landed, and `RegistryDeployed` announces it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub step: usize,
    pub kind: Kind,
    pub registry: String,
    pub data: String,
    /// What the step is expected to leave behind, for the reconciliation pass.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    /// What a `status` step sets, so the reconciliation can read it back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Where to send it, once that is knowable: the factory for a deploy, the registry
    /// for anything under one that has landed. A plan cannot carry it — the address
    /// exists once the deploy does — so `reconcile` stamps it on what it hands back,
    /// and a sender resuming needs no log of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

/// Append a step numbered by its place in the plan, and hand it back for the
/// fields only some kinds carry.
fn push<'a>(steps: &'a mut Vec<Step>, kind: Kind, registry: &str, data: String) -> &'a mut Step {
    steps.push(Step {
        step: steps.len() + 1,
        kind,
        registry: registry.to_string(),
        data,
        checksum: None,
        version: None,
        status: None,
        to: None,
    });
    steps.last_mut().expect("just pushed")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Deploy,
    Record,
    Status,
    /// The whole file as leaves of the registry's MMR, in one `appendLeaves`.
    Leaves,
}

/// What one registry's plan came to, for the summary.
#[derive(Debug, Clone, Serialize)]
pub struct Planned {
    pub registry: String,
    pub mode: Mode,
    pub records: usize,
    pub calls: usize,
    pub gas: u64,
}

/// What a rooted registry commits to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Root {
    /// A merkle root over the file's lines, so a single row can be proven
    /// without shipping the rest. Reads and verifies every file it commits to.
    Merkle,
    /// The file's sha256, which the manifest already carries -- so this plans
    /// without the export staged, and verifies nothing. A row is then proven by
    /// producing the whole file.
    Sha256,
    /// The rows as leaves of the registry's MMR (`Registry.appendLeaves`): a row
    /// proves against the root with `log n` siblings, and the registry goes on
    /// appending records as leaves afterwards.
    Mmr,
}

#[derive(Debug, Clone)]
pub struct Options {
    /// Registries at or below this many records are replayed record by record.
    /// Zero roots everything, which is the default: what a replayed record costs
    /// is chain-permanent, so it is the caller who has to ask for it.
    pub threshold: usize,
    /// What the ones above it commit to.
    pub root: Root,
    /// Where the tranche files are staged, as the module's loader also required.
    pub export_dir: PathBuf,
    /// Prefix a root record's `uri` is built from, so the file it commits to can
    /// be fetched: `{base}/{file}`.
    pub uri_base: String,
}

/// The plan, and what it adds up to.
#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub steps: Vec<Step>,
    pub registries: Vec<Planned>,
}

impl Plan {
    pub fn gas(&self) -> u64 {
        self.registries.iter().map(|r| r.gas).sum()
    }
}

/// Plan the whole corpus.
///
/// Refuses before it emits anything: the manifest's own totals must agree with
/// what it lists, and a registry name must be unique. Names are not unique on
/// chain any more, but the export keys its records to one, so two registries
/// sharing a name would silently hand the first one's records to the second --
/// which is the check the module's loader made for the same reason.
pub fn plan(registries: &[RegistryImport], manifest: &Manifest, opts: &Options) -> Result<Plan> {
    if registries.len() != manifest.totals.registries {
        bail!(
            "registries.json has {} registries, manifest.json expects {}",
            registries.len(),
            manifest.totals.registries
        );
    }
    let mut seen = BTreeSet::new();
    for registry in registries {
        if !seen.insert(registry.name.as_str()) {
            bail!(
                "registries.json has duplicate registry name `{}`",
                registry.name
            );
        }
    }
    let files: BTreeMap<&str, &FileEntry> = manifest
        .files
        .iter()
        .map(|f| (f.registry.as_str(), f))
        .collect();

    let mut steps = Vec::new();
    let mut planned = Vec::new();
    let mut records_seen = 0;

    for registry in registries {
        let file = files.get(registry.name.as_str()).with_context(|| {
            format!(
                "manifest.json lists no file for registry `{}`",
                registry.name
            )
        })?;
        records_seen += file.records;

        push(
            &mut steps,
            Kind::Deploy,
            &registry.name,
            deploy_registry_call(&registry.name, &registry.description, &registry.metadata),
        );

        let mode = if file.records <= opts.threshold {
            Mode::Record
        } else if opts.root == Root::Mmr {
            Mode::Leaves
        } else {
            Mode::Root
        };
        let before = steps.len();
        let gas = match mode {
            Mode::Record => replay(&mut steps, registry, file, opts)?,
            Mode::Root => root(&mut steps, registry, file, opts)?,
            Mode::Leaves => leaves(&mut steps, registry, file, opts)?,
        };
        planned.push(Planned {
            registry: registry.name.clone(),
            mode,
            records: file.records,
            calls: steps.len() - before,
            gas,
        });
    }

    if records_seen != manifest.totals.records {
        bail!(
            "manifest.json lists {records_seen} records across its files, its totals say {}",
            manifest.totals.records
        );
    }
    Ok(Plan {
        steps,
        registries: planned,
    })
}

/// Every record of one registry, in file order — which is the order that makes
/// the derived numbering reproduce the module's `record_id`, and the version
/// inside each stream reproduce its `index`.
fn replay(
    steps: &mut Vec<Step>,
    registry: &RegistryImport,
    file: &FileEntry,
    opts: &Options,
) -> Result<u64> {
    let (mut gas, mut versions) = (0, BTreeMap::<String, u64>::new());
    for record in read_records(&opts.export_dir, file)? {
        if record.registry != file.registry {
            bail!(
                "{}: record names registry `{}`, the manifest says `{}`",
                file.file,
                record.registry,
                file.registry
            );
        }
        let version = versions
            .entry(record.checksum.clone())
            .and_modify(|v| *v += 1)
            .or_insert(1);
        gas += if *version == 1 {
            GAS_FIRST_VERSION
        } else {
            GAS_LATER_VERSION
        };

        // The corpus predates categories and pointers, so a replayed record says so
        // in the contract's own terms: `Unspecified`, and no pointer.
        let data = add_record_call(
            &record.uri,
            &record.checksum,
            &record.checksum_algo,
            &record.metadata,
            0,
            "",
        );
        let step = push(steps, Kind::Record, &registry.name, data);
        step.checksum = Some(record.checksum.clone());
        step.version = Some(*version);

        // Status was a field on the record and is a per-version anchor now, so a
        // record that carried one needs a second call against the version it
        // belongs to.
        if !record.status.is_empty() {
            gas += GAS_FIRST_VERSION;
            let data = update_status_call(&record.checksum, *version, &record.status);
            let step = push(steps, Kind::Status, &registry.name, data);
            step.checksum = Some(record.checksum.clone());
            step.version = Some(*version);
            step.status = Some(record.status.clone());
        }
    }
    Ok(gas)
}

/// One record committing to the whole export file.
///
/// The checksum is a merkle root over the file's lines rather than its digest, so
/// a single row can be proven without shipping the rest: leaves are
/// `keccak256(line)` in file order, a node is `keccak256(left ‖ right)`, and an
/// odd node is promoted unchanged.
fn root(
    steps: &mut Vec<Step>,
    registry: &RegistryImport,
    file: &FileEntry,
    opts: &Options,
) -> Result<u64> {
    let (root, algo, proof) = match opts.root {
        Root::Merkle => (
            merkle_root(&read_lines(&opts.export_dir, file)?),
            "keccak256-merkle",
            "a row proves against the root; leaf keccak256(line), node keccak256(left || right), odd promoted",
        ),
        // Straight from the manifest, so nothing was read and nothing verified.
        Root::Sha256 => (
            normalize_hex(&file.sha256_uncompressed),
            "sha256",
            "a row proves by producing the whole file",
        ),
        Root::Mmr => unreachable!("a registry above the threshold plans as leaves under --root=mmr"),
    };
    let metadata = serde_json::json!({
        "legacy": {
            "registry": file.registry,
            "mode": "root",
            "file": file.file,
            "records": file.records,
            "sha256_gz": file.sha256_gz,
            "sha256": file.sha256_uncompressed,
            "proof": proof,
        }
    });

    let data = add_record_call(
        &format!("{}/{}", opts.uri_base.trim_end_matches('/'), file.file),
        &root,
        algo,
        &metadata.to_string(),
        0,
        "",
    );
    let step = push(steps, Kind::Record, &registry.name, data);
    step.checksum = Some(root);
    step.version = Some(1);
    Ok(GAS_FIRST_VERSION)
}

/// The whole file as leaves of the registry's MMR, in one `appendLeaves`.
///
/// A leaf is `keccak256("leaf" ‖ keccak256(line))`; the file is cut, from an empty
/// MMR, into perfect subtrees by the binary decomposition of its length, largest
/// first, which is the aligned cut the precompile insists on. What the step leaves
/// behind is the MMR root, so that is its `checksum`. Its gas is mostly state: the
/// precompile creates one slot per chunk, each a peak, and one for the count.
fn leaves(
    steps: &mut Vec<Step>,
    registry: &RegistryImport,
    file: &FileEntry,
    opts: &Options,
) -> Result<u64> {
    let chunks = mmr_chunks(&read_lines(&opts.export_dir, file)?);
    let root = mmr_root(&chunks);
    let metadata = serde_json::json!({
        "legacy": {
            "registry": file.registry,
            "mode": "leaves",
            "file": file.file,
            "records": file.records,
            "sha256_gz": file.sha256_gz,
            "sha256": file.sha256_uncompressed,
            "chunks": chunks.iter().map(|(height, _)| height).collect::<Vec<_>>(),
            "proof": "a row is leaf keccak256(\"leaf\" || keccak256(line)) at its index; siblings up to its peak, peaks bagged highest first",
        }
    });
    let data = leaves_call(&chunks, &metadata.to_string());
    let step = push(steps, Kind::Leaves, &registry.name, data);
    step.checksum = Some(root);
    Ok(GAS_FRESH_SLOT * (chunks.len() as u64 + 1) + GAS_LEAVES_CALL)
}

// -- the registry's MMR, as the precompile hashes it ----------------------------

fn mmr_leaf(line: &[u8]) -> [u8; 32] {
    hash_leaf(&keccak256(line))
}

fn mmr_merge(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash_merge(left, right)
}

/// The file's lines as aligned perfect subtrees from an empty MMR: `(height, root)`
/// in leaf order, sizes by the binary decomposition of the length, largest first.
pub fn mmr_chunks(lines: &[Vec<u8>]) -> Vec<(u8, [u8; 32])> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < lines.len() {
        let size = 1usize << (usize::BITS - 1 - (lines.len() - at).leading_zeros());
        let mut level: Vec<[u8; 32]> = lines[at..at + size].iter().map(|l| mmr_leaf(l)).collect();
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|pair| mmr_merge(&pair[0], &pair[1]))
                .collect();
        }
        out.push((size.trailing_zeros() as u8, level[0]));
        at += size;
    }
    out
}

/// The root the precompile computes: the chunks are the peaks of an MMR loaded
/// from empty, bagged highest first; zero when empty.
pub fn mmr_root(chunks: &[(u8, [u8; 32])]) -> String {
    let peaks: Vec<[u8; 32]> = chunks.iter().map(|(_, root)| *root).collect();
    hex0x(&bag(&peaks))
}

/// `appendLeaves(bytes32[] chunkRoots, uint8[] chunkHeights, bytes metadata)`.
pub fn leaves_call(chunks: &[(u8, [u8; 32])], metadata: &str) -> String {
    let word = |n: usize| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&(n as u64).to_be_bytes());
        w
    };
    let array = |words: Vec<[u8; 32]>| {
        let mut tail = word(words.len()).to_vec();
        tail.extend(words.concat());
        tail
    };
    let roots = array(chunks.iter().map(|(_, root)| *root).collect());
    let heights = array(
        chunks
            .iter()
            .map(|(height, _)| word(*height as usize))
            .collect(),
    );
    let mut bytes = word(metadata.len()).to_vec();
    bytes.extend_from_slice(metadata.as_bytes());
    bytes.resize(bytes.len().next_multiple_of(32), 0);

    let head_len = 3 * 32;
    let mut data = selector("appendLeaves(bytes32[],uint8[],bytes)").to_vec();
    data.extend(word(head_len));
    data.extend(word(head_len + roots.len()));
    data.extend(word(head_len + roots.len() + heights.len()));
    data.extend(roots);
    data.extend(heights);
    data.extend(bytes);
    hex0x(&data)
}

/// The merkle root of `leaves`' lines. An empty file has no root to commit to.
pub fn merkle_root(lines: &[Vec<u8>]) -> String {
    if lines.is_empty() {
        return hex0x(&[0u8; 32]);
    }
    let mut level: Vec<[u8; 32]> = lines.iter().map(|line| keccak256(line)).collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [left, right] => keccak256(&[left.as_slice(), right.as_slice()].concat()),
                [odd] => *odd,
                _ => unreachable!("chunks(2) yields one or two"),
            })
            .collect();
    }
    hex0x(&level[0])
}

/// A tranche file's lines, verified against the manifest before anything reads
/// them -- both digests, as the module's loader did, because a file that is not
/// the one the manifest describes plans a corpus nobody exported.
fn read_lines(export_dir: &Path, file: &FileEntry) -> Result<Vec<Vec<u8>>> {
    let path = export_dir.join(&file.file);
    let gz = std::fs::read(&path)
        .with_context(|| format!("{} is not staged under {}", file.file, export_dir.display()))?;
    verify(&gz, &file.sha256_gz, &file.file, "sha256_gz")?;

    let mut content = Vec::new();
    std::io::Read::read_to_end(&mut GzDecoder::new(&gz[..]), &mut content)
        .with_context(|| format!("{}: gzip stream", file.file))?;
    verify(
        &content,
        &file.sha256_uncompressed,
        &file.file,
        "sha256_uncompressed",
    )?;

    let lines: Vec<Vec<u8>> = BufReader::new(&content[..])
        .split(b'\n')
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .map(|line| line.trim_ascii_end().to_vec())
        .filter(|line| !line.is_empty())
        .collect();
    if lines.len() != file.records {
        bail!(
            "{}: holds {} records, the manifest says {}",
            file.file,
            lines.len(),
            file.records
        );
    }
    Ok(lines)
}

fn read_records(export_dir: &Path, file: &FileEntry) -> Result<Vec<RecordImport>> {
    read_lines(export_dir, file)?
        .iter()
        .enumerate()
        .map(|(i, line)| {
            serde_json::from_slice(line).with_context(|| format!("{} line {}", file.file, i + 1))
        })
        .collect()
}

fn verify(bytes: &[u8], expected: &str, file: &str, field: &str) -> Result<()> {
    let got = hex::encode(Sha256::digest(bytes));
    if got != strip_hex(expected) {
        bail!("{file}: {field} is {got}, the manifest says {expected}");
    }
    Ok(())
}

// -- calldata -----------------------------------------------------------------
//
// Hand-encoded rather than generated: every call the plan makes takes strings
// and nothing else, so the whole encoder is a head of offsets and a tail of
// padded bytes. `tests/migrate.rs` pins each selector and a full call.

fn selector(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

/// `abi.encode` over strings, with static words placed into the head by slot --
/// `updateRecordStatus` has one, and `addRecord` has its category.
fn encode(signature: &str, strings: &[&str], statics: &[(usize, u64)]) -> String {
    let arity = strings.len() + statics.len();
    let mut head: Vec<[u8; 32]> = vec![[0u8; 32]; arity];
    let mut tail: Vec<u8> = Vec::new();

    for (slot, value) in statics {
        head[*slot][24..].copy_from_slice(&value.to_be_bytes());
    }
    let mut string_slots = (0..arity).filter(|slot| !statics.iter().any(|(s, _)| s == slot));
    for text in strings {
        let slot = string_slots.next().expect("a slot per string");
        let offset = arity * 32 + tail.len();
        head[slot][24..].copy_from_slice(&(offset as u64).to_be_bytes());

        let mut length = [0u8; 32];
        length[24..].copy_from_slice(&(text.len() as u64).to_be_bytes());
        tail.extend_from_slice(&length);
        tail.extend_from_slice(text.as_bytes());
        tail.resize(tail.len().next_multiple_of(32), 0);
    }

    let mut data = selector(signature).to_vec();
    data.extend(head.concat());
    data.extend(tail);
    hex0x(&data)
}

pub fn deploy_registry_call(name: &str, description: &str, metadata: &str) -> String {
    encode(
        "deployRegistry(string,string,string)",
        &[name, description, metadata],
        &[],
    )
}

pub fn add_record_call(
    uri: &str,
    checksum: &str,
    checksum_algo: &str,
    metadata: &str,
    category: u8,
    data_pointer: &str,
) -> String {
    encode(
        "addRecord(string,string,string,string,uint8,string)",
        &[uri, checksum, checksum_algo, metadata, data_pointer],
        &[(4, u64::from(category))],
    )
}

pub fn update_status_call(checksum: &str, version: u64, status: &str) -> String {
    encode(
        "updateRecordStatus(string,uint256,string)",
        &[checksum, status],
        &[(1, version)],
    )
}

// -- reconciliation -----------------------------------------------------------

/// What the chain holds for one registry: its records, or `None` when no registry
/// carries the plan's name — so its deploy is still to send, and everything under
/// it with it.
pub type Held = Option<Vec<Record>>;

/// One way the chain and the plan disagree, in the words an operator acts on.
#[derive(Debug, Clone, Serialize)]
pub struct Divergence {
    pub registry: String,
    pub detail: String,
}

/// What a plan is still owed, and what it cannot be.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    /// What sending cannot fix. Non-empty is the one reason `reconcile` exits non-zero.
    pub divergences: Vec<Divergence>,
    /// The steps still to send, in plan order — how a stopped run resumes.
    pub remaining: Vec<Step>,
}

/// A plan, read back off the chain.
///
/// Registries are matched by the name the plan deployed them under, because that
/// is the only handle it has: the address exists once the deploy has landed, and
/// a name the listing does not carry means that step did not.
///
/// Takes the plan's text rather than a path, so the rule below can be exercised
/// against a listing without one on disk.
pub async fn against_chain(ctx: &Ctx, plan: &str) -> Result<Report> {
    let steps: Vec<Step> = plan
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()
        .context("the plan is one JSON step per line")?;

    let listing = service::deployments(ctx, &NameFilter::default())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let factory = listing["factory"]
        .as_str()
        .context("the listing names the factory it was read from")?
        .to_string();
    let deployed: Vec<Deployed> = serde_json::from_value(listing["registries"].clone())?;
    let mut by_name: BTreeMap<&str, Vec<&Deployed>> = BTreeMap::new();
    for registry in &deployed {
        by_name.entry(&registry.name).or_default().push(registry);
    }

    // Sort the plan's names into landed, not yet, and ambiguous — then read every
    // landed one's records in a single walk, rather than one walk per registry.
    let names: BTreeSet<&str> = steps.iter().map(|step| step.registry.as_str()).collect();
    let (mut held, mut ambiguous) = (BTreeMap::new(), Vec::new());
    let mut landed: BTreeMap<&str, &str> = BTreeMap::new();
    for name in names {
        match by_name.get(name).map(Vec::as_slice).unwrap_or(&[]) {
            [registry] => {
                landed.insert(name, registry.address.as_str());
            }
            // The plan refuses duplicate names, so two here came from elsewhere,
            // and there is no telling which one it meant or resuming into it.
            carried @ [_, _, ..] => ambiguous.push(Divergence {
                registry: name.to_string(),
                detail: format!("{} registries carry this name", carried.len()),
            }),
            [] => {
                held.insert(name.to_string(), None);
            }
        }
    }
    let addresses: Vec<String> = landed.values().map(|at| at.to_string()).collect();
    let served = service::records_held_by(ctx, &addresses)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    for (name, address) in &landed {
        let records: Vec<Record> = serde_json::from_value(served["registries"][*address].clone())?;
        held.insert(name.to_string(), Some(records));
    }

    // What each landed registry's MMR was first loaded with, in one more walk: a
    // leaves step is judged by its own landing, not by what came after.
    let served = service::mmr_held_by(ctx, &addresses, Edge::Oldest)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let roots: BTreeMap<String, String> = landed
        .iter()
        .filter_map(|(name, address)| {
            let root = served["registries"][address.to_lowercase()]["root"].as_str()?;
            Some((name.to_string(), root.to_string()))
        })
        .collect();

    let mut report = reconcile(&steps, &held, &roots);
    report.divergences.extend(ambiguous);
    report.remaining = addressed(report.remaining, &factory, &landed);
    Ok(report)
}

/// Stamp `to` on the steps still owed, wherever the address is already knowable: a
/// deploy goes to the factory, and everything under a registry that has landed goes
/// to that registry. Steps under one that has not stay unaddressed — their address
/// is what its deploy will announce, so a sender resends the deploy and asks again.
pub fn addressed(
    mut remaining: Vec<Step>,
    factory: &str,
    landed: &BTreeMap<&str, &str>,
) -> Vec<Step> {
    for step in &mut remaining {
        step.to = match step.kind {
            Kind::Deploy => Some(factory.to_string()),
            _ => landed.get(step.registry.as_str()).map(|at| at.to_string()),
        };
    }
    remaining
}

/// Compare a plan against what the chain holds.
///
/// One question per step: would sending it close the gap? If so it is `remaining`,
/// and that is not a divergence — a stopped run has steps left, and being mid-way
/// is the normal state to reconcile from. Deciding it per step against the chain
/// is what makes a stopped run resumable: `addRecord` appends a version every time
/// it is called, so a re-sent step leaves one too many rather than doing nothing.
///
/// `divergences` is what sending cannot fix, so a human has to look: a record the
/// chain holds *past* the version the plan writes, which is a step that went twice,
/// and one the plan does not write at all.
///
/// A `leaves` step is judged by `roots`, the root each landed registry's first
/// append left: none owes the step, the planned one closes it, and any other is a
/// divergence, since the chunks were cut for an empty MMR. The first append rather
/// than the newest, so a record added after the load leaves the verdict alone.
pub fn reconcile(
    steps: &[Step],
    held: &BTreeMap<String, Held>,
    roots: &BTreeMap<String, String>,
) -> Report {
    let mut report = Report::default();
    let records_of = |registry: &str| held.get(registry).and_then(Option::as_deref);

    for step in steps {
        let Some(records) = records_of(&step.registry) else {
            report.remaining.push(step.clone()); // its deploy has not landed
            continue;
        };
        if step.kind == Kind::Leaves {
            let planned = step.checksum.as_deref().unwrap_or_default().to_lowercase();
            match roots.get(&step.registry).map(|r| r.to_lowercase()) {
                None => report.remaining.push(step.clone()),
                Some(held) if held == planned => {}
                Some(held) => report.divergences.push(Divergence {
                    registry: step.registry.clone(),
                    detail: format!(
                        "the MMR's first append left root {held}; the plan loads {planned} \
                         into an empty one"
                    ),
                }),
            }
            continue;
        }
        let (Some(checksum), Some(version)) = (&step.checksum, step.version) else {
            continue; // a deploy that landed
        };
        let record = records.iter().find(|r| r.checksum == *checksum);

        let owed = match (step.kind, record) {
            (Kind::Deploy, _) => false,
            (Kind::Record, None) => true,
            (Kind::Record, Some(held)) => held.version < version,
            // A status is sent right after the version it names, so it cannot go
            // before that version is there, and a record already past it is one
            // whose status step went by.
            (Kind::Status, None) => true,
            (Kind::Status, Some(held)) if held.version < version => true,
            (Kind::Status, Some(held)) if held.version > version => false,
            (Kind::Status, Some(held)) => held.status.as_deref() != step.status.as_deref(),
            (Kind::Leaves, _) => unreachable!("a leaves step was judged by its root above"),
        };
        if owed {
            report.remaining.push(step.clone());
        }
    }

    // The other direction: what the chain holds and the plan does not write.
    let mut planned: BTreeMap<(&str, &str), u64> = BTreeMap::new();
    for step in steps.iter().filter(|s| s.kind == Kind::Record) {
        if let (Some(checksum), Some(version)) = (&step.checksum, step.version) {
            let newest = planned.entry((&step.registry, checksum)).or_default();
            *newest = (*newest).max(version);
        }
    }
    for (registry, records) in held {
        for record in records.iter().flatten() {
            let detail = match planned.get(&(registry.as_str(), record.checksum.as_str())) {
                None => format!(
                    "`{}` is there and the plan does not write it",
                    record.checksum
                ),
                Some(version) if record.version > *version => format!(
                    "`{}` is at version {}, past the plan's {version} — a step sent twice",
                    record.checksum, record.version
                ),
                Some(_) => continue,
            };
            report.divergences.push(Divergence {
                registry: registry.clone(),
                detail,
            });
        }
    }
    report
}
