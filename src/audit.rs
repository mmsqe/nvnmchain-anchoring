//! Does the index still match the chain?
//!
//! The precompile keeps one MMR per namespace, and every append is in the log
//! with what it added. So a namespace's history folds back into a root, and
//! that root is compared with `state()` on the node at the same block — every
//! leaf the index ever saw for that namespace is under it, which is what the
//! head model could never say: a slot per key could only be checked for keys
//! the index already knew.
//!
//! Note what that does and does not prove. Building the fold is *our* hashing,
//! so a drift in it would report every namespace as mismatched; the event's own
//! root is checked against the fold at each step to tell an index fault from an
//! instrument fault, and one `eth_getStorageAt` on the count slot calibrates
//! the slot layout against `state()`. A namespace the index never saw at all is
//! still invisible, bounded — not closed — by the index's own coverage.
//!
//! Every read is pinned to the block ingest has reached, not to `latest`. An
//! index is always some blocks behind a node, and comparing one as of block N
//! against state as of N+3 reports every append written in between as a
//! mismatch.

use anyhow::{Context, Result};
use serde_json::Value;

use crate::envelope::is_self_verifying;
use crate::eth::{hex0x, normalize_hex, strip_hex};
use crate::mmr::{bag, Mmr};
use crate::precompile::{count_slot, ADDRESS};
use crate::rpc::{decode_state, Rpc};
use crate::tidx::{Append, Appended, Coverage, Tidx};

/// Namespaces per JSON-RPC batch. Large enough that the round trip stops
/// dominating, small enough to stay inside a node's request-size limit.
const BATCH: usize = 200;

#[derive(Debug)]
pub struct Report {
    /// Namespaces folded and compared.
    pub checked: usize,
    /// Leaves folded, across every namespace.
    pub leaves: u64,
    /// Namespaces where the chain disagrees with the fold of what the index holds.
    pub mismatched: Vec<Mismatch>,
    /// Appends whose own root or position disagrees with the fold up to them, or
    /// that the precompile would have refused outright — the index's copy of the
    /// log contradicting itself, rather than the chain.
    pub inconsistent: Vec<Inconsistent>,
    /// Leaves whose commitment is not `keccak256(metadata)`. Not an error — a
    /// plain `appendLeaf` may commit to anything — but every registry write is
    /// self-verifying, so a run of these says the leaves are not registry ones.
    pub unverifiable: usize,
    /// What the index holds, and the block every state read was taken at.
    pub coverage: Coverage,
    /// The lowest block an append could have been written at, so coverage
    /// short of it leaves namespaces this run cannot know about.
    pub first_block: u64,
    /// Whether the slot layout still agrees with the node's `state()`.
    /// `None` when there was no namespace to calibrate against.
    pub slot_rule_holds: Option<bool>,
}

#[derive(Debug)]
pub struct Mismatch {
    pub namespace: String,
    pub indexed_root: String,
    pub indexed_count: u64,
    pub onchain_root: String,
    pub onchain_count: u64,
}

#[derive(Debug)]
pub struct Inconsistent {
    pub namespace: String,
    pub block_num: u64,
    pub log_idx: u64,
    pub detail: String,
}

impl Report {
    pub fn is_clean(&self) -> bool {
        self.mismatched.is_empty()
            && self.inconsistent.is_empty()
            && self.coverage.reaches(self.first_block)
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "checked {} namespace(s), {} leaves, at block {}: {}",
            self.checked,
            self.leaves,
            self.coverage.tip_num,
            if self.mismatched.is_empty() {
                "every root matches the precompile".to_string()
            } else {
                format!("{} MISMATCHED", self.mismatched.len())
            }
        )?;
        for m in &self.mismatched {
            writeln!(
                f,
                "  {}\n    indexed {} ({} leaves)\n    onchain {} ({} leaves)",
                m.namespace, m.indexed_root, m.indexed_count, m.onchain_root, m.onchain_count
            )?;
        }
        for i in &self.inconsistent {
            writeln!(
                f,
                "  INCONSISTENT {} at block {} log {}: {}",
                i.namespace, i.block_num, i.log_idx, i.detail
            )?;
        }
        if !self.coverage.reaches(self.first_block) {
            writeln!(
                f,
                "GAP: the index reaches back to {}, not {}; namespaces appended to only below \
                 that are invisible to this run",
                self.coverage
                    .backfill_num
                    .map_or_else(|| "nothing yet".to_string(), |b| b.to_string()),
                self.first_block
            )?;
        }
        if self.coverage.lag() > 0 {
            writeln!(
                f,
                "index is {} block(s) behind the chain; state was read at its block, not the head",
                self.coverage.lag()
            )?;
        }
        if self.slot_rule_holds == Some(false) {
            writeln!(
                f,
                "WARNING: the count slot disagrees with state(); the slot layout this crate \
                 assumes has moved"
            )?;
        }
        write!(
            f,
            "{} leaf(s) are not keccak(metadata) — plain appendLeaf rather than a registry write",
            self.unverifiable
        )
    }
}

/// One namespace's history folded: what the index says its MMR should be.
#[derive(Debug)]
pub struct Folded {
    pub mmr: Mmr,
    pub leaves: u64,
    pub unverifiable: usize,
    pub inconsistent: Vec<Inconsistent>,
}

impl Folded {
    fn note(&mut self, namespace: &str, append: &Append, detail: String) {
        self.inconsistent.push(Inconsistent {
            namespace: namespace.to_string(),
            block_num: append.block_num,
            log_idx: append.log_idx,
            detail,
        });
    }
}

/// Replay `history`, oldest first, checking each event against the fold up to it:
/// a leaf must land at the count, a batch must start there and end where it says,
/// and the root each event carries must be the fold's.
///
/// An event that cannot be replayed at all — a chunk the precompile would have
/// refused, a word that is not one — is noted like the rest and ends the fold: the
/// chain never wrote it, and nothing after it can be judged against a tree that
/// cannot be built.
pub fn fold(namespace: &str, history: &[Append]) -> Folded {
    let mut folded = Folded {
        mmr: Mmr::default(),
        leaves: 0,
        unverifiable: 0,
        inconsistent: Vec::new(),
    };
    for append in history {
        let before = folded.mmr.count;
        let (what, from, to) = match &append.what {
            Appended::Leaf { index, commitment } => {
                if !is_self_verifying(commitment, &append.metadata) {
                    folded.unverifiable += 1;
                }
                ("leaf", *index, None)
            }
            Appended::Leaves { first, count, .. } => ("a batch from", *first, Some(*count)),
        };
        if from != before {
            folded.note(
                namespace,
                append,
                format!("{what} {from} where the count is {before}"),
            );
        }
        match replay(&mut folded.mmr, &append.what) {
            Ok(added) => folded.leaves += added,
            Err(refused) => {
                folded.note(
                    namespace,
                    append,
                    format!("cannot be replayed: {refused:#}"),
                );
                break;
            }
        }
        if let Some(count) = to.filter(|count| *count != folded.mmr.count) {
            folded.note(
                namespace,
                append,
                format!(
                    "a batch to {count} where the fold reaches {}",
                    folded.mmr.count
                ),
            );
        }
        let root = hex0x(&folded.mmr.root());
        if normalize_hex(&append.root) != root {
            folded.note(
                namespace,
                append,
                format!("the event says root {}, the fold {root}", append.root),
            );
        }
    }
    folded
}

/// One append onto `mmr`, and the leaves it added.
fn replay(mmr: &mut Mmr, what: &Appended) -> Result<u64> {
    match what {
        Appended::Leaf { commitment, .. } => {
            mmr.append(&word(commitment)?)?;
            Ok(1)
        }
        Appended::Leaves {
            chunk_roots,
            chunk_heights,
            ..
        } => {
            let mut added = 0;
            for (root, height) in chunk_roots.iter().zip(chunk_heights) {
                mmr.push(*height, word(root)?)?;
                added += 1u64 << height;
            }
            Ok(added)
        }
    }
}

fn word(hexed: &str) -> Result<[u8; 32]> {
    hex::decode(strip_hex(hexed))
        .ok()
        .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
        .with_context(|| format!("{hexed}: not a 32-byte word"))
}

/// Fold every namespace the index holds and compare each with the precompile's
/// state at the same block.
pub async fn run(rpc: &Rpc, tidx: &Tidx, first_block: u64) -> Result<Report> {
    // Coverage first: it carries the block everything else is pinned to, so
    // the fold and the state it is compared against describe the same chain.
    let coverage = tidx.coverage().await?;
    let at = coverage.tip_num;
    let histories = tidx.histories(at).await?;

    let mut report = Report {
        checked: 0,
        leaves: 0,
        mismatched: Vec::new(),
        inconsistent: Vec::new(),
        unverifiable: 0,
        coverage,
        first_block,
        slot_rule_holds: None,
    };

    let mut folds = Vec::with_capacity(histories.len());
    for (namespace, history) in &histories {
        let folded = fold(namespace, history);
        report.leaves += folded.leaves;
        report.unverifiable += folded.unverifiable;
        report.inconsistent.extend(folded.inconsistent);
        folds.push((namespace, folded.mmr));
    }

    for chunk in folds.chunks(BATCH) {
        let calls: Vec<(&str, Value)> = chunk
            .iter()
            .map(|(namespace, _)| ("eth_call", Rpc::state_call(namespace, at)))
            .collect();
        for ((namespace, mmr), result) in chunk.iter().zip(rpc.call_batch(calls).await?) {
            let onchain = decode_state(result.as_str().unwrap_or("0x"))
                .with_context(|| format!("state({namespace}): malformed return"))?;
            report.checked += 1;
            let onchain_root = hex0x(&bag(&onchain
                .peaks
                .iter()
                .map(|p| word(p))
                .collect::<Result<Vec<_>>>()?));
            let indexed_root = hex0x(&mmr.root());
            if onchain.count != mmr.count || onchain_root != indexed_root {
                report.mismatched.push(Mismatch {
                    namespace: namespace.to_string(),
                    indexed_root,
                    indexed_count: mmr.count,
                    onchain_root,
                    onchain_count: onchain.count,
                });
            }
        }
    }

    // Calibrate the instrument: the slot layout is global, so one storage read on
    // a single namespace's count says whether it still agrees with the node.
    if let Some((namespace, _)) = folds.first() {
        let onchain = rpc.mmr_state(namespace, at).await?;
        let slot = count_slot(namespace).context("a checksummed address derives a slot")?;
        let via_slot = rpc.storage_at(ADDRESS, &slot, at).await?;
        let via_slot = u64::from_str_radix(strip_hex(&via_slot), 16).unwrap_or(u64::MAX);
        report.slot_rule_holds = Some(via_slot == onchain.count);
    }
    Ok(report)
}
