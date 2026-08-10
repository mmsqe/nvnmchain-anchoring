//! Does the index still match the chain?
//!
//! The precompile keeps one word per `(namespace, key)` at
//! `keccak256(0x01 ‖ pad32(ns) ‖ key)` — a derivation its own test suite pins
//! as reproducible off-chain — so every head can be compared against the
//! chain's own storage.
//!
//! Note what that does and does not prove. Building the slot is *our* keccak,
//! so a drift in the derivation would report every head as mismatched; one
//! `latest()` call calibrates against the node's own answer to tell an index
//! fault from an instrument fault. And the precompile stores nothing
//! enumerable, so this can only check keys the index already holds: a range
//! never ingested that anchored only *new* keys is invisible here, bounded —
//! not closed — by the index's own coverage.
//!
//! Every read is pinned to the block ingest has reached, not to `latest`. An
//! index is always some blocks behind a node, and comparing one as of block N
//! against state as of N+3 reports every anchor written in between as a
//! mismatch.

use anyhow::Result;
use serde_json::json;
use tracing::warn;

use crate::envelope::is_self_verifying;
use crate::eth::normalize_hex;
use crate::precompile::{head_slot, ADDRESS};
use crate::rpc::{block_tag, Rpc};
use crate::tidx::{Coverage, Head, Tidx};

/// Heads per JSON-RPC batch. Large enough that the round trip stops dominating,
/// small enough to stay inside a node's request-size limit.
const BATCH: usize = 200;

#[derive(Debug)]
pub struct Report {
    pub checked: usize,
    /// Heads where the chain disagrees with the index.
    pub mismatched: Vec<Mismatch>,
    /// Anchors whose commitment is not `keccak256(metadata)`. Not an error —
    /// plain `anchor()` may commit to anything — but every registry write uses
    /// `anchorAndHash`, so a run of these says the payloads are not registry ones.
    pub unverifiable: usize,
    /// What the index holds, and the block every state read was taken at.
    pub coverage: Coverage,
    /// The lowest block an anchor could have been written at, so coverage
    /// short of it leaves keys this run cannot know about.
    pub first_block: u64,
    /// Whether our slot derivation still agrees with the node's `latest()`.
    /// `None` when there was no head to calibrate against.
    pub slot_rule_holds: Option<bool>,
}

#[derive(Debug)]
pub struct Mismatch {
    pub namespace: String,
    pub key: String,
    pub indexed: String,
    pub onchain: String,
}

impl Report {
    pub fn is_clean(&self) -> bool {
        self.mismatched.is_empty() && self.coverage.reaches(self.first_block)
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "checked {} head(s) at block {}: {}",
            self.checked,
            self.coverage.tip_num,
            if self.mismatched.is_empty() {
                "all match the precompile".to_string()
            } else {
                format!("{} MISMATCHED", self.mismatched.len())
            }
        )?;
        for m in &self.mismatched {
            writeln!(
                f,
                "  {} / {}\n    indexed {}\n    onchain {}",
                m.namespace, m.key, m.indexed, m.onchain
            )?;
        }
        if !self.coverage.reaches(self.first_block) {
            writeln!(
                f,
                "GAP: the index reaches back to {}, not {}; keys anchored only below that \
                 are invisible to this run",
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
                "WARNING: the head-slot derivation disagrees with latest(); \
                 the mismatches above are the audit being wrong, not the index"
            )?;
        }
        write!(
            f,
            "{} head(s) are not keccak(metadata) — plain anchor() rather than anchorAndHash",
            self.unverifiable
        )
    }
}

/// Compare every head the index holds against the precompile's storage.
pub async fn run(rpc: &Rpc, tidx: &Tidx, first_block: u64) -> Result<Report> {
    // Coverage first: it carries the block everything else is pinned to, so
    // the heads and the storage they are compared against describe the same
    // chain.
    let coverage = tidx.coverage().await?;
    let at = coverage.tip_num;
    let heads = tidx.heads(at).await?;
    let block = block_tag(at);

    // Pair each head with its slot up front. A key no slot derives from is
    // dropped here — sent as an empty slot it would error the whole batch,
    // which is failing the audit, not skipping the head.
    let slotted: Vec<(&Head, String)> = heads
        .iter()
        .filter_map(|head| match head_slot(&head.namespace, &head.key) {
            Some(slot) => Some((head, slot)),
            None => {
                warn!("skipping malformed key {} / {}", head.namespace, head.key);
                None
            }
        })
        .collect();

    let mut report = Report {
        checked: 0,
        mismatched: Vec::new(),
        unverifiable: heads
            .iter()
            .filter(|h| !is_self_verifying(&h.commitment, &h.metadata))
            .count(),
        coverage,
        first_block,
        slot_rule_holds: None,
    };

    for chunk in slotted.chunks(BATCH) {
        let calls: Vec<(&str, serde_json::Value)> = chunk
            .iter()
            .map(|(_, slot)| ("eth_getStorageAt", json!([ADDRESS, slot, block])))
            .collect();
        for ((head, _), result) in chunk.iter().zip(rpc.call_batch(calls).await?) {
            let onchain = normalize_hex(result.as_str().unwrap_or("0x"));
            report.checked += 1;
            if onchain != normalize_hex(&head.commitment) {
                report.mismatched.push(Mismatch {
                    namespace: head.namespace.clone(),
                    key: head.key.clone(),
                    indexed: normalize_hex(&head.commitment),
                    onchain,
                });
            }
        }
    }

    // Calibrate the instrument: the slot rule is global, so one `latest()` on
    // a single head says whether our derivation still agrees with the node.
    if let Some((head, slot)) = slotted.first() {
        let onchain = rpc.latest(&head.namespace, &head.key, at).await?;
        let via_slot = normalize_hex(&rpc.storage_at(ADDRESS, slot, at).await?);
        report.slot_rule_holds = Some(normalize_hex(&onchain) == via_slot);
    }
    Ok(report)
}
