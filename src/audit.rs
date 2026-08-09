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
//! enumerable, so this can only check keys the index already holds: a missed
//! range that anchored only *new* keys is invisible here. That gap is covered
//! separately by checking the checkpoints cover the scanned range with no hole.

use anyhow::Result;
use tracing::warn;

use serde_json::json;

use crate::db::{self, Db};
use crate::envelope::is_self_verifying;
use crate::eth::normalize_hex;
use crate::precompile::{head_slot, ADDRESS};
use crate::rpc::Rpc;

/// Heads per JSON-RPC batch. Large enough that the round trip stops dominating,
/// small enough to stay inside a node's request-size limit.
const BATCH: usize = 200;

#[derive(Debug, Default)]
pub struct Report {
    pub checked: usize,
    /// Heads where the chain disagrees with the index.
    pub mismatched: Vec<Mismatch>,
    /// Anchors whose commitment is not `keccak256(metadata)`. Not an error —
    /// plain `anchor()` may commit to anything — but every registry write uses
    /// `anchorAndHash`, so a run of these says the payloads are not registry ones.
    pub unverifiable: usize,
    /// A span scanned but never pinned to a block hash, so a reorg across it
    /// would go unnoticed.
    pub uncheckpointed: Option<(u64, u64)>,
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
        self.mismatched.is_empty() && self.uncheckpointed.is_none()
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "checked {} head(s): {}",
            self.checked,
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
        if let Some((from, to)) = self.uncheckpointed {
            writeln!(f, "GAP: blocks {from}..={to} scanned with no checkpoint")?;
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

/// Compare every head this index holds against the precompile's storage.
pub async fn run(rpc: &Rpc, db: &Db) -> Result<Report> {
    let (heads, uncheckpointed) = {
        let conn = db::lock(db);
        (db::heads(&conn)?, db::uncheckpointed(&conn)?)
    };
    let mut report = Report {
        uncheckpointed,
        ..Report::default()
    };

    for chunk in heads.chunks(BATCH) {
        let mut slots = Vec::with_capacity(chunk.len());
        for head in chunk {
            if !is_self_verifying(&head.commitment, &head.metadata) {
                report.unverifiable += 1;
            }
            match head_slot(&head.namespace, &head.key) {
                Some(slot) => slots.push(slot),
                None => {
                    warn!("skipping malformed key {} / {}", head.namespace, head.key);
                    slots.push(String::new());
                }
            }
        }
        let calls: Vec<(&str, serde_json::Value)> = slots
            .iter()
            .map(|slot| ("eth_getStorageAt", json!([ADDRESS, slot, "latest"])))
            .collect();
        let results = rpc.call_batch(calls).await?;

        for (head, result) in chunk.iter().zip(results) {
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

    // Calibrate the instrument: the slot rule is global, so one `latest()` on a
    // single head says whether our derivation still agrees with the node.
    if let Some(head) = heads.first() {
        let onchain = rpc.latest(&head.namespace, &head.key).await?;
        let slot = head_slot(&head.namespace, &head.key).unwrap_or_default();
        let via_slot = normalize_hex(&rpc.storage_at(ADDRESS, &slot).await?);
        report.slot_rule_holds = Some(normalize_hex(&onchain) == via_slot);
    }
    Ok(report)
}
