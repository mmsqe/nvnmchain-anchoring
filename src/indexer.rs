//! Ingestion: `eth_getLogs` per source, a cursor per source, and one reorg
//! check across them. Blocks are never fetched for their contents — the history
//! is a log, so a filtered range scan is the whole read path.

use anyhow::{Context, Result};
use serde_json::Value;
use tracing::{info, warn};

use crate::config::Settings;
use crate::db::{self, Anchored, Db, RegistryEvent};
use crate::eth::{address_from_topic, normalize_hex, strip_hex};
use crate::precompile::{self, decode_anchored_data, ANCHORED_TOPIC};
use crate::registry::REGISTRY_TOPICS;
use crate::rpc::{parse_hex_u64, Rpc};

/// How many checkpoints back a reorg may be resolved before giving up and
/// re-syncing. Deeper than any reorg this chain should produce.
const MAX_REORG_DEPTH: usize = 64;

/// What was ingested in one pass, for the log line.
#[derive(Debug, Default)]
pub struct Progress {
    pub anchored: usize,
    pub registry_events: usize,
}

pub struct Indexer {
    pub rpc: Rpc,
    pub db: Db,
    pub cfg: Settings,
}

impl Indexer {
    /// Index every source up to the current head.
    ///
    /// Each source keeps its own cursor: configuring `REGISTRY_ADDRESS` after a
    /// sync has already reached the head must not skip its history, which one
    /// shared cursor would do silently and permanently.
    pub async fn sync_to_head(&self) -> Result<(u64, Progress)> {
        let head = self.rpc.block_number().await.context("chain head")?;
        self.check_for_reorg().await?;

        let mut progress = Progress::default();
        self.sync_source(db::SOURCE_ANCHORED, head, &mut progress)
            .await?;
        if let Some(registry) = self.cfg.registry_address.clone() {
            self.sync_source(&db::registry_source(&registry), head, &mut progress)
                .await?;
        }
        Ok((head, progress))
    }

    async fn sync_source(&self, source: &str, head: u64, progress: &mut Progress) -> Result<()> {
        let anchored = source == db::SOURCE_ANCHORED;
        let mut from = {
            let conn = db::lock(&self.db);
            db::cursor(&conn, source).map_or(self.cfg.start_block, |c| c + 1)
        };
        while from <= head {
            let to = (from + self.cfg.log_range - 1).min(head);
            // The block hash comes back with the logs, so the checkpoint costs
            // no extra round trip and commits with the cursor it belongs to.
            let (logs, hash) = self.fetch(source, anchored, from, to).await?;
            let count = logs.len();
            {
                let mut conn = db::lock(&self.db);
                let txn = conn.transaction()?;
                for log in &logs {
                    match log {
                        Ingested::Anchored(event) => db::insert_anchored(&txn, event)?,
                        Ingested::Registry(event) => db::insert_registry_event(&txn, event)?,
                    }
                }
                db::save_checkpoint(&txn, to, &hash)?;
                db::set_cursor(&txn, source, to)?;
                txn.commit()?;
            }
            if count > 0 {
                info!("{source} {from}..={to}: {count} log(s)");
                *if anchored {
                    &mut progress.anchored
                } else {
                    &mut progress.registry_events
                } += count;
            }
            from = to + 1;
        }
        Ok(())
    }

    /// One range of one source, plus the hash of its last block.
    async fn fetch(
        &self,
        source: &str,
        anchored: bool,
        from: u64,
        to: u64,
    ) -> Result<(Vec<Ingested>, String)> {
        let (address, topics): (String, Vec<&str>) = if anchored {
            (precompile::ADDRESS.to_string(), vec![ANCHORED_TOPIC])
        } else {
            (
                source.trim_start_matches("registry:").to_string(),
                REGISTRY_TOPICS.iter().map(|(topic, _)| *topic).collect(),
            )
        };
        let (logs, block) = self
            .rpc
            .logs_and_block_hash(&address, &topics, from, to)
            .await
            .with_context(|| format!("{source} logs {from}..={to}"))?;
        let ingested = logs
            .iter()
            .filter_map(|log| {
                if anchored {
                    parse_anchored(log).map(Ingested::Anchored)
                } else {
                    parse_registry_event(log).map(Ingested::Registry)
                }
            })
            .collect();
        Ok((ingested, block))
    }

    /// Walk the checkpoints back until one still matches the chain, and drop
    /// everything above it. A no-op on the happy path (newest checkpoint agrees).
    async fn check_for_reorg(&self) -> Result<()> {
        let checkpoints = {
            let conn = db::lock(&self.db);
            db::recent_checkpoints(&conn, MAX_REORG_DEPTH)?
        };
        // Descending, so the last disagreement is the deepest one — roll back
        // once to there rather than once per rejected checkpoint.
        let mut fork = None;
        for (block, stored) in &checkpoints {
            let onchain = self.rpc.block_hash(*block).await?;
            if onchain.as_deref().map(normalize_hex) == Some(normalize_hex(stored)) {
                break;
            }
            fork = Some(*block);
        }
        let Some(fork) = fork else {
            return Ok(());
        };
        if fork == checkpoints.last().map(|(b, _)| *b).unwrap_or(fork) {
            warn!(
                "reorg deeper than {} checkpoints; re-syncing",
                checkpoints.len()
            );
        }
        warn!("reorg: rolling back to block {fork}");
        let conn = db::lock(&self.db);
        db::rollback_to(&conn, fork)
    }
}

/// A parsed log, still tagged by which table it belongs in.
enum Ingested {
    Anchored(Anchored),
    Registry(RegistryEvent),
}

/// Where a log sits in the chain: block, position, and the transaction.
fn log_site(log: &Value) -> Option<(i64, i64, String)> {
    Some((
        parse_hex_u64(log.get("blockNumber")?.as_str()?)? as i64,
        parse_hex_u64(log.get("logIndex")?.as_str()?)? as i64,
        log.get("transactionHash")?.as_str()?.to_string(),
    ))
}

fn log_data(log: &Value) -> Option<Vec<u8>> {
    hex::decode(strip_hex(
        log.get("data").and_then(Value::as_str).unwrap_or("0x"),
    ))
    .ok()
}

/// One `Anchored` log as a row, or `None` when it is not one we can trust.
pub fn parse_anchored(log: &Value) -> Option<Anchored> {
    let topics = log.get("topics")?.as_array()?;
    if topics.len() < 3 || !topics[0].as_str()?.eq_ignore_ascii_case(ANCHORED_TOPIC) {
        return None;
    }
    let (block_number, log_index, tx_hash) = log_site(log)?;
    let (commitment, metadata) = decode_anchored_data(&log_data(log)?)?;
    Some(Anchored {
        block_number,
        log_index,
        tx_hash,
        namespace: address_from_topic(topics[1].as_str()?)?,
        key: normalize_hex(topics[2].as_str()?),
        commitment,
        metadata,
    })
}

pub fn parse_registry_event(log: &Value) -> Option<RegistryEvent> {
    let topics = log.get("topics")?.as_array()?;
    let (block_number, log_index, tx_hash) = log_site(log)?;
    // Topics as one blob of 32-byte words; topic0 is derived from it at the SQL
    // boundary, so the two spellings cannot disagree.
    let mut packed = Vec::with_capacity(topics.len() * 32);
    for topic in topics {
        packed.extend_from_slice(&hex::decode(strip_hex(topic.as_str()?)).ok()?);
    }
    Some(RegistryEvent {
        block_number,
        log_index,
        tx_hash,
        topics: packed,
        data: log_data(log)?,
    })
}
