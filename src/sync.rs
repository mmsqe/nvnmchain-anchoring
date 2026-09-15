//! Keeping the index level with the contract, by paging `registries` past the highest id held.
//! Events cannot: the registries loaded at genesis have no `AddRegistry` log.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_primitives::Address;
use anyhow::{bail, Result};
use tracing::{info, warn};

use crate::contract::{decode_page, page_after};
use crate::index::Index;
use crate::rpc::Rpc;

/// The last round of sync, as `/health` reports it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Round {
    /// When a round last succeeded, in Unix seconds; none before the first.
    pub synced_at: Option<u64>,
    /// What the last round said, if it failed.
    pub error: Option<String>,
}

/// Where each round is reported: `follow` writes, `/health` reads.
#[derive(Default)]
pub struct Status(Mutex<Round>);

impl Status {
    pub fn ok(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Round {
            synced_at: Some(now),
            error: None,
        };
    }

    pub fn failed(&self, err: &anyhow::Error) {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).error = Some(format!("{err:#}"));
    }

    pub fn round(&self) -> Round {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Indexes every registry past the last one held, and returns how many that was.
pub async fn catch_up(rpc: &Rpc, contract: Address, index: &Index) -> Result<u64> {
    let mut added = 0;
    loop {
        let after = index.last_id()?;
        let (page, more) = decode_page(&rpc.eth_call(contract, &page_after(after)).await?)?;
        // A page that does not carry on from `after` without a hole is not from the
        // contract this index was built from, and would break `last_id`.
        for (expected, registry) in (after + 1..).zip(&page) {
            if registry.id != expected {
                bail!("registry {} came where {expected} was due", registry.id);
            }
        }
        index.insert(&page)?;
        added += page.len() as u64;
        if !more || page.is_empty() {
            return Ok(added);
        }
    }
}

/// `catch_up` every `poll`, reporting each round to `status`. A failed round is logged and
/// retried on the next tick, so a node restarting does not take the search down with it.
pub async fn follow(rpc: Rpc, contract: Address, index: &Index, poll: Duration, status: &Status) {
    loop {
        tokio::time::sleep(poll).await;
        match catch_up(&rpc, contract, index).await {
            Ok(added) => {
                status.ok();
                if added != 0 {
                    info!("new registries indexed: {added}");
                }
            }
            Err(e) => {
                warn!("sync: {e:#}");
                status.failed(&e);
            }
        }
    }
}
