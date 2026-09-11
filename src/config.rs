//! Runtime configuration, from the environment.

use std::env;
use std::time::Duration;

use alloy_primitives::Address;
use anyhow::{Context, Result};

pub const DEFAULT_RPC_URL: &str = "https://rpc.nvnm.canary.mantrachain.dev";

/// The anchoring contract.
pub const DEFAULT_CONTRACT: &str = "0x0000000000000000000000000000000000000a00";

#[derive(Debug, Clone)]
pub struct Settings {
    pub rpc_url: String,
    pub contract: Address,
    /// Derived data: delete it and the next start copies every registry again.
    pub db_path: String,
    /// Where `serve` listens.
    pub bind: String,
    /// How often to ask the contract for registries past the last one indexed, one second at least.
    pub poll: Duration,
}

impl Settings {
    pub fn from_env() -> Result<Self> {
        let contract = env::var("CONTRACT_ADDRESS").unwrap_or_else(|_| DEFAULT_CONTRACT.into());
        let poll_seconds: u64 = match env::var("POLL_SECONDS") {
            Ok(v) => v
                .trim()
                .parse()
                .with_context(|| format!("POLL_SECONDS={v}: not a whole number of seconds"))?,
            Err(_) => 2,
        };
        Ok(Self {
            rpc_url: env::var("NVNM_RPC")
                .or_else(|_| env::var("TEMPO_RPC"))
                .unwrap_or_else(|_| DEFAULT_RPC_URL.to_string()),
            contract: contract
                .trim()
                .parse()
                .with_context(|| format!("CONTRACT_ADDRESS={contract}: not a 20-byte address"))?,
            db_path: env::var("DB_PATH").unwrap_or_else(|_| "anchoring_name_index.db".into()),
            bind: env::var("BIND").unwrap_or_else(|_| "127.0.0.1:8081".to_string()),
            poll: Duration::from_secs(poll_seconds.max(1)),
        })
    }
}
