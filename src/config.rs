//! Runtime configuration, from the environment.

use std::env;

pub const DEFAULT_RPC_URL: &str = "https://rpc.nvnm.canary.mantrachain.dev";

#[derive(Debug, Clone)]
pub struct Settings {
    pub rpc_url: String,
    pub db_path: String,
    /// The `AnchoringRegistry` proxy, when there is one to follow. Without it
    /// the indexer still has every anchor — only role history is missing.
    pub registry_address: Option<String>,
    /// Where to start scanning. The precompile arrives at T10, so there is no
    /// point reading below that block.
    pub start_block: u64,
    /// Blocks per `eth_getLogs` call. Nodes cap this; 2000 is widely safe.
    pub log_range: u64,
    pub poll_seconds: f64,
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

impl Settings {
    pub fn from_env() -> Self {
        Self {
            rpc_url: env::var("NVNM_RPC")
                .or_else(|_| env::var("TEMPO_RPC"))
                .unwrap_or_else(|_| DEFAULT_RPC_URL.to_string()),
            db_path: env_or("DB_PATH", "anchoring.db"),
            registry_address: env::var("REGISTRY_ADDRESS")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            start_block: env_parse("START_BLOCK", 0),
            log_range: env_parse::<u64>("LOG_RANGE", 2000).max(1),
            poll_seconds: env_parse::<f64>("POLL_SECONDS", 2.0).max(0.1),
        }
    }
}
