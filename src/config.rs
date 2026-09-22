//! Runtime configuration, from the environment.

use std::env;

const DEFAULT_RPC_URL: &str = "https://rpc.nvnm.canary.mantrachain.dev";

pub struct Settings {
    /// A node started with `--anchoring.name-index`, which answers the search this translates.
    pub rpc_url: String,
    /// Where `serve` listens.
    pub bind: String,
}

impl Settings {
    pub fn from_env() -> Self {
        Self {
            rpc_url: env::var("NVNM_RPC")
                .or_else(|_| env::var("TEMPO_RPC"))
                .unwrap_or_else(|_| DEFAULT_RPC_URL.to_string()),
            bind: env::var("BIND").unwrap_or_else(|_| "127.0.0.1:8081".to_string()),
        }
    }
}
