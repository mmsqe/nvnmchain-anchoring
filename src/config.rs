//! Runtime configuration, from the environment.

use std::env;

use anyhow::{Context, Result};

use crate::tidx::{Engine, HARD_LIMIT};

pub const DEFAULT_RPC_URL: &str = "https://rpc.nvnm.canary.mantrachain.dev";
pub const DEFAULT_TIDX_URL: &str = "http://127.0.0.1:8080";

#[derive(Debug, Clone)]
pub struct Settings {
    /// A node, for the precompile's own storage. Nothing else needs one.
    pub rpc_url: String,
    /// A tidx instance indexing the same chain.
    pub tidx_url: String,
    /// tidx serves several chains from one endpoint, so every query names one.
    pub chain_id: u64,
    pub engine: Engine,
    /// The precompile arrives at T10, so an index reaching this far back has
    /// seen every anchor there is.
    pub first_block: u64,
    /// Rows per tidx round trip. Only worth setting below the default to make
    /// the paging loop observable in a test.
    pub page_size: usize,
}

impl Settings {
    pub fn from_env() -> Result<Self> {
        let engine = match env::var("TIDX_ENGINE") {
            Ok(v) => Engine::parse(&v)
                .with_context(|| format!("TIDX_ENGINE={v}: expected postgres or clickhouse"))?,
            Err(_) => Engine::Postgres,
        };
        Ok(Self {
            rpc_url: env::var("NVNM_RPC")
                .or_else(|_| env::var("TEMPO_RPC"))
                .unwrap_or_else(|_| DEFAULT_RPC_URL.to_string()),
            tidx_url: env::var("TIDX_URL").unwrap_or_else(|_| DEFAULT_TIDX_URL.to_string()),
            // No default: tidx requires a chain id on every query, and guessing
            // one would silently audit a chain the node is not serving.
            chain_id: env::var("CHAIN_ID")
                .context("CHAIN_ID is required — tidx serves several chains from one endpoint")?
                .trim()
                .parse()
                .context("CHAIN_ID must be a number")?,
            engine,
            first_block: env::var("START_BLOCK")
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0),
            page_size: env::var("PAGE_SIZE")
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(HARD_LIMIT),
        })
    }
}
