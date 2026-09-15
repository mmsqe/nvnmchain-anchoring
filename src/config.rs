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
    /// How often to ask the contract for registries past the last one indexed.
    pub poll: Duration,
}

/// Floor on the poll interval, so a zero cannot spin on the RPC.
const MIN_POLL_SECONDS: f64 = 0.1;

impl Settings {
    pub fn from_env() -> Result<Self> {
        let contract = env::var("CONTRACT_ADDRESS").unwrap_or_else(|_| DEFAULT_CONTRACT.into());
        let poll_seconds: f64 = match env::var("POLL_SECONDS") {
            Ok(v) => v
                .trim()
                .parse()
                .ok()
                .filter(|s: &f64| s.is_finite())
                .with_context(|| format!("POLL_SECONDS={v}: not a number of seconds"))?,
            Err(_) => 2.0,
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
            poll: Duration::from_secs_f64(poll_seconds.max(MIN_POLL_SECONDS)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fraction of a second is a valid interval; anything but a number is not.
    #[test]
    fn poll_seconds_takes_a_fraction_and_refuses_nonsense() {
        let poll = |v: &str| {
            // SAFETY: single-threaded test, and every case sets the variable before reading it.
            unsafe { env::set_var("POLL_SECONDS", v) };
            Settings::from_env().map(|s| s.poll)
        };
        assert_eq!(poll("0.2").unwrap(), Duration::from_millis(200));
        assert_eq!(poll(" 3 ").unwrap(), Duration::from_secs(3));
        assert_eq!(
            poll("0").unwrap(),
            Duration::from_secs_f64(MIN_POLL_SECONDS)
        );
        assert!(poll("soon").is_err());
        unsafe { env::remove_var("POLL_SECONDS") };
    }
}
