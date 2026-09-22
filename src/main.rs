use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::info;

use nvnmchain_anchoring::config::Settings;
use nvnmchain_anchoring::rpc::Rpc;
use nvnmchain_anchoring::service::{self, App};

const USAGE: &str = "usage: nvnmchain-anchoring [serve]";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nvnmchain_anchoring=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let command = std::env::args().nth(1).unwrap_or_else(|| "serve".into());
    if command != "serve" {
        eprintln!("unknown command `{command}`\n{USAGE}");
        std::process::exit(2);
    }

    let cfg = Settings::from_env();
    let rpc = Arc::new(Rpc::new(&cfg.rpc_url)?);
    // Asked before listening, so a node without the index says so here and not per request.
    let status = rpc.status().await.with_context(|| {
        format!(
            "{} does not answer anchoring_nameIndexStatus; start it with --anchoring.name-index",
            cfg.rpc_url
        )
    })?;
    info!(
        "rpc={} indexed through id {} of {}",
        cfg.rpc_url, status.last_id, status.registry_count
    );

    service::serve(App { rpc }, &cfg.bind).await
}
