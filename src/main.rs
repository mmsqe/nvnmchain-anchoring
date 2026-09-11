use std::sync::Arc;

use anyhow::Result;
use tracing::info;

use nvnmchain_anchoring::config::Settings;
use nvnmchain_anchoring::index::Index;
use nvnmchain_anchoring::rpc::Rpc;
use nvnmchain_anchoring::{service, sync};

const USAGE: &str = "usage: nvnmchain-anchoring [serve|sync]";

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
    if !matches!(command.as_str(), "serve" | "sync") {
        eprintln!("unknown command `{command}`\n{USAGE}");
        std::process::exit(2);
    }

    let cfg = Settings::from_env()?;
    let rpc = Rpc::new(&cfg.rpc_url)?;
    let index = Arc::new(Index::open(&cfg.db_path)?);
    info!(
        "rpc={} contract={} db={}",
        cfg.rpc_url, cfg.contract, cfg.db_path
    );

    // Caught up before serving, so a search never answers from half an index.
    let added = sync::catch_up(&rpc, cfg.contract, &index).await?;
    info!(
        "registries indexed: {added}, through id {}",
        index.last_id()?
    );
    if command == "sync" {
        return Ok(());
    }

    let following = index.clone();
    tokio::spawn(async move { sync::follow(rpc, cfg.contract, &following, cfg.poll).await });
    service::serve(index, &cfg.bind).await
}
