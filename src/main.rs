use anyhow::Result;
use tracing::info;

use nvnmchain_anchoring::config::Settings;
use nvnmchain_anchoring::rpc::Rpc;
use nvnmchain_anchoring::tidx::Tidx;
use nvnmchain_anchoring::{audit, envelope, service};
use std::sync::Arc;

const USAGE: &str = "usage: nvnmchain-anchoring [audit|kinds|serve]";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nvnmchain_anchoring=info".into()),
        )
        .init();

    let cfg = Settings::from_env()?;
    let rpc = Rpc::new(&cfg.rpc_url)?;
    let tidx = Tidx::with_page(&cfg.tidx_url, cfg.chain_id, cfg.engine, cfg.page_size)?;

    info!(
        "rpc={} tidx={} chain={} engine={}",
        cfg.rpc_url,
        cfg.tidx_url,
        cfg.chain_id,
        cfg.engine.as_param()
    );

    match std::env::args().nth(1).as_deref().unwrap_or("audit") {
        "kinds" => {
            // What this chain actually carries — the quickest way to see
            // whether a namespace is anchoring registry envelopes at all.
            let heads = tidx.heads(tidx.coverage().await?.tip_num).await?;
            let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
            for head in &heads {
                let name = match envelope::read_payload(&head.key, &head.metadata) {
                    envelope::Payload::Envelope(e) => e.kind.to_string(),
                    envelope::Payload::Json(_) => "json".into(),
                    envelope::Payload::Text(_) => "text".into(),
                    envelope::Payload::Opaque => "opaque".into(),
                };
                *counts.entry(name).or_default() += 1;
            }
            println!("{} head(s):", heads.len());
            for (kind, count) in counts {
                println!("  {count:>5}  {kind}");
            }
        }
        "audit" => {
            let report = audit::run(&rpc, &tidx, cfg.first_block).await?;
            println!("{report}");
            if !report.is_clean() {
                std::process::exit(1);
            }
        }
        "serve" => {
            let bind = cfg.bind.clone();
            service::serve(Arc::new(service::Ctx { tidx, cfg }), &bind).await?;
        }
        other => {
            eprintln!("unknown command `{other}`\n{USAGE}");
            std::process::exit(2);
        }
    }
    Ok(())
}
