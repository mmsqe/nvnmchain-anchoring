use std::time::Duration;

use anyhow::{Context, Result};
use tracing::info;

use nvnmchain_anchoring::config::Settings;
use nvnmchain_anchoring::db;
use nvnmchain_anchoring::indexer::Indexer;
use nvnmchain_anchoring::rpc::Rpc;
use nvnmchain_anchoring::{audit, envelope};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nvnmchain_anchoring=info".into()),
        )
        .init();

    let cfg = Settings::from_env();
    let db = db::open(&cfg.db_path).context("open database")?;
    let indexer = Indexer {
        rpc: Rpc::new(&cfg.rpc_url)?,
        db: db.clone(),
        cfg: cfg.clone(),
    };

    info!(
        "rpc={} db={} registry={} from={}",
        cfg.rpc_url,
        cfg.db_path,
        cfg.registry_address.as_deref().unwrap_or("(none)"),
        cfg.start_block
    );

    match std::env::args().nth(1).as_deref().unwrap_or("sync") {
        "once" => {
            let (head, progress) = indexer.sync_to_head().await?;
            let total = db::count_anchored(&db::lock(&db))?;
            info!(
                "head {head}: +{} anchor(s), +{} registry event(s), {total} total",
                progress.anchored, progress.registry_events
            );
        }
        "kinds" => {
            // What this chain actually carries — the quickest way to see
            // whether a namespace is anchoring registry envelopes at all, and
            // whether they are tagged.
            let heads = db::heads(&db::lock(&db))?;
            let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
            for head in &heads {
                let name = match envelope::read_payload(&head.key, &head.metadata) {
                    envelope::Payload::Envelope(e) => {
                        format!(
                            "{} ({})",
                            e.kind,
                            if e.tagged { "tagged" } else { "untagged" }
                        )
                    }
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
            let report = audit::run(&indexer.rpc, &db).await?;
            println!("{report}");
            if !report.is_clean() {
                std::process::exit(1);
            }
        }
        _ => loop {
            // Only what this pass changed: summarising the whole index every
            // tick would cost more than the indexing does.
            let (head, progress) = indexer.sync_to_head().await?;
            if progress.anchored > 0 || progress.registry_events > 0 {
                info!(
                    "head {head}: +{} anchor(s), +{} registry event(s)",
                    progress.anchored, progress.registry_events
                );
            }
            tokio::time::sleep(Duration::from_secs_f64(cfg.poll_seconds)).await;
        },
    }
    Ok(())
}
