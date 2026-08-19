use anyhow::Result;
use tracing::info;

use nvnmchain_anchoring::config::Settings;
use nvnmchain_anchoring::registry::NameFilter;
use nvnmchain_anchoring::rpc::Rpc;
use nvnmchain_anchoring::tidx::Tidx;
use nvnmchain_anchoring::{audit, envelope, service};
use std::sync::Arc;

const USAGE: &str = "usage: nvnmchain-anchoring [audit|kinds|serve|\n\
     registries [--name=|--name-prefix=|--name-suffix=|--name-contains=]|\n\
     records <registry>|roles <registry>|\n\
     record <registry> <checksum>|checksum <checksum>]";

/// `--name=…` and friends, the command line's spelling of the query parameters
/// `/registries` takes. Anything else is refused rather than ignored, since a
/// mistyped filter that were dropped would list every registry and read as one
/// that matched them all.
fn name_filter(args: &[String]) -> NameFilter {
    let mut filter = NameFilter::default();
    for arg in args {
        let (flag, value) = arg.split_once('=').unwrap_or((arg.as_str(), ""));
        let field = match flag {
            "--name" => &mut filter.name,
            "--name-prefix" => &mut filter.prefix,
            "--name-suffix" => &mut filter.suffix,
            "--name-contains" => &mut filter.contains,
            other => {
                eprintln!("`{other}` is not a filter\n{USAGE}");
                std::process::exit(2);
            }
        };
        *field = Some(value.to_string());
    }
    filter
}

/// Print a projection as JSON, or say why there is none and exit non-zero.
///
/// The read half of what `nvnmchaind query anchoring …` was: the same calls
/// `serve` answers with, against tidx directly rather than through a running
/// service. The write half has no successor here and wants none — a record is an
/// EVM transaction now, so it belongs to whatever holds the key, and this process
/// holds none.
fn print(projection: Result<serde_json::Value, service::ApiError>) -> Result<()> {
    match projection {
        Ok(value) => {
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        }
        Err(err) => {
            eprintln!("{err}");
            // 2 for anything the caller could fix by asking differently, 1 for
            // this process or the index being wrong.
            std::process::exit(if err.0.is_client_error() { 2 } else { 1 });
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nvnmchain_anchoring=info".into()),
        )
        // Logs to stderr, because stdout is a projection someone pipes into `jq`.
        .with_writer(std::io::stderr)
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
        query @ ("registries" | "records" | "roles" | "record" | "checksum") => {
            let ctx = service::Ctx { tidx, cfg };
            let arg = |n: usize| {
                std::env::args().nth(n).unwrap_or_else(|| {
                    eprintln!("`{query}` needs an argument\n{USAGE}");
                    std::process::exit(2);
                })
            };
            match query {
                "registries" => {
                    let filter = name_filter(&std::env::args().skip(2).collect::<Vec<_>>());
                    print(service::deployments(&ctx, &filter).await)?
                }
                "records" => print(service::records_held(&ctx, &arg(2)).await)?,
                "roles" => print(service::roles_held(&ctx, &arg(2)).await)?,
                "record" => print(service::record_versions(&ctx, &arg(2), &arg(3)).await)?,
                // `checksum`, the only one left.
                _ => print(service::anchored_anywhere(&ctx, &arg(2)).await)?,
            }
        }
        other => {
            eprintln!("unknown command `{other}`\n{USAGE}");
            std::process::exit(2);
        }
    }
    Ok(())
}
