use anyhow::{Context, Result};
use tracing::info;

use nvnmchain_anchoring::config::Settings;
use nvnmchain_anchoring::registry::NameFilter;
use nvnmchain_anchoring::rpc::Rpc;
use nvnmchain_anchoring::tidx::Tidx;
use nvnmchain_anchoring::{audit, envelope, migrate, service};
use std::sync::Arc;

const USAGE: &str = "usage: nvnmchain-anchoring [audit|kinds|serve|\n\
     registries [--name=|--name-prefix=|--name-suffix=|--name-contains=]|\n\
     records <registry>|roles <registry>|\n\
     record <registry> <checksum>|checksum <checksum>|\n\
     migrate --registries=<file> --manifest=<file> [--export=<dir>]\n\
             [--threshold=<n>] [--root=merkle|sha256] [--uri-base=<url>]|\n\
     reconcile --plan=<file> [--remaining=<file>]]";

/// `--flag=value` off the command line, or the default.
fn flag(name: &str, default: &str) -> String {
    std::env::args()
        .find_map(|arg| arg.strip_prefix(&format!("--{name}=")).map(str::to_string))
        .unwrap_or_else(|| default.to_string())
}

fn required(command: &str, name: &str) -> String {
    let value = flag(name, "");
    if value.is_empty() {
        eprintln!("{command} needs --{name}=\n{USAGE}");
        std::process::exit(2);
    }
    value
}

/// Plan the corpus onto the registry contracts, as JSONL on stdout.
///
/// Reads no chain: it needs the export and nothing else, so it runs before the
/// settings every other command is configured by.
fn print_plan() -> Result<()> {
    let read = |name: &str| -> Result<Vec<u8>> {
        let path = required("migrate", name);
        std::fs::read(&path).with_context(|| format!("read {path}"))
    };
    let registries: Vec<migrate::RegistryImport> = serde_json::from_slice(&read("registries")?)?;
    let manifest: migrate::Manifest = serde_json::from_slice(&read("manifest")?)?;
    let opts = migrate::Options {
        threshold: flag("threshold", "0").parse().context("--threshold")?,
        root: match flag("root", "merkle").as_str() {
            "merkle" => migrate::Root::Merkle,
            "sha256" => migrate::Root::Sha256,
            other => {
                eprintln!("--root={other}: expected merkle or sha256\n{USAGE}");
                std::process::exit(2);
            }
        },
        export_dir: flag("export", ".").into(),
        uri_base: flag("uri-base", "file://export"),
    };

    let plan = migrate::plan(&registries, &manifest, &opts)?;
    for step in &plan.steps {
        println!("{}", serde_json::to_string(step)?);
    }

    let by = |mode| plan.registries.iter().filter(move |r| r.mode == mode);
    let count = |mode| (by(mode).count(), by(mode).map(|r| r.records).sum::<usize>());
    let (by_record, record_rows) = count(migrate::Mode::Record);
    let (by_root, root_rows) = count(migrate::Mode::Root);
    eprintln!(
        "{} registries: {by_record} by record ({record_rows} records), \
         {by_root} by root ({root_rows} records)\n\
         {} steps, ~{:.1}e9 gas",
        plan.registries.len(),
        plan.steps.len(),
        plan.gas() as f64 / 1e9,
    );
    Ok(())
}

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

    // Planning reads an export, not a chain, so it runs before the settings.
    if std::env::args().nth(1).as_deref() == Some("migrate") {
        return print_plan();
    }

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
            // whether a namespace is appending registry envelopes at all.
            let leaves = tidx.leaves(tidx.coverage().await?.tip_num).await?;
            let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
            for leaf in &leaves {
                let name = match envelope::read_payload(&leaf.metadata) {
                    envelope::Payload::Envelope(e) => e.kind.to_string(),
                    envelope::Payload::Json(_) => "json".into(),
                    envelope::Payload::Text(_) => "text".into(),
                    envelope::Payload::Opaque => "opaque".into(),
                };
                *counts.entry(name).or_default() += 1;
            }
            println!("{} leaf(s):", leaves.len());
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
        "reconcile" => {
            let ctx = service::Ctx { tidx, cfg };
            let path = required("reconcile", "plan");
            let plan = std::fs::read_to_string(&path).with_context(|| format!("read {path}"))?;
            let report = migrate::against_chain(&ctx, &plan).await?;
            // `--remaining` writes the steps still owed, which is how a stopped run
            // resumes: by chain state, never by count. Empty when nothing is, so a
            // shell loop can test the file rather than parse it.
            let resume = flag("remaining", "");
            if !resume.is_empty() {
                let lines: String = report
                    .remaining
                    .iter()
                    .map(|step| serde_json::to_string(step).map(|line| line + "\n"))
                    .collect::<Result<_, _>>()?;
                std::fs::write(&resume, lines).with_context(|| format!("write {resume}"))?;
            }
            eprintln!("{} step(s) still to send", report.remaining.len());
            // Steps still owed are not a failure: sending them is the fix. Exit 1 is
            // for what sending cannot fix, which is what a human has to look at.
            let answer = serde_json::json!({
                "divergences": report.divergences,
                "remaining": report.remaining.len(),
            });
            println!("{}", serde_json::to_string_pretty(&answer)?);
            if !report.divergences.is_empty() {
                eprintln!("{} divergence(s)", report.divergences.len());
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
