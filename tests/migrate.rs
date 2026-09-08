//! Planning the legacy corpus: what each step will send, and what is refused
//! before anything is sent at all.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use flate2::write::GzEncoder;
use flate2::Compression;
use nvnmchain_anchoring::migrate::{
    add_record_call, addressed, deploy_registry_call, leaves_call, merkle_root, mmr_chunks,
    mmr_root, plan, reconcile, update_status_call, Held, Kind, Manifest, Mode, Options,
    RegistryImport, Root,
};
use sha2::{Digest, Sha256};

/// An export staged on disk, as the module's loader also required. Named per
/// test so two can run at once.
struct Export {
    dir: PathBuf,
}

impl Export {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("anchoring-migrate-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("staging dir");
        Self { dir }
    }

    /// Writes `lines` as a tranche file and returns its manifest entry.
    fn tranche(&self, registry: &str, lines: &[String]) -> serde_json::Value {
        let content = lines.join("\n") + "\n";
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(content.as_bytes()).expect("compress");
        let gz = gz.finish().expect("compress");

        let file = format!("{registry}.jsonl.gz");
        std::fs::write(self.dir.join(&file), &gz).expect("write tranche");
        serde_json::json!({
            "registry": registry,
            "records": lines.len(),
            "file": file,
            "tranche": 1,
            "sha256_gz": hex::encode(Sha256::digest(&gz)),
            "sha256_uncompressed": hex::encode(Sha256::digest(content.as_bytes())),
        })
    }

    fn opts(&self, threshold: usize) -> Options {
        Options {
            threshold,
            root: Root::Merkle,
            export_dir: self.dir.clone(),
            uri_base: "https://export.example/legacy".into(),
            skip_status: None,
        }
    }
}

impl Drop for Export {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn record(registry: &str, checksum: &str, uri: &str, status: &str) -> String {
    serde_json::json!({
        "registry": registry,
        "uri": uri,
        "checksum": checksum,
        "checksumAlgo": "sha256",
        "metadata": "{}",
        "status": status,
    })
    .to_string()
}

fn registries(names: &[&str]) -> Vec<RegistryImport> {
    serde_json::from_value(serde_json::json!(names
        .iter()
        .map(|n| serde_json::json!({"name": n, "description": "", "metadata": "{}"}))
        .collect::<Vec<_>>()))
    .expect("registries")
}

fn manifest(files: Vec<serde_json::Value>) -> Manifest {
    let records: usize = files
        .iter()
        .map(|f| f["records"].as_u64().unwrap() as usize)
        .sum();
    serde_json::from_value(serde_json::json!({
        "totals": {"registries": files.len(), "records": records},
        "files": files,
    }))
    .expect("manifest")
}

#[test]
fn the_mmr_is_hashed_as_the_precompile_hashes_it() {
    // Pinned in Python with keccak: three lines' root, and the selector the call carries.
    let lines = [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
    let chunks = mmr_chunks(&lines);
    assert_eq!(
        chunks.iter().map(|(h, _)| *h).collect::<Vec<_>>(),
        [1, 0],
        "a pair, then one"
    );
    assert_eq!(
        mmr_root(&chunks),
        "0xff324afacd068a01dda359c03c1589d703eb1a70b26a7aa3c6526e965e0e67c2"
    );
    assert!(
        leaves_call(&chunks, "{}").starts_with("0x7150c2c6"),
        "appendLeaves' selector"
    );
    assert_eq!(
        mmr_root(&[]),
        format!("0x{}", "00".repeat(32)),
        "empty is zero, as the root is"
    );
    // The whole call, against an independent encoder: two chunks as pairs, then the metadata.
    let (h1, r1) = chunks[0];
    let (h0, r0) = chunks[1];
    assert_eq!(
        leaves_call(&chunks, "{}"),
        format!(
            "0x7150c2c6\
             {:064x}{:064x}\
             {:064x}{}{:064x}{}{:064x}\
             {:064x}{:0<64}",
            0x40,
            0xe0,
            2,
            hex::encode(r1),
            h1,
            hex::encode(r0),
            h0,
            2,
            hex::encode("{}"),
        )
    );
}

#[test]
fn a_registry_loads_as_leaves_under_root_mmr() {
    let export = Export::new("leaves");
    let lines: Vec<String> = ["aaa", "bbb", "ccc", "ddd", "eee"]
        .iter()
        .map(|c| record("r", c, "ipfs://x", "Active"))
        .collect();
    let file = export.tranche("r", &lines);
    let opts = Options {
        root: Root::Mmr,
        ..export.opts(0)
    };
    let planned = plan(&registries(&["r"]), &manifest(vec![file]), &opts).expect("a plan");

    assert_eq!(planned.registries[0].mode, Mode::Leaves);
    let kinds: Vec<_> = planned.steps.iter().map(|s| s.kind).collect();
    assert_eq!(
        kinds,
        [Kind::Deploy, Kind::Leaves],
        "one call for the whole file"
    );
    let bytes: Vec<Vec<u8>> = lines.iter().map(|l| l.as_bytes().to_vec()).collect();
    let chunks = mmr_chunks(&bytes);
    assert_eq!(
        chunks.iter().map(|(h, _)| *h).collect::<Vec<_>>(),
        [2, 0],
        "five rows: four, then one"
    );
    assert_eq!(
        planned.steps[1].checksum,
        Some(mmr_root(&chunks)),
        "what the step leaves behind"
    );
    assert!(
        planned.steps[1].data.starts_with("0x7150c2c6"),
        "an appendLeaves call"
    );
}

#[test]
fn a_status_the_caller_leaves_out_is_not_planned() {
    // Left out, the record still lands and any other status is planned as before.
    let export = Export::new("skip-status");
    let file = export.tranche(
        "r",
        &[
            record("r", "aaa", "ipfs://a", "Active"),
            record("r", "bbb", "ipfs://b", "approved"),
            record("r", "ccc", "ipfs://c", ""),
        ],
    );
    let opts = Options {
        skip_status: Some("Active".into()),
        ..export.opts(10)
    };
    let steps = plan(&registries(&["r"]), &manifest(vec![file]), &opts)
        .expect("a plan")
        .steps;
    let planned: Vec<(Kind, Option<&str>)> = steps
        .iter()
        .map(|s| (s.kind, s.status.as_deref()))
        .collect();
    assert_eq!(
        planned,
        [
            (Kind::Deploy, None),
            (Kind::Record, None),
            (Kind::Record, None),
            (Kind::Status, Some("approved")),
            (Kind::Record, None),
        ],
        "the Active status is left out; the other is planned"
    );
}

#[test]
fn a_leaves_step_is_judged_by_what_the_registry_was_first_loaded_with() {
    let export = Export::new("leaves-reconcile");
    let file = export.tranche(
        "r",
        &[
            record("r", "aaa", "ipfs://a", ""),
            record("r", "bbb", "ipfs://b", ""),
        ],
    );
    let opts = Options {
        root: Root::Mmr,
        ..export.opts(0)
    };
    let steps = plan(&registries(&["r"]), &manifest(vec![file]), &opts)
        .expect("a plan")
        .steps;
    let planned_root = steps[1].checksum.clone().unwrap();
    let held: BTreeMap<String, Held> = [("r".to_string(), Some(vec![]))].into(); // deployed, empty

    // `roots` is what each registry's first append left.
    let judge = |root: Option<&str>| {
        let roots: BTreeMap<String, String> = root
            .map(|r| ("r".to_string(), r.to_string()))
            .into_iter()
            .collect();
        reconcile(&steps, &held, &roots)
    };
    let owed = judge(None);
    assert_eq!(
        owed.remaining.iter().map(|s| s.kind).collect::<Vec<_>>(),
        [Kind::Leaves],
        "no MMR yet: owed"
    );
    assert!(owed.divergences.is_empty());

    let landed = judge(Some(&planned_root));
    assert!(
        landed.remaining.is_empty() && landed.divergences.is_empty(),
        "the first append left the planned root"
    );

    let other = judge(Some("0xdead"));
    assert!(
        other.remaining.is_empty(),
        "the chunks were cut for an empty tree; sending them now would only be refused"
    );
    assert!(
        other.divergences[0].detail.contains("first append"),
        "{}",
        other.divergences[0].detail
    );
}

#[test]
fn the_calldata_is_what_the_contracts_take() {
    // Against an independent encoder, because everything else here only checks
    // that the plan is self-consistent -- a wrong selector would plan a corpus
    // onto a function that does not exist.
    assert_eq!(
        deploy_registry_call("us-ca1", "First Circuit", r#"{"court":"ca1"}"#),
        "0x09f85c40\
         0000000000000000000000000000000000000000000000000000000000000060\
         00000000000000000000000000000000000000000000000000000000000000a0\
         00000000000000000000000000000000000000000000000000000000000000e0\
         0000000000000000000000000000000000000000000000000000000000000006\
         75732d6361310000000000000000000000000000000000000000000000000000\
         000000000000000000000000000000000000000000000000000000000000000d\
         4669727374204369726375697400000000000000000000000000000000000000\
         000000000000000000000000000000000000000000000000000000000000000f\
         7b22636f757274223a22636131227d0000000000000000000000000000000000"
    );
    assert_eq!(
        add_record_call("ipfs://cid", "0xabc", "sha256", "{}", 0, ""),
        "0x430d86ad\
         00000000000000000000000000000000000000000000000000000000000000c0\
         0000000000000000000000000000000000000000000000000000000000000100\
         0000000000000000000000000000000000000000000000000000000000000140\
         0000000000000000000000000000000000000000000000000000000000000180\
         0000000000000000000000000000000000000000000000000000000000000000\
         00000000000000000000000000000000000000000000000000000000000001c0\
         000000000000000000000000000000000000000000000000000000000000000a\
         697066733a2f2f63696400000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000005\
         3078616263000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000006\
         7368613235360000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000002\
         7b7d000000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000000"
    );
    // The one call with a static argument between two dynamic ones.
    assert_eq!(
        update_status_call("0xabc", 2, "approved"),
        "0xb0c12de5\
         0000000000000000000000000000000000000000000000000000000000000060\
         0000000000000000000000000000000000000000000000000000000000000002\
         00000000000000000000000000000000000000000000000000000000000000a0\
         0000000000000000000000000000000000000000000000000000000000000005\
         3078616263000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000008\
         617070726f766564000000000000000000000000000000000000000000000000"
    );
}

#[test]
fn the_merkle_tree_is_the_one_the_metadata_describes() {
    // keccak256(line) leaves, keccak256(left || right) nodes, odd promoted --
    // spelled out here because a proof written against the metadata's
    // description has to land on the same root.
    let lines: Vec<Vec<u8>> = [r#"{"a":1}"#, r#"{"b":2}"#, r#"{"c":3}"#]
        .iter()
        .map(|l| l.as_bytes().to_vec())
        .collect();
    assert_eq!(
        merkle_root(&lines),
        "0x032e97fc9c62348c16dba15b3fc9c1e8fffb6b479715e2692c9187da3e28391e"
    );
    // One leaf is its own root, and nothing is not a tree.
    assert_eq!(
        merkle_root(&lines[..1]),
        nvnmchain_anchoring::eth::keccak_hex(b"{\"a\":1}")
    );
    assert_eq!(merkle_root(&[]), format!("0x{}", "00".repeat(32)));
}

#[test]
fn the_threshold_splits_the_corpus() {
    let export = Export::new("threshold");
    let small = export.tranche(
        "small",
        &[
            record("small", "aaa", "ipfs://a", ""),
            record("small", "aaa", "ipfs://a2", "approved"),
            record("small", "bbb", "ipfs://b", ""),
        ],
    );
    let large = export.tranche(
        "large",
        &[
            record("large", "ccc", "ipfs://c", ""),
            record("large", "ddd", "ipfs://d", ""),
            record("large", "eee", "ipfs://e", ""),
            record("large", "fff", "ipfs://f", ""),
        ],
    );

    let planned = plan(
        &registries(&["small", "large"]),
        &manifest(vec![small, large]),
        &export.opts(3),
    )
    .expect("a plan");

    let modes: Vec<_> = planned
        .registries
        .iter()
        .map(|r| (r.registry.as_str(), r.mode))
        .collect();
    assert_eq!(modes, [("small", Mode::Record), ("large", Mode::Root)]);

    let kinds: Vec<_> = planned
        .steps
        .iter()
        .map(|s| (s.kind, s.registry.as_str()))
        .collect();
    assert_eq!(
        kinds,
        [
            (Kind::Deploy, "small"),
            (Kind::Record, "small"), // aaa v1
            (Kind::Record, "small"), // aaa v2
            (Kind::Status, "small"), // ...which carried a status
            (Kind::Record, "small"), // bbb v1
            (Kind::Deploy, "large"),
            (Kind::Record, "large"), // the whole file, as one root
        ],
        "a rooted registry is one record however many rows it holds"
    );

    // Versions run per checksum in file order, which is what makes the derived
    // numbering reproduce the module's record ids.
    let versions: Vec<_> = planned
        .steps
        .iter()
        .filter(|s| s.kind == Kind::Record && s.registry == "small")
        .map(|s| (s.checksum.clone().unwrap(), s.version.unwrap()))
        .collect();
    assert_eq!(
        versions,
        [("aaa".into(), 1u64), ("aaa".into(), 2), ("bbb".into(), 1)]
    );

    // The status step names the version it belongs to, not the newest one.
    let status = planned
        .steps
        .iter()
        .find(|s| s.kind == Kind::Status)
        .unwrap();
    assert_eq!(status.version, Some(2));
    assert_eq!(status.data, update_status_call("aaa", 2, "approved"));

    // Steps are numbered from one, in order, so a run can resume by number.
    assert!(planned
        .steps
        .iter()
        .enumerate()
        .all(|(i, s)| s.step == i + 1));
}

#[test]
fn a_file_that_is_not_the_one_the_manifest_describes_is_refused() {
    let export = Export::new("digest");
    let entry = export.tranche("small", &[record("small", "aaa", "ipfs://a", "")]);
    std::fs::write(export.dir.join("small.jsonl.gz"), b"not that file").expect("overwrite");

    let refused = plan(
        &registries(&["small"]),
        &manifest(vec![entry]),
        &export.opts(10),
    );
    let message = refused.expect_err("a digest mismatch").to_string();
    assert!(message.contains("sha256_gz"), "{message}");
}

#[test]
fn an_export_that_does_not_add_up_is_refused() {
    // Both the module's loader and this one check the totals before writing
    // anything: an export missing a tranche plans a corpus nobody exported.
    let export = Export::new("totals");
    let entry = export.tranche("small", &[record("small", "aaa", "ipfs://a", "")]);
    let mut short = manifest(vec![entry]);
    short.totals.records = 2;

    let refused = plan(&registries(&["small"]), &short, &export.opts(10));
    assert!(refused.expect_err("totals").to_string().contains("totals"));
}

#[test]
fn a_duplicate_registry_name_is_refused() {
    // Records are keyed to a registry by name, so two registries sharing one
    // would hand the first one's records to the second. Names are no longer
    // unique on chain, which is exactly why this is checked here.
    let export = Export::new("duplicate");
    let entry = export.tranche("same", &[record("same", "aaa", "ipfs://a", "")]);
    let mut both = manifest(vec![entry]);
    both.totals.registries = 2;

    let refused = plan(&registries(&["same", "same"]), &both, &export.opts(10));
    assert!(refused
        .expect_err("duplicate")
        .to_string()
        .contains("duplicate"));
}

/// One record as the listing serves it, at its newest version.
fn served(
    checksum: &str,
    version: u64,
    status: Option<&str>,
) -> nvnmchain_anchoring::registry::Record {
    serde_json::from_value(serde_json::json!({
        "number": 1,
        "checksum_hash": "0x00",
        "version": version,
        "uri": "ipfs://a",
        "checksum": checksum,
        "checksum_algo": "sha256",
        "metadata": "{}",
        "category": 0,
        "data_pointer": "",
        "author": "0x0000000000000000000000000000000000C0FFEE",
        "timestamp": 0,
        "status": status,
    }))
    .expect("a record")
}

fn plan_of(export: &Export, lines: &[String]) -> Vec<nvnmchain_anchoring::migrate::Step> {
    let entry = export.tranche("r", lines);
    plan(
        &registries(&["r"]),
        &manifest(vec![entry]),
        &export.opts(1000),
    )
    .expect("a plan")
    .steps
}

#[test]
fn a_step_that_did_not_land_is_owed_and_one_sent_twice_is_a_divergence() {
    let export = Export::new("compare");
    let steps = plan_of(
        &export,
        &[
            record("r", "aaa", "ipfs://a", ""),
            record("r", "aaa", "ipfs://a2", "approved"),
            record("r", "bbb", "ipfs://b", ""),
        ],
    );
    let against = |records: Vec<nvnmchain_anchoring::registry::Record>| {
        reconcile(
            &steps,
            &BTreeMap::from([("r".to_string(), Some(records))]),
            &BTreeMap::new(),
        )
    };
    let landed = || vec![served("aaa", 2, Some("approved")), served("bbb", 1, None)];

    let clean = against(landed());
    assert!(
        clean.divergences.is_empty() && clean.remaining.is_empty(),
        "{clean:?}"
    );

    // Not landed yet is the normal mid-run state, so it is owed rather than wrong.
    let missing = against(vec![served("aaa", 2, Some("approved"))]);
    assert!(missing.divergences.is_empty(), "{missing:?}");
    assert_eq!(
        missing
            .remaining
            .iter()
            .filter_map(|s| s.checksum.as_deref())
            .collect::<Vec<_>>(),
        ["bbb"]
    );

    // The trap that resuming by step number rather than by chain state walks into:
    // `addRecord` appends every time, so a replayed step leaves a version too many.
    let twice = against(vec![served("aaa", 3, None), served("bbb", 1, None)]);
    assert!(
        twice
            .divergences
            .iter()
            .any(|d| d.detail.contains("a step sent twice")),
        "{twice:?}"
    );

    // A status that differs is closed by sending the status step again.
    let wrong = against(vec![
        served("aaa", 2, Some("redacted")),
        served("bbb", 1, None),
    ]);
    assert!(wrong.divergences.is_empty(), "{wrong:?}");
    assert!(
        wrong.remaining.iter().any(|s| s.kind == Kind::Status),
        "{wrong:?}"
    );

    let extra = against([landed(), vec![served("ccc", 1, None)]].concat());
    assert!(extra.divergences[0]
        .detail
        .contains("the plan does not write it"));
}

#[test]
fn what_is_left_to_send_is_decided_against_the_chain() {
    let export = Export::new("remaining");
    let steps = plan_of(
        &export,
        &[
            record("r", "aaa", "ipfs://a", ""),
            record("r", "aaa", "ipfs://a2", "approved"),
            record("r", "bbb", "ipfs://b", ""),
        ],
    );
    let left = |held: Held| {
        reconcile(
            &steps,
            &BTreeMap::from([("r".to_string(), held)]),
            &BTreeMap::new(),
        )
        .remaining
        .iter()
        .map(|s| (s.kind, s.checksum.clone(), s.version))
        .collect::<Vec<_>>()
    };

    // Nothing deployed: the whole plan, deploy included.
    assert_eq!(left(None).len(), steps.len());

    // Deployed and empty: everything but the deploy.
    assert_eq!(
        left(Some(vec![])),
        [
            (Kind::Record, Some("aaa".into()), Some(1)),
            (Kind::Record, Some("aaa".into()), Some(2)),
            (Kind::Status, Some("aaa".into()), Some(2)),
            (Kind::Record, Some("bbb".into()), Some(1)),
        ]
    );

    // Stopped after `aaa` v1: its v2 and the rest, and *not* v1 again -- which is
    // the whole point, since sending that again leaves a version too many.
    assert_eq!(
        left(Some(vec![served("aaa", 1, None)])),
        [
            (Kind::Record, Some("aaa".into()), Some(2)),
            (Kind::Status, Some("aaa".into()), Some(2)),
            (Kind::Record, Some("bbb".into()), Some(1)),
        ]
    );

    // A run that landed has nothing left, and one whose status did not has that.
    assert!(left(Some(vec![
        served("aaa", 2, Some("approved")),
        served("bbb", 1, None)
    ]))
    .is_empty());
    assert_eq!(
        left(Some(vec![served("aaa", 2, None), served("bbb", 1, None)])),
        [(Kind::Status, Some("aaa".into()), Some(2))]
    );

    // A status names the version it sits after, so a record past that version is
    // one whose status step has already gone by -- not one to send again.
    assert!(
        left(Some(vec![served("aaa", 3, None), served("bbb", 1, None)]))
            .iter()
            .all(|(kind, ..)| *kind != Kind::Status)
    );
}

#[test]
fn what_is_handed_back_names_its_target_where_that_is_knowable() {
    let export = Export::new("addressed");
    let steps = plan_of(&export, &[record("r", "aaa", "ipfs://a", "")]);
    let mut other = steps.clone();
    for step in &mut other {
        step.registry = "s".into(); // the same shape under a registry that has not landed
    }
    let all = [steps, other].concat();

    let landed = BTreeMap::from([("r", "0xR")]);
    let targets: Vec<Option<String>> = addressed(all, "0xF", &landed)
        .into_iter()
        .map(|s| s.to)
        .collect();

    // r's deploy and record are addressed; s's deploy is, its record is not -- the
    // address it needs is what that deploy will announce.
    assert_eq!(
        targets,
        [
            Some("0xF".into()),
            Some("0xR".into()),
            Some("0xF".into()),
            None,
        ]
    );
}
