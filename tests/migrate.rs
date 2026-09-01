//! Planning the legacy corpus: what each step will send, and what is refused
//! before anything is sent at all.

use std::io::Write;
use std::path::PathBuf;

use flate2::write::GzEncoder;
use flate2::Compression;
use nvnmchain_anchoring::migrate::{
    add_record_call, deploy_registry_call, merkle_root, plan, update_status_call, Kind, Manifest,
    Mode, Options, RegistryImport, Root,
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
