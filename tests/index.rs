use alloy_primitives::Address;

use nvnmchain_anchoring::contract::Registry;
use nvnmchain_anchoring::index::{Index, Mode};

fn registry(id: u64, name: &str) -> Registry {
    Registry {
        id,
        name: name.into(),
        description: format!("about {name}"),
        creator: "nvnm14a3em3mr9mvta9ccgk80wn0dxgzt5lkt2r8trx".into(),
        createdAt: "2026-07-30 15:04:00.973906311 +0000 UTC".into(),
        metadata: "{}".into(),
    }
}

fn ids(index: &Index, mode: Mode, name: &str) -> Vec<u64> {
    let found = index.search(mode, name, 50, 0).unwrap();
    found.iter().map(|r| r.id).collect()
}

fn fixture() -> Index {
    let index = Index::open(":memory:").unwrap();
    index
        .insert(&[
            registry(1, "Alpha Fund"),
            // Names are not unique.
            registry(2, "alpha fund"),
            registry(3, "Beta Alpha"),
            registry(4, "Fund of Funds"),
            registry(5, "50% off_sale"),
            registry(6, "Crème Brûlée"),
        ])
        .unwrap();
    index
}

#[test]
fn exact_ignores_case_and_finds_every_registry_by_that_name() {
    let index = fixture();
    assert_eq!(ids(&index, Mode::Exact, "ALPHA FUND"), [1, 2]);
    assert!(ids(&index, Mode::Exact, "alpha").is_empty());
}

#[test]
fn prefix_suffix_and_contains_match_where_they_say() {
    let index = fixture();
    assert_eq!(ids(&index, Mode::Prefix, "alpha"), [1, 2]);
    assert_eq!(ids(&index, Mode::Suffix, "alpha"), [3]);
    assert_eq!(ids(&index, Mode::Suffix, "FUNDS"), [4]);
    assert_eq!(ids(&index, Mode::Contains, "fund"), [1, 2, 4]);
}

#[test]
fn a_wildcard_in_the_query_matches_only_itself() {
    let index = fixture();
    assert_eq!(ids(&index, Mode::Contains, "%"), [5]);
    assert_eq!(ids(&index, Mode::Contains, "_"), [5]);
    assert_eq!(ids(&index, Mode::Prefix, "50%"), [5]);
    // "f_n" would match "fun" if `_` were a wildcard.
    assert!(ids(&index, Mode::Contains, "f_n").is_empty());
    assert!(ids(&index, Mode::Prefix, "%").is_empty());
}

#[test]
fn suffix_reverses_by_character_so_multibyte_names_match() {
    let index = fixture();
    assert_eq!(ids(&index, Mode::Suffix, "BRÛLÉE"), [6]);
    assert_eq!(ids(&index, Mode::Suffix, "lée"), [6]);
}

#[test]
fn pages_by_id() {
    let index = Index::open(":memory:").unwrap();
    let all: Vec<Registry> = (1..=120)
        .map(|id| registry(id, &format!("Registry {id}")))
        .collect();
    index.insert(&all).unwrap();

    let page = index.search(Mode::Prefix, "registry", 50, 100).unwrap();
    let got: Vec<u64> = page.iter().map(|r| r.id).collect();
    assert_eq!(got, (101..=120).collect::<Vec<_>>());
    assert!(index
        .search(Mode::Prefix, "registry", 50, 120)
        .unwrap()
        .is_empty());
    // Past what SQLite can count to is past the end, not an error.
    assert!(index
        .search(Mode::Prefix, "registry", u64::MAX, u64::MAX)
        .unwrap()
        .is_empty());
}

/// Ids run from 1 on every chain, so only what the index recorded tells one chain's from another's.
#[test]
fn an_index_serves_the_one_chain_and_contract_it_was_built_from() {
    let index = Index::open(":memory:").unwrap();
    let (contract, other) = (Address::repeat_byte(0x0a), Address::repeat_byte(0x0b));
    index.bind(1, contract).unwrap();
    index.bind(1, contract).unwrap();
    index.insert(&[registry(1, "One")]).unwrap();

    let err = index.bind(2, contract).unwrap_err().to_string();
    assert_eq!(
        err,
        format!("the index is from chain 1 contract {contract}, not chain 2 contract {contract}: delete it to rebuild")
    );
    assert!(index.bind(1, other).is_err());

    // Built before the index recorded its chain: refused rather than claimed.
    let legacy = Index::open(":memory:").unwrap();
    legacy.insert(&[registry(1, "One")]).unwrap();
    let err = legacy.bind(1, contract).unwrap_err().to_string();
    assert_eq!(
        err,
        "the index predates recording its chain: delete it to rebuild"
    );
}

#[test]
fn inserting_a_page_again_changes_nothing() {
    let index = Index::open(":memory:").unwrap();
    assert_eq!(index.last_id().unwrap(), 0);
    let page = [registry(1, "One"), registry(2, "Two")];
    index.insert(&page).unwrap();
    index.insert(&page).unwrap();
    assert_eq!(index.last_id().unwrap(), 2);
    assert_eq!(ids(&index, Mode::Contains, "o"), [1, 2]);
    let one = &index.search(Mode::Exact, "one", 50, 0).unwrap()[0];
    assert_eq!(one, &page[0]);
}
