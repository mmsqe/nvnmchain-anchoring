//! The precompile's Merkle Mountain Range, as this crate folds it.
//!
//! The same hashing as `crates/precompiles/src/anchoring` and the contracts'
//! `MMR.sol`, pinned there by sixteen roots: a leaf is `keccak256("leaf" ‖ c)`,
//! a merge `keccak256("merge" ‖ l ‖ r)`, and the root bags the peaks highest
//! first with `keccak256("bag" ‖ acc ‖ peak)`. The audit replays a namespace's
//! appends through this to the root the chain holds; the migrator cuts a file
//! into the chunks one `appendLeaves` takes.

use anyhow::{bail, Context, Result};

use crate::eth::keccak256;

pub fn hash_leaf(commitment: &[u8; 32]) -> [u8; 32] {
    keccak256(&[b"leaf".as_slice(), commitment].concat())
}

pub fn hash_merge(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    keccak256(&[b"merge".as_slice(), left, right].concat())
}

/// The peaks bagged from the highest down; zero when there are none.
pub fn bag(peaks: &[[u8; 32]]) -> [u8; 32] {
    let Some((first, rest)) = peaks.split_first() else {
        return [0u8; 32];
    };
    rest.iter().fold(*first, |acc, peak| {
        keccak256(&[b"bag".as_slice(), &acc, peak].concat())
    })
}

/// One namespace's MMR: the leaf count and the peaks, highest first — what the
/// precompile keeps, and what a proof is checked against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mmr {
    pub count: u64,
    pub peaks: Vec<[u8; 32]>,
}

impl Mmr {
    /// Merges `node`, a perfect subtree of `height`, at the low end, carrying
    /// through every peak of consecutive height. A chunk of height `h` merges
    /// only when the count is a multiple of `2^h`, as the precompile insists.
    pub fn push(&mut self, height: u8, node: [u8; 32]) -> Result<()> {
        let size = 1u64
            .checked_shl(u32::from(height))
            .with_context(|| format!("a chunk of height {height} does not fit"))?;
        if self.count & (size - 1) != 0 {
            bail!(
                "a chunk of height {height} at count {}, which is not a multiple of {size}",
                self.count
            );
        }
        // Settled before any peak moves, so a refused push changes nothing.
        let count = self
            .count
            .checked_add(size)
            .with_context(|| format!("a chunk of height {height} overflows the count"))?;
        let mut node = node;
        let mut height = u32::from(height);
        while self.count.checked_shr(height).unwrap_or(0) & 1 == 1 {
            let peak = self
                .peaks
                .pop()
                .context("a peak per set bit of the count")?;
            node = hash_merge(&peak, &node);
            height += 1;
        }
        self.peaks.push(node);
        self.count = count;
        Ok(())
    }

    /// One leaf.
    pub fn append(&mut self, commitment: &[u8; 32]) -> Result<()> {
        self.push(0, hash_leaf(commitment))
    }

    pub fn root(&self) -> [u8; 32] {
        bag(&self.peaks)
    }
}

/// The perfect subtree covering leaf `index` in a tree of `count` leaves: where it
/// starts, and its height. Peaks align to leaf positions, so this walks the set
/// bits of the count from the high end.
fn peak_of(count: u64, index: u64) -> (u64, u32) {
    let mut start = 0;
    for h in (0..u64::BITS).rev() {
        if count >> h & 1 == 0 {
            continue;
        }
        if index < start + (1 << h) {
            return (start, h);
        }
        start += 1 << h;
    }
    (start, 0)
}

/// An inclusion proof for the leaf at `index`: the siblings up to its peak, lowest
/// first — what `MMRVerifier.verify` takes beside the peaks and the count.
///
/// Over the commitments a batch was cut from, since its rows never reached the
/// chain one at a time. The root the chain holds is the commitment to that file,
/// so this proves a leaf at a position against a root the chain agrees with.
pub fn proof(commitments: &[[u8; 32]], index: u64) -> Result<Vec<[u8; 32]>> {
    let count = commitments.len() as u64;
    if index >= count {
        bail!("leaf {index} is past the {count} this was cut from");
    }
    let (start, height) = peak_of(count, index);
    let (start, size) = (start as usize, 1usize << height);
    let mut nodes: Vec<[u8; 32]> = commitments[start..start + size]
        .iter()
        .map(hash_leaf)
        .collect();
    let mut at = index as usize - start;
    let mut siblings = Vec::with_capacity(height as usize);
    while nodes.len() > 1 {
        siblings.push(nodes[at ^ 1]);
        nodes = nodes
            .chunks(2)
            .map(|pair| hash_merge(&pair[0], &pair[1]))
            .collect();
        at /= 2;
    }
    Ok(siblings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(i: u64) -> [u8; 32] {
        let mut word = [0u8; 32];
        word[24..].copy_from_slice(&i.to_be_bytes());
        word
    }

    /// Folding a leaf with its proof reaches one of the peaks, for every leaf of a
    /// tree whose count is not a power of two — the shape where peaks differ in
    /// height and a proof has to find the right one.
    #[test]
    fn every_leaf_proves_up_to_a_peak() {
        let commitments: Vec<[u8; 32]> = (1..=13).map(c).collect();
        let mut mmr = Mmr::default();
        for x in &commitments {
            mmr.append(x).unwrap();
        }
        assert_eq!(mmr.peaks.len(), 3, "13 = 0b1101, so heights 3, 2 and 0");

        for index in 0..commitments.len() as u64 {
            let siblings = proof(&commitments, index).expect("a proof");
            // Fold from the leaf: the sibling's side is the bit of the offset
            // within the peak, lowest first, which is what the verifier walks.
            let mut node = hash_leaf(&commitments[index as usize]);
            let mut at = index - peak_start(&commitments, index);
            for sibling in &siblings {
                node = if at & 1 == 0 {
                    hash_merge(&node, sibling)
                } else {
                    hash_merge(sibling, &node)
                };
                at >>= 1;
            }
            assert!(
                mmr.peaks.contains(&node),
                "leaf {index} folded to something that is not a peak"
            );
        }
    }

    /// Where the perfect subtree covering `index` starts — the same walk `proof`
    /// makes, spelled out here so the test does not lean on the code it checks.
    fn peak_start(commitments: &[[u8; 32]], index: u64) -> u64 {
        let count = commitments.len() as u64;
        let mut start = 0;
        for h in (0..u64::BITS).rev() {
            if count >> h & 1 == 0 {
                continue;
            }
            if index < start + (1 << h) {
                break;
            }
            start += 1 << h;
        }
        start
    }

    /// One proof against vectors computed independently in Python, so a change to
    /// the hashing shows up as a changed proof and not only as a changed root.
    #[test]
    fn a_proof_matches_an_independent_fold() {
        let commitments: Vec<[u8; 32]> = (1..=13).map(c).collect();
        let siblings = proof(&commitments, 5).expect("a proof");
        assert_eq!(
            siblings.iter().map(hex::encode).collect::<Vec<_>>(),
            [
                "883c502c26a5eaf5064fa4f3436acef6a5c0d2bca572e3bed242d0bcb19063c3",
                "ec3e3f93dc9844db6729364ada1bc56d3f2714191ef6df216a782a464595f8c0",
                "9a444d98cfab773b89efcfe3749342cd1b072e8f2276f9f822fb1e19edabb77b",
            ]
        );
        assert_eq!(proof(&commitments, 12).expect("the lone peak").len(), 0);
        assert!(proof(&commitments, 13).is_err(), "past the end");
    }

    /// The first, fifth and thirteenth of the sixteen roots the precompile and the
    /// contracts pin, over commitments `bytes32(1)`, `bytes32(2)`, …
    #[test]
    fn folds_to_the_pinned_roots() {
        let mut mmr = Mmr::default();
        for i in 1..=13 {
            mmr.append(&c(i)).unwrap();
            let root = hex::encode(mmr.root());
            match i {
                1 => assert_eq!(
                    root,
                    "5786039c2502cb1b5ff9a9f0b0b6957bb8b3f6489d20080f677236b2dd590dcd"
                ),
                5 => assert_eq!(
                    root,
                    "bbd0ad9fcc22a20f7adc962f214aba7710aed4d06063e7d722d65d07920a269d"
                ),
                13 => assert_eq!(
                    root,
                    "bc438a6c52d1d3f2abea81fdd299bdfb9c8961b03e2adbeeff075db74971b2ae"
                ),
                _ => {}
            }
        }
        assert_eq!(mmr.count, 13);
        assert_eq!(mmr.peaks.len(), 3, "13 = 8 + 4 + 1");
    }

    #[test]
    fn a_chunk_off_the_alignment_is_refused() {
        let mut mmr = Mmr::default();
        mmr.append(&c(1)).unwrap();
        let refused = mmr.push(1, c(9)).unwrap_err().to_string();
        assert!(refused.contains("not a multiple of 2"), "{refused}");
        assert_eq!(mmr.count, 1, "nothing moved");
    }
}
