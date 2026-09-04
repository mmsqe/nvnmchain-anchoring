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
        self.count += size;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn c(i: u64) -> [u8; 32] {
        let mut word = [0u8; 32];
        word[24..].copy_from_slice(&i.to_be_bytes());
        word
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
