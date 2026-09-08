//! Reading the nvnmchain anchoring precompile's log, and checking it.
//!
//! The chain keeps one Merkle Mountain Range per namespace — its leaf count and
//! peaks — and every leaf's payload lives in the log. `tidx` ingests that log;
//! this crate does the two things a general log indexer structurally cannot:
//! decode a leaf's payload into the shapes the retired module queries served,
//! and fold a namespace's leaves back into the root the precompile holds.

pub mod audit;
pub mod config;
pub mod envelope;
pub mod eth;
pub mod migrate;
pub mod mmr;
pub mod precompile;
pub mod registry;
pub mod rpc;
pub mod service;
pub mod tidx;
