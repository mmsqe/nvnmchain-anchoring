//! Reading the nvnmchain anchoring precompile's `Anchored` log, and checking it.
//!
//! The chain keeps only the latest commitment per `(namespace, key)`; history
//! and payloads live in the log. `tidx` ingests that log — this crate does the
//! two things a general log indexer structurally cannot: decode the anchored
//! payload into the shapes the retired module queries served, and compare the
//! index against the precompile's own storage.

pub mod audit;
pub mod config;
pub mod envelope;
pub mod eth;
pub mod precompile;
pub mod registry;
pub mod rpc;
pub mod tidx;
