//! Indexer over the nvnmchain anchoring precompile's `Anchored` log.
//!
//! The chain keeps only the latest commitment per `(namespace, key)`; the
//! registry and record queries its predecessor served were retired along with
//! the rest. Deriving them back from the log is this crate's job.

pub mod audit;
pub mod config;
pub mod db;
pub mod envelope;
pub mod eth;
pub mod indexer;
pub mod precompile;
pub mod registry;
pub mod rpc;
