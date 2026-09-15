//! The registries in SQLite. A name is stored lowercased and lowercased-reversed, each indexed:
//! exact and prefix seek the first, suffix the second, contains scans.

use std::sync::{Mutex, PoisonError};

use alloy_primitives::Address;
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};

use crate::contract::Registry;

/// `RegistryNameMatchMode`. Matching is case-insensitive in every mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Exact,
    Prefix,
    Suffix,
    Contains,
}

impl Mode {
    /// The enum's number or its name, as the REST gateway took either.
    /// Unspecified is exact.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "0"
            | "1"
            | "REGISTRY_NAME_MATCH_MODE_UNSPECIFIED"
            | "REGISTRY_NAME_MATCH_MODE_EXACT" => Some(Self::Exact),
            "2" | "REGISTRY_NAME_MATCH_MODE_PREFIX" => Some(Self::Prefix),
            "3" | "REGISTRY_NAME_MATCH_MODE_SUFFIX" => Some(Self::Suffix),
            "4" | "REGISTRY_NAME_MATCH_MODE_CONTAINS" => Some(Self::Contains),
            _ => None,
        }
    }
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS registries (
    id             INTEGER PRIMARY KEY,
    name           TEXT NOT NULL,
    description    TEXT NOT NULL,
    creator        TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    metadata       TEXT NOT NULL,
    name_lower     TEXT NOT NULL,
    name_rev_lower TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_registries_name_lower ON registries(name_lower);
CREATE INDEX IF NOT EXISTS idx_registries_name_rev_lower ON registries(name_rev_lower);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
";

fn max_id(conn: &Connection) -> Result<u64> {
    let id: Option<i64> = conn.query_row("SELECT MAX(id) FROM registries", [], |r| r.get(0))?;
    Ok(id.unwrap_or(0) as u64)
}

pub struct Index {
    conn: Mutex<Connection>,
}

impl Index {
    /// Opens `path`, creating it and its schema if needed. `case_sensitive_like`, or SQLite would
    /// not serve `LIKE` from an index; both sides are lowercased first.
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("open {path}"))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.pragma_update(None, "case_sensitive_like", true)?;
        conn.execute_batch(SCHEMA).context("create schema")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// The highest id indexed, or 0 for none. Ids have no holes, so the index lacks only what
    /// follows it.
    pub fn last_id(&self) -> Result<u64> {
        max_id(&self.conn.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Records that the index is `contract`'s on `chain_id`, or refuses one that is not: ids run
    /// from 1 on every chain, so another chain's index looks level and answers with its names.
    pub fn bind(&self, chain_id: u64, contract: Address) -> Result<()> {
        let source = format!("chain {chain_id} contract {contract}");
        let conn = self.conn.lock().unwrap_or_else(PoisonError::into_inner);
        let recorded: Option<String> = conn
            .query_row("SELECT value FROM meta WHERE key = 'source'", [], |r| {
                r.get(0)
            })
            .optional()?;
        match recorded {
            Some(from) if from == source => Ok(()),
            Some(from) => bail!("the index is from {from}, not {source}: delete it to rebuild"),
            None if max_id(&conn)? != 0 => {
                bail!("the index predates recording its chain: delete it to rebuild")
            }
            None => {
                conn.execute(
                    "INSERT INTO meta (key, value) VALUES ('source', ?1)",
                    [source],
                )?;
                Ok(())
            }
        }
    }

    /// Indexes `registries` in one transaction. A registry never changes on chain, so one read
    /// twice is left as it is rather than written again.
    pub fn insert(&self, registries: &[Registry]) -> Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(PoisonError::into_inner);
        let tx = conn.transaction()?;
        {
            let mut insert = tx.prepare_cached(
                "INSERT OR IGNORE INTO registries
                     (id, name, description, creator, created_at, metadata, name_lower, name_rev_lower)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for r in registries {
                let lower = r.name.to_lowercase();
                insert.execute(params![
                    r.id as i64,
                    r.name,
                    r.description,
                    r.creator,
                    r.createdAt,
                    r.metadata,
                    lower,
                    lower.chars().rev().collect::<String>(),
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Registries whose name matches `name` under `mode`, by id, `limit` from `offset`.
    pub fn search(&self, mode: Mode, name: &str, limit: u64, offset: u64) -> Result<Vec<Registry>> {
        let (sql, pattern) = statement(mode, &name.to_lowercase());
        let conn = self.conn.lock().unwrap_or_else(PoisonError::into_inner);
        let mut query = conn.prepare_cached(&sql)?;
        // SQLite integers are signed; anything past i64 is past the last row anyway.
        let (limit, offset) = (limit.min(i64::MAX as u64), offset.min(i64::MAX as u64));
        let rows = query.query_map(params![pattern, limit as i64, offset as i64], |r| {
            Ok(Registry {
                id: r.get::<_, i64>(0)? as u64,
                name: r.get(1)?,
                description: r.get(2)?,
                creator: r.get(3)?,
                createdAt: r.get(4)?,
                metadata: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

/// The statement and pattern for `mode`, apart so a test can check which index serves each.
fn statement(mode: Mode, lower: &str) -> (String, String) {
    let (filter, pattern) = match mode {
        Mode::Exact => ("name_lower = ?1", lower.to_string()),
        Mode::Prefix => (
            "name_lower LIKE ?1 ESCAPE '\\'",
            format!("{}%", escape_like(lower)),
        ),
        // Reversed by character, so a multi-byte name still matches by suffix.
        Mode::Suffix => (
            "name_rev_lower LIKE ?1 ESCAPE '\\'",
            format!("{}%", escape_like(&lower.chars().rev().collect::<String>())),
        ),
        Mode::Contains => (
            "name_lower LIKE ?1 ESCAPE '\\'",
            format!("%{}%", escape_like(lower)),
        ),
    };
    let sql = format!(
        "SELECT id, name, description, creator, created_at, metadata FROM registries
         WHERE {filter} ORDER BY id LIMIT ?2 OFFSET ?3"
    );
    (sql, pattern)
}

/// `name` as a literal inside a `LIKE` pattern: a `%` or `_` in it matches only itself.
fn escape_like(name: &str) -> String {
    name.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An unused index still answers correctly, just by reading every row, so only the plan shows it.
    #[test]
    fn exact_prefix_and_suffix_seek_an_index_and_contains_scans() {
        let index = Index::open(":memory:").unwrap();
        let conn = index.conn.lock().unwrap();
        let plan = |mode| {
            let (sql, pattern) = statement(mode, "fund");
            let mut query = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            let rows = query
                .query_map(params![pattern, 50, 0], |r| r.get::<_, String>(3))
                .unwrap();
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
                .join("; ")
        };
        for (mode, index) in [
            (Mode::Exact, "idx_registries_name_lower"),
            (Mode::Prefix, "idx_registries_name_lower"),
            (Mode::Suffix, "idx_registries_name_rev_lower"),
        ] {
            let plan = plan(mode);
            assert!(
                plan.contains(&format!("SEARCH registries USING INDEX {index}")),
                "{mode:?}: {plan}"
            );
        }
        let plan = plan(Mode::Contains);
        assert!(plan.starts_with("SCAN registries"), "contains: {plan}");
    }
}
