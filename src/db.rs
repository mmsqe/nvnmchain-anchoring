//! Storage: the raw log is the truth, everything else is a projection of it.
//!
//! Only `anchored` and `registry_events` are written from the chain. Derived
//! views (registries, records, versions, roles) are rebuildable from those two
//! tables, so a projection bug is fixed by reprojecting rather than re-syncing.

use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};

pub type Db = Arc<Mutex<Connection>>;

#[derive(Debug, Clone)]
pub struct Anchored {
    pub block_number: i64,
    pub log_index: i64,
    pub tx_hash: String,
    pub namespace: String,
    pub key: String,
    pub commitment: String,
    pub metadata: Vec<u8>,
}

/// One log from the registry wrapper, kept raw. Roles are the only thing the
/// anchored log cannot rebuild, so this table is not optional.
#[derive(Debug, Clone)]
pub struct RegistryEvent {
    pub block_number: i64,
    pub log_index: i64,
    pub tx_hash: String,
    /// The indexed topics, packed as 32-byte words. `topic0` is a column
    /// derived from this at insert time so the two cannot disagree, and
    /// `topic1`/`topic2` are promoted for the roles projection to seek on:
    /// `RoleGranted` puts the registry id and the account there.
    pub topics: Vec<u8>,
    pub data: Vec<u8>,
}

/// Bumped whenever the schema changes; `open` refuses a database from a newer
/// build rather than reading it wrong. Every table here is re-derivable from
/// the chain, so a backward change is a re-sync, not a migration.
pub const SCHEMA_VERSION: i64 = 1;

pub fn open(path: &str) -> Result<Db> {
    let conn = Connection::open(path).with_context(|| format!("open {path}"))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    // NORMAL can lose the last transaction on power loss but never corrupts,
    // and a lost range is re-scanned from the cursor.
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS anchored (
            block_number INTEGER NOT NULL,
            log_index INTEGER NOT NULL,
            tx_hash BLOB NOT NULL,
            namespace BLOB NOT NULL,
            key BLOB NOT NULL,
            commitment BLOB NOT NULL,
            metadata BLOB NOT NULL,
            PRIMARY KEY (block_number, log_index)
        );
        CREATE INDEX IF NOT EXISTS idx_anchored_ns_key
            ON anchored(namespace, key, block_number, log_index);

        CREATE TABLE IF NOT EXISTS registry_events (
            block_number INTEGER NOT NULL,
            log_index INTEGER NOT NULL,
            tx_hash BLOB NOT NULL,
            topic0 BLOB NOT NULL,
            topic1 BLOB,
            topic2 BLOB,
            topics BLOB NOT NULL,
            data BLOB NOT NULL,
            PRIMARY KEY (block_number, log_index)
        );
        CREATE INDEX IF NOT EXISTS idx_registry_events_topic0
            ON registry_events(topic0, topic1, block_number, log_index);

        -- Block hashes at the cursor, so a reorg under us is detectable rather
        -- than silently indexed twice.
        CREATE TABLE IF NOT EXISTS checkpoints (
            block_number INTEGER PRIMARY KEY,
            block_hash BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        "#,
    )?;
    let found: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if found > SCHEMA_VERSION {
        anyhow::bail!("database is schema v{found}; this build understands v{SCHEMA_VERSION}");
    }
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(Arc::new(Mutex::new(conn)))
}

pub fn lock(db: &Db) -> MutexGuard<'_, Connection> {
    db.lock().unwrap_or_else(|e| e.into_inner())
}

fn blob(value: &str) -> Vec<u8> {
    hex::decode(crate::eth::strip_hex(value)).unwrap_or_default()
}

pub fn insert_anchored(conn: &Connection, event: &Anchored) -> Result<()> {
    conn.prepare_cached(
        "INSERT OR REPLACE INTO anchored
           (block_number, log_index, tx_hash, namespace, key, commitment, metadata)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?
    .execute(params![
        event.block_number,
        event.log_index,
        blob(&event.tx_hash),
        blob(&event.namespace),
        blob(&event.key),
        blob(&event.commitment),
        event.metadata,
    ])?;
    Ok(())
}

pub fn insert_registry_event(conn: &Connection, event: &RegistryEvent) -> Result<()> {
    // topic0/1/2 are slices of `topics`, sliced in SQL so they cannot drift.
    conn.prepare_cached(
        "INSERT OR REPLACE INTO registry_events
           (block_number, log_index, tx_hash, topic0, topic1, topic2, topics, data)
         VALUES (?1, ?2, ?3, substr(?4, 1, 32), substr(?4, 33, 32), substr(?4, 65, 32), ?4, ?5)",
    )?
    .execute(params![
        event.block_number,
        event.log_index,
        blob(&event.tx_hash),
        event.topics,
        event.data,
    ])?;
    Ok(())
}

fn row_to_anchored(row: &rusqlite::Row) -> rusqlite::Result<Anchored> {
    Ok(Anchored {
        block_number: row.get(0)?,
        log_index: row.get(1)?,
        tx_hash: crate::eth::hex0x(&row.get::<_, Vec<u8>>(2)?),
        namespace: crate::eth::checksum_address(&crate::eth::hex0x(&row.get::<_, Vec<u8>>(3)?)),
        key: crate::eth::hex0x(&row.get::<_, Vec<u8>>(4)?),
        commitment: crate::eth::hex0x(&row.get::<_, Vec<u8>>(5)?),
        metadata: row.get(6)?,
    })
}

const ANCHORED_COLS: &str =
    "block_number, log_index, tx_hash, namespace, key, commitment, metadata";

/// Every revision of one `(namespace, key)`, newest first.
pub fn key_history(conn: &Connection, namespace: &str, key: &str) -> Result<Vec<Anchored>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {ANCHORED_COLS} FROM anchored WHERE namespace=?1 AND key=?2
         ORDER BY block_number DESC, log_index DESC"
    ))?;
    let rows = stmt.query_map(params![blob(namespace), blob(key)], row_to_anchored)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// The head this index believes in for every `(namespace, key)` it has seen —
/// what the audit compares against the chain's own storage.
pub fn heads(conn: &Connection) -> Result<Vec<Anchored>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {ANCHORED_COLS} FROM (
             SELECT *, ROW_NUMBER() OVER (
                 PARTITION BY namespace, key ORDER BY block_number DESC, log_index DESC
             ) AS rn
             FROM anchored
         ) WHERE rn = 1"
    ))?;
    let rows = stmt.query_map([], row_to_anchored)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn count_anchored(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("SELECT COUNT(*) FROM anchored", [], |r| r.get(0))?)
}

// ---------------------------------------------------------------------------
// Cursor and reorg checkpoints
// ---------------------------------------------------------------------------

/// The precompile's log — always present.
pub const SOURCE_ANCHORED: &str = "anchored";

/// One registry wrapper's own events. Keyed by address: a second proxy is a
/// second source with its own history to catch up on.
pub fn registry_source(address: &str) -> String {
    format!("registry:{}", crate::eth::normalize_hex(address))
}

/// How far `source` has been scanned. Per source, because a source configured
/// after the first sync must start from the beginning rather than inherit a
/// cursor already at the head.
pub fn cursor(conn: &Connection, source: &str) -> Option<u64> {
    conn.query_row(
        "SELECT value FROM meta WHERE key=?1",
        params![format!("cursor:{source}")],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .ok()
    .flatten()
    .and_then(|v| v.parse().ok())
}

pub fn set_cursor(conn: &Connection, source: &str, block: u64) -> Result<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![format!("cursor:{source}"), block.to_string()],
    )?;
    Ok(())
}

/// The furthest any source has been scanned, and the newest checkpoint. They
/// should be equal — the checkpoint commits with the cursor — so a difference
/// means a range was scanned without being pinned to a block hash, and a reorg
/// across it would go undetected.
pub fn uncheckpointed(conn: &Connection) -> Result<Option<(u64, u64)>> {
    let cursor: Option<i64> = conn.query_row(
        "SELECT MAX(CAST(value AS INTEGER)) FROM meta WHERE key LIKE 'cursor:%'",
        [],
        |r| r.get(0),
    )?;
    let checkpoint: Option<i64> =
        conn.query_row("SELECT MAX(block_number) FROM checkpoints", [], |r| {
            r.get(0)
        })?;
    Ok(match (cursor, checkpoint) {
        (Some(c), Some(k)) if c > k => Some((k as u64, c as u64)),
        (Some(c), None) => Some((0, c as u64)),
        _ => None,
    })
}

pub fn save_checkpoint(conn: &Connection, block: u64, hash: &str) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO checkpoints (block_number, block_hash) VALUES (?1, ?2)",
        params![block as i64, blob(hash)],
    )?;
    Ok(())
}

/// The most recent checkpoints, newest first — walked backwards to find the
/// last block both sides still agree on.
pub fn recent_checkpoints(conn: &Connection, limit: usize) -> Result<Vec<(u64, String)>> {
    let mut stmt = conn.prepare(
        "SELECT block_number, block_hash FROM checkpoints ORDER BY block_number DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![limit as i64], |r| {
        Ok((
            r.get::<_, i64>(0)? as u64,
            crate::eth::hex0x(&r.get::<_, Vec<u8>>(1)?),
        ))
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Drop everything at or above `block` — the reorg path.
pub fn rollback_to(conn: &Connection, block: u64) -> Result<()> {
    // Raw tables only. A projection is a fold and cannot be un-folded — it is
    // rewound by resetting its own cursor and re-reading these tables.
    for table in ["anchored", "registry_events", "checkpoints"] {
        conn.execute(
            &format!("DELETE FROM {table} WHERE block_number >= ?1"),
            params![block as i64],
        )?;
    }
    let rewind = block.saturating_sub(1);
    conn.execute(
        "UPDATE meta SET value=?1 WHERE key LIKE 'cursor:%' AND CAST(value AS INTEGER) > ?2",
        params![rewind.to_string(), rewind as i64],
    )?;
    Ok(())
}
