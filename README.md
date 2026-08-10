# nvnmchain-anchoring

Indexer over the anchoring precompile's `Anchored` log.

The chain keeps one word per `(namespace, key)` — the latest commitment. History
and payloads live in the log, and the `Registries`/`Records` queries the
predecessor module served at `0x…0A00` were retired with it (the old selector
now reverts `UnknownFunctionSelector`). This derives them back.

## Running

```bash
NVNM_RPC=http://127.0.0.1:8545 DB_PATH=/tmp/anchoring.db cargo run
```

| Command | |
|---|---|
| `cargo run` | follow the chain |
| `cargo run -- once` | one pass and exit |
| `cargo run -- kinds` | what this chain carries |
| `cargo run -- audit` | check the index against the chain; non-zero on divergence |

| Variable | Default | |
|---|---|---|
| `NVNM_RPC` / `TEMPO_RPC` | canary | JSON-RPC endpoint |
| `DB_PATH` | `anchoring.db` | SQLite file; one per chain |
| `REGISTRY_ADDRESS` | — | `AnchoringRegistry` proxy; adds its events as a second source |
| `START_BLOCK` | `0` | nothing to find below the T10 block |
| `LOG_RANGE` | `2000` | blocks per `eth_getLogs` |
| `POLL_SECONDS` | `2` | between passes |

## How it reads the chain

Blocks are never fetched. Two log filters, **each with its own cursor**:

- `0x…0A00` / `Anchored` — every namespace, including anchors that never went
  through a registry
- the registry proxy / `RegistryAdded`, `RecordAdded`, `RecordStatusUpdated`,
  `RoleGranted`, `RoleRevoked`

Separate cursors because setting `REGISTRY_ADDRESS` on an existing database has
to backfill that source, not inherit a cursor already at the head and skip its
history silently. Roles do not depend on it — grants and revokes anchor — but it
is a cheaper projection than decoding envelopes, and cross-checks the anchored
ACL against what the wrapper said it did.

A range is one request — logs and the hash of its last block together — so the
checkpoint costs nothing extra and commits with the cursor. Reorgs walk those
checkpoints back to the last hash the chain still agrees with.

The two raw tables are the truth. Registries, records, versions and roles are a
projection over them, rebuilt rather than re-synced; `rollback_to` truncates
only the raw tables, since a fold cannot be un-folded.

## Envelopes

`AnchoringRegistry` anchors in two formats — a bare `abi.encode`, and a newer
one leading with a `bytes32` kind (`registry`, `record`, `status`, `acl`).

Only the tagged form has ever been emitted, so the untagged reading is dead
code — and not insurance against a later format change either, since a third
format would need its own reading. It is deletable until a build predating the
kind tags ships.

Either way the ids have to reproduce the key the payload was anchored under,
`keccak256(abi.encode(kind, ids…))`. For untagged payloads that is the only
thing identifying the shape; for tagged ones it still catches a schema that has
drifted from the contract. Anything else reads as JSON, then text, then opaque.

## `audit`

Every head against the chain's own storage at `keccak256(0x01 ‖ pad32(ns) ‖ key)`,
batched a few hundred keys per request — sequentially that is hours over a large
index, batched it is a minute.

Two limits it handles rather than hides. Building the slot is *our* keccak, so a
drift would flag every head; one `latest()` call per run calibrates against the
node and says which side is wrong. And the precompile stores nothing enumerable,
so it can only check keys the index already holds — a missed range that anchored
only new keys is invisible, which is why the run also reports any span scanned
without a checkpoint.

## Status

Ingest, storage, reorgs, both envelope formats and the audit are in. Next: the
projection into registries/records/versions/roles, and the query API — worth
matching the retired `proto/nvnmchain/anchoring/v1` shapes so callers of the old
node queries move over unchanged. (That projection is why `registry_events`
promotes `topic0`/`topic1`/`topic2` to indexed columns.)

## Tests

`cargo test` — offline. Envelope payloads are dumped from forge runs against
both contract revisions, not re-encoded here. `tempo-e2e`'s `test_anchoring.py`
and `test_anchoring_registry.py` cover the same ground against a live node and
are the acceptance spec.

The topics filtered on are checked twice over: each topic0 is the keccak of the
signature beside it, and each signature is one the contracts compile to. The
second half matters because a signature and its hash drift together — agreeing
with each other while matching nothing on chain, which indexes silently empty.

`make fixtures` vendors the contracts' event ABI to
`tests/fixtures/contract-events.json`, recording the commit it read for failure
messages. Nothing offline can spot a stale fixture, so rerun it on any event
change.
