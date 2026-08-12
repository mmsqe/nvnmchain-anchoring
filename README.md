# nvnmchain-anchoring

Reads the anchoring precompile's `Anchored` log, and checks it.

The chain keeps one word per `(namespace, key)` — the latest commitment. History
and payloads live in the log, and the `Registries`/`Records` queries the
predecessor module served at `0x…0A00` were retired with it (the old selector
now reverts `UnknownFunctionSelector`).

[tidx](https://github.com/tempoxyz/tidx) indexes that log, along with every
other log on the chain. This is what it structurally cannot do:

- **decode** the anchored payload — `metadata` reaches tidx as opaque `bytes`,
  and most of the retired queries' fields live inside it;
- **audit** — tidx holds blocks, transactions, logs and receipts, never state,
  so it cannot say whether what it indexed is what the chain kept.

## Running

`serve` exposes the projections over HTTP, read from the log rather than from
the module that retired them:

```
CHAIN_ID=… REGISTRY_ADDRESS=0x… BIND=127.0.0.1:8081 nvnmchain-anchoring serve

GET /health                     how far the index this answers from reaches
GET /registries                 every registry the wrapper announced, in id order
GET /registries/{id}/records    each record decoded, at its newest version
GET /registries/{id}/roles      every role held, folded from the log
```

An unreadable id is a 400 and never reaches SQL; a missing `REGISTRY_ADDRESS` is
a 500, since that is this process misconfigured rather than the one behind it;
tidx unreachable or refusing is a 502. None of them is ever an empty result — an
empty list means a registry with nothing in it.

`/records` reads every head under the wrapper's namespace and keeps the registry
asked for, because the key hashes the registry id in and leaves nothing for a
`WHERE` to narrow on. `/roles` and `/registries` narrow in SQL, where the id is
`topic1`.


```bash
CHAIN_ID=… TIDX_URL=http://127.0.0.1:8080 NVNM_RPC=http://127.0.0.1:8545 cargo run
```

| Command | |
|---|---|
| `cargo run` / `cargo run -- audit` | check the index against the chain; non-zero on divergence |
| `cargo run -- kinds` | what this chain carries |

| Variable | Default | |
|---|---|---|
| `CHAIN_ID` | — | required; tidx serves several chains from one endpoint |
| `TIDX_URL` | `http://127.0.0.1:8080` | a tidx indexing the same chain |
| `TIDX_ENGINE` | `postgres` | or `clickhouse` |
| `NVNM_RPC` / `TEMPO_RPC` | canary | JSON-RPC endpoint, for state reads |
| `START_BLOCK` | `0` | where anchors become possible — T10 |

## How it reads the log

One `GET /query` over the base `logs` table — `topic1` and `topic2` are the
indexed `caller` and `key`, `data` is the payload. Heads are a window function
over it: the precompile's own rule as SQL, one word per `(namespace, key)`,
newest anchor wins, bounded at the block the audit reads state at.

**Not the decoded event table** a `?signature=` parameter would generate, which
would be the obvious way to do this. tidx cannot decode this event: a dynamic
`bytes` argument comes back as its ABI offset word rather than the payload, so
`metadata` would arrive as `0x…40` — hashing to nothing, decoding to no
envelope. `decode_anchored_data` reads `data` instead. The upside is that the
only contract fact left in the SQL is a topic0 that `tests/signatures.rs`
already pins against the compiled ABI.

**The address and topic predicates are spelled per engine** — `'\x…'` for
PostgreSQL, `'0x…'` for ClickHouse. Carried between them they match nothing,
and matching nothing is an empty result rather than an error.
`Engine::bytes_literal` is the one place it is written.

Both are observed against a running tidx, not inferred from its source — as is
the block a query may be bounded at, which is the tip ingest has reached and not
the contiguous marker below it.

## Envelopes

`AnchoringRegistry` anchors in two formats — a bare `abi.encode`, and a newer
one leading with a `bytes32` kind (`registry`, `record`, `status`, `acl`). Only
the tagged form has ever been emitted; the untagged reading stays dead until a
build predating the kind tags ships.

Either way the ids must reproduce the key the payload was anchored under,
`keccak256(abi.encode(kind, ids…))` — the only thing identifying an untagged
shape, and still a check that a tagged one has not drifted from the contract.
Anything else reads as JSON, then text, then opaque.

## `audit`

Every head against the chain's own storage at `keccak256(0x01 ‖ pad32(ns) ‖ key)`,
batched a few hundred keys per request — sequentially hours over a large index,
batched a minute.

State reads are pinned to the block ingest has reached, and the heads query is
bounded at the same block — skew in either direction reports every anchor in
between as a mismatch.

That block is `/status`'s `tip_num`, not `synced_num`. Realtime sync advances
`tip_num` and leaves `synced_num` to gap-fill, so on an index following the
chain `synced_num` sits below rows that are already there — and an audit bounded
by it checks almost nothing while reporting clean. Coverage comes from `/status`
because `/query` allowlists `blocks`/`txs`/`logs`/`receipts` and refuses
`sync_state` by name with a 422.

Two limits it handles rather than hides. Building the slot is *our* keccak, so a
drift would flag every head; one `latest()` call per run calibrates against the
node and says which side is wrong. And the precompile stores nothing enumerable,
so it can only check keys the index already holds — a range never ingested that
anchored only new keys is invisible. `/status`'s `backfill_num` bounds that
rather than closing it: a run reports when the index has not reached back to
`START_BLOCK`.

## Status

The decoder and the audit are in. The projection into registries, records,
versions and roles, and the query API over it, are not.

Two of those four fold in SQL over tidx alone. `registries` and `records` do
not: the wrapper's events are narrower than the envelopes they accompany, so
three of `Registry`'s six fields and four of `Record`'s ten exist only in the
anchored payload. Worth matching the `proto/nvnmchain/anchoring/v1` shapes so
callers of the old node queries move over unchanged.

## Tests

`cargo test` — offline. Envelope payloads are dumped from forge runs against
both contract revisions, and tidx responses are the shapes its `/query` returns,
including `ok: false`.

Signatures are checked twice over: each topic0 is the keccak of the signature
beside it, and each signature is one the contracts compile to — a signature and
its hash drift together, agreeing with each other while matching nothing on
chain. `make fixtures` vendors that ABI to `tests/fixtures/contract-events.json`;
nothing offline can spot a stale one, so rerun it on any event change.
