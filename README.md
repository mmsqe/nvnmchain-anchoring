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

A registry anchors two kinds, each leading with a `bytes32` tag: `record` and
`status`. One word identifies the shape, and the ids inside must then reproduce
the key the payload was anchored under, `keccak256(abi.encode(kind, ids…))` —
which catches a schema that has drifted from the contract, and binds the payload
to its key. Anything else reads as JSON, then text, then opaque.

No registry id in any key: a registry is a deployment, so the address a payload
was anchored under is the registry. A payload only means something with its
namespace beside it — the same commitment under two registries is two different
records.

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

The decoder and the audit are in. The projection into records, versions and
roles, and the query API over it, are not.

Two of those three no longer need this crate at all. `roles` is written out —
`registry::roles_sql`, one query a caller sends tidx directly, which this crate
never runs — and `registries` is the factory's deployment event, read straight
off the log with no envelope behind it. `records` and `versions` are what is
left, and they do need the decoder: four of `Record`'s ten fields exist only in
the anchored payload, and `metadata` is a dynamic `bytes` that tidx hands back
as its ABI offset word. Worth matching the `proto/nvnmchain/anchoring/v1` shapes
so callers of the old node queries move over unchanged.

### `roles`, over `?signature=`

`RoleGranted` and `RoleRevoked` carry only `bytes32` outside the topics, so tidx
decodes them where it cannot decode `Anchored`. The query orders the two against
each other — newest row per `(checksumHash, account, role)` wins, kept if it
granted — because revokes are not deletions and the same key can be granted,
revoked and granted again.

**Two signatures, not three.** A registry announces its creator's `admin` as an
ordinary `RoleGranted` when the factory initializes it, so the grant/revoke pair
answers in full. The wrapper needed a third — it wrote `member` directly in
`addRegistry` and announced that admin only as a `RegistryAdded` — and the seed
arm that supplied it went with the wrapper.

It names the **address**, which is the whole partition: a registry is a
deployment, tidx's generated CTEs filter on topic0 alone, and one contract per
registry means that address selects exactly one registry's logs. The `topic1`
narrowing this used to need is gone with the id it narrowed on — `topic1` is the
role's scope now, not a registry id.

That also retires the measurement this section used to carry (66 ms against
2.4 ms over a synthetic 4M-log index): it compared an unscoped read of one
wrapper's logs against a topic1-narrowed one, and neither shape exists any more.
A registry's logs are only its own, so the address predicate is the narrowing.
No replacement figure is quoted here because none has been taken.

## Tests

`cargo test` — offline. Envelope payloads are dumped from forge runs against
both contract revisions, and tidx responses are the shapes its `/query` returns,
including `ok: false`.

Signatures are checked twice over: each topic0 is the keccak of the signature
beside it, and each signature is one the contracts compile to — a signature and
its hash drift together, agreeing with each other while matching nothing on
chain. `make fixtures` vendors that ABI to `tests/fixtures/contract-events.json`;
nothing offline can spot a stale one, so rerun it on any event change.
