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

`serve` exposes the projections over HTTP, which is what the explorer's
`ANCHORING_URL` links to:

```
CHAIN_ID=… FACTORY_ADDRESS=0x… BIND=127.0.0.1:8081 nvnmchain-anchoring serve

GET /health                          how far the index this answers from reaches
GET /registries[?name=|?name_prefix=|?name_suffix=|?name_contains=]
                                     every registry the factory deployed, in order
GET /registries/{address}/records    each record decoded, at its newest version
GET /registries/{address}/roles      every role held, folded from the log
GET /registries/{address}/records/{checksum}   one record's versions, oldest first
GET /records/{checksum}              every registry that anchored this checksum
POST /registries/records  [addr,…]   several registries' records in one walk, unnumbered
```

The version list is the one projection that does not fold to heads: the chain
keeps a single word per key, so every version before the newest exists only as
the log row the head replaced.

`/records/{checksum}` is the lookup no per-registry path can serve, and what the
module answered for `records(registry_id = 0, checksum, …)`. A record's key is
`keccak256(abi.encode("record", keccak256(checksum)))` — the checksum and nothing
else — so the same checksum in two registries is one key under two namespaces,
and one filter on an indexed topic answers for all of them. It carries no
`number`, which is a property of one registry's whole ordering that this query
never walks; and a payload that is not a record is counted in `other` rather than
failing the request, since anyone may anchor under any key.

The `name…` filters are the module's `registriesByName`, spelled the way its
proto did. They run after decoding rather than in SQL — the name is a dynamic
`string` in the deployment event, which tidx hands back as an offset word — so
the walk is the same and only the rows returned differ. Byte-exact in every mode,
anchored at both ends, and an AND when several are set, so a contradictory pair
returns nothing rather than one of them quietly winning. An unknown parameter is
a 400, since ignoring a typo would answer with every registry there is. Numbering
is deployment order, assigned before the filter: a filtered listing reports the
numbers registries have, not their places in the answer.

A malformed address is a 400 and never reaches SQL; an address the factory never
deployed, or a checksum with nothing anchored under it, is a 404; tidx being
unreachable or refusing is a 502; a missing `FACTORY_ADDRESS` is a 500, since
that is this process misconfigured rather than the one behind it. None of them is
ever an empty result — an empty list means a registry with nothing in it.

That 404 is the module's "registry 999 does not exist", restored where the log
can still establish it: an address is a registry only because the factory
announced it. Without a `FACTORY_ADDRESS` — the audit-only setup — nothing
distinguishes one from any other address, so every address is answered for.

**Paged, and it refuses rather than truncates.** tidx caps a query at 10,000
rows and says nothing when it hits that, so every projection walks by cursor
until a page comes back short. The cursor is the query's own ordering, which for
a windowed query is also its partition — a page boundary that fell inside a
partition would fold "newest per key" from half a key's rows. Anything that
somehow arrives full anyway is an error: a short list is indistinguishable from
a complete one. `PAGE_SIZE` lowers the rows per round trip, which is only worth
doing to watch the loop work.

```bash
CHAIN_ID=… TIDX_URL=http://127.0.0.1:8080 NVNM_RPC=http://127.0.0.1:8545 cargo run
```

| Command | |
|---|---|
| `cargo run` / `cargo run -- audit` | check the index against the chain; non-zero on divergence |
| `cargo run -- kinds` | what this chain carries |
| `… registries [--name=…]` | every registry the factory deployed, filtered by name |
| `… records <registry>` | that registry's records, at their newest version |
| `… roles <registry>` | every role it holds as granted |
| `… record <registry> <checksum>` | one record's versions |
| `… checksum <checksum>` | every registry that anchored it |
| `… migrate --registries= --manifest=` | plan the module's corpus onto the contracts |
| `… reconcile --plan=` | read a plan back off the chain; non-zero only on what sending cannot fix |

The five query commands print the projections `serve` answers with, as JSON and
straight from tidx — the read half of `nvnmchaind query anchoring …`, for an
operator with no service running. They exit 2 for what the caller could ask
differently (a malformed address, a registry the factory never deployed) and 1
for this process or the index being wrong.

The write half — `tx anchoring add-registry` — has no successor and wants none: a
record is an EVM transaction now, so it belongs to whatever holds the key, and
this process holds none.

## `migrate`

The module seeded its corpus from an upgrade handler: no transactions, no gas. A
record is an `Anchored` log entry now, and logs come only from transactions, so the
corpus has to be replayed — and 1:1 that is about **3.1e12 gas** and gigabytes of
log, permanently (`src/migrate.rs` has the arithmetic).

So `migrate` splits it at `--threshold` records. Above it, the whole export file
becomes one record whose checksum is a merkle root over its lines
(`--root=merkle`, the default) — every row still proves against that root, so
what a rooted registry gives up is not provability but being queryable from the
chain: `/records/{checksum}` across registries, and the decoded fields the log
would have carried. `--root=sha256` takes the digest the manifest already holds
instead, so it plans without the export staged and verifies nothing; a row then
proves by producing the whole file.

Below the threshold a registry is replayed record by record and keeps all of
that. It defaults to zero — everything rooted — because a replayed record is
chain-permanent where raising the threshold later is not: 1:1 is ~8.4 GB of log
and 1.6 GB of state, at 10,000 still 0.5 GB, at 1,000 0.08 GB, and a rooted
registry can be replayed afterwards with the root it already carries staying true.

```
nvnmchain-anchoring migrate --registries=registries.json --manifest=manifest.json \
  --export=<staged export dir> --threshold=10000 --uri-base=https://… > plan.jsonl
```

Out comes one JSON step per line, in the order they must be sent: `deploy` for
each registry, then its records, then a `status` for every record that carried
one — `updateRecordStatus` against the version it belongs to, since a status was
a field on the record and is a per-version anchor now. `--skip-status=<value>`
leaves those out. A step names its registry by the export's name rather than an
address, because the address only exists once its `deploy` has landed and
`RegistryDeployed` announces it.

It plans and verifies; it does not sign. Whatever holds the key sends the steps,
and can batch them — a tempo transaction carries several calls, all or nothing.

`reconcile --plan=plan.jsonl` reads it back off the chain, matching each registry
by the name the plan deployed it under — the only handle a plan has — and reading
every landed one's records in a single walk. What comes back is split in two.
`--remaining=<file>` gets the steps still to send, each naming its target where
that is already knowable (the factory for a deploy, the registry for anything
under one that has landed), so a sender resuming needs no log of its own. What
exits non-zero is only what sending cannot fix — a record past the version the
plan writes, one the plan does not write at all, a name two registries carry — so
the resume loop needs no parsing:

    until reconcile --plan=plan.jsonl --remaining=left.jsonl && [ ! -s left.jsonl ]
    do send left.jsonl; done

It resumes by chain state, never by how far a run got: `addRecord` appends a
version on every call, so a step re-sent by count leaves one too many.

What the plan does not carry over, because nothing can: the registry ids (the
module's own migration also let the chain assign them), `created_at`, the
original creator, and the original anchoring time. The chain stamps its own —
which is why the timing of the old corpus is something to commit to once, from
the old chain, rather than something a replay reproduces.

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

The decoder, the audit, and `serve` over registries, records, roles, one
checksum across every registry, and one record's versions are in.

`/registries/{address}/records` still answers at each record's newest version,
because that is what the chain keeps — one word per key. History got the separate
endpoint it wanted rather than a field on the listing that could quietly be
short: `/registries/{address}/records/{checksum}` returns every version from the
log, each with its own envelope and the status anchored against it.

`records` is where the decoder earns the repo: four of `Record`'s ten fields
exist only inside the anchored payload, and `metadata` is a dynamic `bytes` that
tidx hands back as its ABI offset word. `registries` and `roles` needed none of
that, so they went first. Still worth matching the
`proto/nvnmchain/anchoring/v1` shapes so callers of the old node queries move
over unchanged.

Read-through, not materialized: every request queries tidx and nothing is kept
here. A second store over the same log is what the explorer already is, and the
measurements on `record_ids_sql` say read-through is comfortable at the sizes
this chain has. Materializing is a decision to make against numbers later.

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
