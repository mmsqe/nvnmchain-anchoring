# nvnmchain-anchoring

Registry name search for the anchoring contract on Tempo. The contract at `0x…0a00` answers
`registriesByName` for an exact name only; this copies its registries into SQLite and serves prefix,
suffix and contains on the chain's `SearchRegistriesByName` route.

## Running

```
NVNM_RPC=http://127.0.0.1:8545 nvnmchain-anchoring serve

GET /NVNM-Chain/nvnmchain/anchoring/v1/registries/search?name=…[&mode=…][&pagination.offset=…][&pagination.limit=…]
GET /health        the highest registry id indexed
```

`serve` catches up from the contract before it listens, then every `POLL_SECONDS`.
`nvnmchain-anchoring sync` copies what is new and exits.

| Variable | Default | |
|---|---|---|
| `NVNM_RPC` or `TEMPO_RPC` | `https://rpc.nvnm.canary.mantrachain.dev` | the node |
| `CONTRACT_ADDRESS` | `0x…0a00` | the anchoring contract |
| `DB_PATH` | `anchoring_name_index.db` | the index; derived, so safe to delete |
| `BIND` | `127.0.0.1:8081` | where `serve` listens |
| `POLL_SECONDS` | `2` | how often to look for new registries; whole seconds, 1 at least |

## The search

`mode` is `REGISTRY_NAME_MATCH_MODE_EXACT` (the default), `_PREFIX`, `_SUFFIX` or `_CONTAINS`, or its
number. Matching is case-insensitive, results come by id, and only `pagination.offset` and
`pagination.limit` apply (50 by default, 200 at most). A missing name, unknown mode or unknown
parameter is a 400. Exact, prefix and suffix use an index; contains scans every name, 0.35 ms over
2,182 of them.
