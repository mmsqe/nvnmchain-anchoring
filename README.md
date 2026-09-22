# nvnmchain-anchoring

The module's `SearchRegistriesByName` on its REST route, from a Tempo node that holds the registry
name index. The node searches; this translates, so a client written against the old chain moves over
by changing the host it calls.

```
NVNM_RPC=http://127.0.0.1:8545 nvnmchain-anchoring serve

GET /NVNM-Chain/nvnmchain/anchoring/v1/registries/search?name=…[&mode=…][&pagination.offset=…][&pagination.limit=…]
GET /health        how far the node's index reaches; 503 while it cannot be read
```

The node must run `--anchoring.name-index`, which is what serves `anchoring_searchRegistriesByName`;
`serve` asks for it at startup rather than failing once per request.

| Variable | Default | |
|---|---|---|
| `NVNM_RPC` or `TEMPO_RPC` | `https://rpc.nvnm.canary.mantrachain.dev` | the node |
| `BIND` | `127.0.0.1:8081` | where `serve` listens |

`mode` is `REGISTRY_NAME_MATCH_MODE_EXACT` (the default), `_PREFIX`, `_SUFFIX` or `_CONTAINS`, or its
number. Only `pagination.offset` and `pagination.limit` apply (50 by default, 200 at most). A missing
name, unknown mode or unknown parameter is a 400, a node that cannot answer a 500. What each mode
matches is the node's, and `tempo-e2e` covers it there.
