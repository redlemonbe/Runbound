# 10 — Appendices

> **Status: draft outline** — generated references to be cross-linked with
> `docs/configuration.md` and `docs/api.md` rather than duplicated.

## A. Configuration reference
See `docs/configuration.md`. Notable directives: `xdp`, `api-port`, `api-key`,
`api-socket` (#174), `log-format` (#175, json/text), `upstream-racing`, `serve-stale`,
DoT upstreams, split-horizon, firewall.

## B. API reference
See `docs/api.md`. Endpoint groups: zones, blacklist/feeds, upstreams, `/system`, stats,
`/api/events` (SSE), `/api/backup` (export/import), split-horizon, relay.

## C. Environment escape hatches
- `RUNBOUND_API_KEY` — API key via env (preferred over config).
- `RUNBOUND_DISABLE_XDP=1` — force the kernel UDP path.

## D. Glossary
XDP, AF_XDP, UMEM, XSKMAP, CPUMAP, RSS, ZC (zero-copy), DRV/SKB mode, EDNS0, DO bit,
TOFU, SO_REUSEPORT, cgroup v2 `memory.max`.

## E. Verifying a release
```
minisign -Vm runbound-x86_64-linux-gnu -P "RWQHTbP57y/xH3OD6tvg2oi8LeyuQ9YYxVen+oeOCyKqTXfV2cCypAk0"
sha256sum -c SHA256SUMS
```
