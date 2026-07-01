# 10 — Appendices

> **Status: current (v0.23.8)** — intentionally pointer-style: references
> `docs/configuration.md` and `docs/api.md` rather than duplicating them.

## A. Configuration reference
See `docs/configuration.md`. Notable directives: `xdp`, `api-port`, `api-key`,
`api-socket` (#174), `ui-bind` (default `127.0.0.1` since v0.22 — set `0.0.0.0` to expose
the WebUI on the network), `log-format` (#175, json/text), `upstream-racing`, `serve-stale`,
DoT upstreams, split-horizon, firewall.

> **Build note.** Sovereign full recursion (`src/dns/recursor_wire.rs`) and DNSSEC
> validation (`src/dns/dnssec_*.rs`) are entirely in-house and always compiled in —
> there is no `recursor` Cargo feature anymore. But both are OFF by runtime default:
> `resolution: forward` and `dnssec-validation: no` are the defaults
> (`UnboundConfig::defaults()`). Full-recursion and DNSSEC validation are opt-in via
> config (`resolution: full-recursion`, `dnssec-validation: yes`), not a compile-time
> flag. `hickory-proto` remains only as a `[dev-dependencies]` entry for the
> differential oracle tests — `cargo tree -e normal` is hickory-free.

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
minisign -Vm runbound-x86_64-linux-gnu -P "RWT4uccC0fq9zgcaMtMsdH90azvmKpsNI1xlZrzlBuGH7xx1nDftTFJr"
sha256sum -c SHA256SUMS
```
