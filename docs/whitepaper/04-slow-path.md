# 04 — The slow path (hickory-server)

> **Status: draft outline.** Chapters 01–03 are written against the source line-by-line.
> This chapter states what is structurally true today; the line-level detail will be
> filled in from `src/dns/server.rs` (≈3000 lines) and `src/upstreams.rs`. Anything not
> yet verified against the code is marked **"to verify."**

The slow path is a full [hickory-server](https://github.com/hickory-dns/hickory-dns)
(`hickory-server`/`-resolver`/`-proto` 0.26). It handles everything the fast paths
deliberately decline:

- **Recursion / forwarding** — cache miss resolved upstream. Upstream racing
  (`upstream-racing: yes`) queries multiple upstreams in parallel and takes the first
  answer (`src/upstreams.rs`, to verify).
- **TCP, DoT (853), DoH, DoQ** — TLS via `rustls` 0.23 (tls12+tls13). `XDP_PASS` ensures
  these reach the kernel and hence hickory.
- **DNSSEC validation** — DO-bit queries are routed here (the wire path returns
  `Fallback`).
- **Complex record types** — CNAME, MX, TXT, NS, SOA, SRV, CAA, TSIG, AXFR.
- **serve-stale** (#108) — serve expired cache entries when upstreams are unreachable,
  per the stale cache in `server.rs` (to verify the exact TTL policy).
- **resolv.conf emergency fallback** (#94).

The slow path is demoted to a fallback by Tiers 1–2 (chapter 01). The instruction-count
motivation (1.78× vs Unbound on the naïve path) is in §1.2.

## To expand
- Exact dispatch from `FallbackMsg` to the hickory handler.
- Negative caching (RFC 2308) state machine — see #166: NXDOMAIN cached vs SERVFAIL
  transient (must NOT be cached long, false-negative trap).
- Upstream selection, health, and DoT reconnect logic.
