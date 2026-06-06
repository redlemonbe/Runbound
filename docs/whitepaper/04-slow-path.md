# 04 — The slow path (hickory-server)

The slow path is a full [hickory](https://github.com/hickory-dns/hickory-dns) stack
(`hickory-server`/`-resolver`/`-proto` 0.26) in `src/dns/server.rs`. It handles everything
the fast paths decline. Its per-request pipeline (`src/dns/server.rs:5`):

1. **ACL check** per source IP (from `unbound.conf`) — `src/dns/acl.rs`.
2. **Rate limit** per source IP, token bucket, default 200 qps (`RATE_LIMIT_QPS_DEFAULT`,
   `src/dns/server.rs`).
3. **Local zones** (local-data, blacklist, feeds) in memory → instant answer.
4. Otherwise → **recursive resolver** (hickory-resolver), UDP+TCP on the configured port.

## 4.1 Backpressure against flood — a hard inflight cap

hickory-server spawns one Tokio task per incoming request **with no backpressure**; under
a flood this exhausts RAM. Runbound bounds it with a semaphore of `MAX_INFLIGHT_REQUESTS =
4096` (`src/dns/server.rs:62`). A **non-blocking** `try_acquire` returns `REFUSED`
instantly without allocating, so the bound holds even at line rate. This is a deliberate
availability trade-off: shed load rather than OOM.

## 4.2 Recursion, racing, and the hard timeout

- **Upstream racing** (`upstream-racing: yes`): the resolver issues queries to multiple
  upstreams in parallel and takes the first success via `futures_util::future::select_ok`
  (`src/dns/server.rs`).
- **Hard lookup timeout** (#83): resolver lookups are wrapped in a hard timeout to prevent
  a stuck upstream from pinning a task/Tokio worker indefinitely (a deadlock root cause
  that was measured and fixed).
- **TLS** via `rustls` 0.23 (TLS 1.2 + 1.3) for DoT/DoH/DoQ.
- **TSIG** supported (`hickory_proto::rr::rdata::tsig`).

## 4.3 Upstream health monitoring

`src/upstreams.rs` probes upstreams every 30 s (2 s timeout):

- **UDP upstreams**: a 28-byte DNS probe for `. IN A` carrying an EDNS0 OPT RR with the
  **DO bit set** (`DNS_PROBE_PACKET`, `src/upstreams.rs:39`). The reply confirms liveness
  and the **AD bit** reveals whether the upstream does DNSSEC validation.
- **DoT upstreams**: a TCP+TLS connect+handshake (no DNS query needed).
- **Backoff** on failure: 30 → 60 → 120 → 300 s cap, so a dead upstream does not spam
  logs; recovery resets the backoff and logs an INFO line.

## 4.4 Caching hand-off

A cache hit on the slow path is currently inferred from latency: a lookup under
`CACHE_HIT_THRESHOLD_US` counts as a hit (`src/dns/server.rs`, `crate::stats`). This is why
the master node's hit-rate metric is meaningful only with `xdp: no`. The authoritative XDP
cache accounting uses dedicated counters (chapter 05).

## To expand (verify against code)
- Negative caching state machine (RFC 2308, #166): NXDOMAIN cached vs SERVFAIL treated as
  transient (must not be cached long — false-negative trap).
- serve-stale (#108) exact TTL policy.
- resolv.conf emergency fallback (#94).
