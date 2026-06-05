# XDP cache ↔ local-zone unification

## Problem (measured, 2026-06-05, AMD 5995WX + X520, xdp:yes resolver)

`answer_dns_wire` (local-zone) and `answer_from_cache` (resolver cache) do the **same
thing** — read a stored wire DNS response by qname and serve it — yet diverged into two
code paths, and the cache one is far slower.

| Path | qname → key | map | hash at lookup |
|------|-------------|-----|----------------|
| local-zone `answer_dns_wire` | `hash_wire_qname` = CRC32c (SSE4.2) | identity-hasher `wire_records.map` | **0** (key IS the hash) |
| cache `answer_from_cache` | raw wire bytes (`QuestionKey`) | `HashMap` std default | **SipHash** (crypto, ~10×) per lookup |

Plus the cache hot path carried per-packet stats added in v0.9.9 (`169092b`): a `String`
alloc (`domain_stats.inc(wire_qname_to_str(..))`) + a global `XDP_CACHE_SNAPSHOT_HITS`
atomic, hammered by every worker.

Net effect under a 13M pps flood over 10k real names: `perf stat` IPC **0.11** (memory/
atomic stall), served collapsed to **278k qps**; the cache was SLOWER than the static
local-zone path.

## What we fixed (shipped / branches)
- **Removed the per-packet stats** from the cache hot path (total is already counted per
  worker by `XDP_WORKER_PKTS`; `qps_update_loop` sums it): **278k → 10.6M dual**.
- `ahash` (AES-NI) instead of SipHash on the snapshot: partial (branch `perf/drop-cache-stats`).
- Residual `rx_no_dma ≈ 4.4M/s` = the lookup is still not the local-zone routine.

## Target architecture (the real fix — issue #165)
**One fast path, one slow path, zero special-casing.**
- **Fast path = cache lookup only**, using the local-zone routine: `hash_wire_qname` (CRC32c)
  → identity-hasher map → SIMD `bytes_eq`. The separate `answer_dns_wire` branch is removed.
- **local-data = a racing upstream.** On a cache miss the slow path races
  `[local-data + network upstreams]`, first-to-respond wins, the winner is cached. local-data
  is an in-memory 0-latency lookup → wins for names it owns.
  - **Hard rule: local-data ABSTAINS when it does not have the name** (must not return an
    instant NXDOMAIN, which would beat the network upstreams).
- The slow path is the only place that knows about "sources" (config vs upstream); it only
  **populates the cache**. The fast path serves everything uniformly from the cache.

Bench acceptance: `rx_no_dma → ~0`, served → toward line-rate (X520 ~13M single / ~16M dual),
`perf stat` IPC back to a healthy range.
