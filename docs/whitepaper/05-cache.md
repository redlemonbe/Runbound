# 05 — Caching

> **Status: draft outline** — to be expanded from `src/dns/cache_snapshot.rs` and the
> cache code in `src/dns/server.rs`.

Key points known to be true:

- **Cache-aware fast path.** The kernel/XDP fast loop answers from a `CacheSnapshot`
  (an `ArcSwap`-published, SIMD-lookup, hickory-free structure) before falling back
  (`src/dns/kernel_loop.rs:213`). The snapshot is rebuilt and atomically swapped so the
  hot path reads a consistent view without locking.
- **Cache sizing respects cgroup v2 `memory.max`.** In a container the cache is sized
  against the cgroup limit, not host RAM, to avoid OOM.
- **serve-stale** (#108) and **negative caching** (#166) — see chapter 04.
- **XDP cache-hit accounting.** With `xdp: yes`, a per-worker miss counter
  (`XDP_WORKER_MISS`) mirrors the existing hit counter; the hit *rate* is computed in
  Rust in the snapshot path so the hot path only does a `fetch_add` on the miss branch.

## To expand
- Snapshot rebuild cadence and memory layout.
- Exact stale/negative TTL policy and the #166 SERVFAIL-vs-NXDOMAIN distinction.
