# 05 — Caching

File: `src/dns/cache_snapshot.rs`. The cache is built for one reader profile — XDP worker
OS threads that must never take a lock on the hot path — and one writer — the DNS server's
async task.

## 5.1 Double-buffer: DashMap writer, ArcSwap reader

- **Writer**: a `DashMap` (concurrent, lock-free inserts) holds the mutable cache
  (`src/dns/cache_snapshot.rs:6`).
- **Reader**: an `ArcSwap<HashMap>` holds an immutable **snapshot**. XDP workers call
  `load_full()` once per received batch and look up from the frozen copy with zero locking.
- A background **publish loop** clones the mutable map every **10 ms**, evicts expired
  entries, and atomically swaps the snapshot in (`src/dns/cache_snapshot.rs:9`).

### Skipping the clone when nothing changed (PERF-1 / #135)

Cloning the whole map every 10 ms is wasteful when no inserts happened. A monotonic
`CACHE_WRITE_GEN` counter is bumped on every insert; the publish loop compares it to its
last-seen value and **skips the O(n) clone** when unchanged (`src/dns/cache_snapshot.rs:91`).

## 5.2 Keys: CRC32c → u64 + IdentityHasher

The snapshot is `HashMap<u64, CacheEntry, IdentityHasherBuilder>`
(`src/dns/cache_snapshot.rs:81`). The key is the wire-QNAME pre-hashed to u64 with the same
CRC32c SSE4.2 routine as `answer_dns_wire` — **one ASM lookup path for both local zones and
cache**. `IdentityHasher` then avoids re-hashing an already-good 64-bit key (§3.2).

Because CRC32c is a 32→64-bit hash, a collision is astronomically rare but possible, so
`CacheEntry` carries `wire_qname` bytes and the lookup confirms them with the SIMD
`bytes_eq` after the hash hit (`src/dns/cache_snapshot.rs:63`, `QuestionKey::eq` at `:47`).
This is correctness insurance, not paranoia: a silent collision would serve the wrong
record.

## 5.3 Zero-copy payloads

`CacheEntry.wire_payload` is a `bytes::Bytes` (an `Arc<[u8]>` internally) holding the full
response datagram with the query ID zeroed; the worker patches bytes [0..2] with the real
QID before sending (`src/dns/cache_snapshot.rs:57`). Cloning an entry during the snapshot
publish is therefore O(1) — just an Arc refcount bump.

## 5.4 Eviction and sizing

On insert when full, Runbound evicts the **first expired** entry; if none is expired it
**skips the insert** (backpressure) rather than evicting a live entry
(`src/dns/cache_snapshot.rs:116`). Cache sizing respects cgroup v2 `memory.max` so a
container does not OOM.

## 5.5 Accounting

`XDP_CACHE_SNAPSHOT_HITS/MISSES/ENTRIES` are atomic counters read by `/api/system` and the
Prometheus handler. With `xdp: yes`, a per-worker miss counter `XDP_WORKER_MISS[64]`
mirrors the existing per-worker `XDP_WORKER_PKTS[64]` (served = hits); the hit *rate* is
computed in Rust off the hot path, so the hot path only does a `fetch_add` on the
miss/fallback branch (`src/dns/cache_snapshot.rs:106`).

## 5.6 Persistence (#29)

`save_xdp_cache`/`load_xdp_cache` serialise the DashMap to disk with `rkyv` (zero-copy
binary), prefixed with a 4-byte magic `b"RBv1"` for format detection.
