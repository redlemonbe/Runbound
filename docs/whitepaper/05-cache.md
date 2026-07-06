# 05 — Caching

File: `src/dns/cache_snapshot.rs`. The cache is built for one reader profile — XDP worker
OS threads that must never take a lock on the hot path — but there are **multiple writers**:
the DNS server's own async resolution path, and the REST API handlers whenever zones,
blacklist entries, or feeds are edited. `resync_xdp_cache`/`resync_xdp_cache_inner`
(`src/api/mod.rs`) is called from at least eight distinct handler call sites (zone reload,
blacklist add/delete, feed add/update/delete) and mutates the same `MutableCacheMap` directly
(`cache.retain(...)` to evict changed names, then `preload_into_cache` to re-insert local-data)
— see CHANGELOG #186 ("across all seven write paths").

## 5.1 Double-buffer: DashMap writer, ArcSwap reader

- **Writer**: a `DashMap` (sharded, per-shard `RwLock` — not lock-free, but contention is
  low since writes are rare: cache inserts on resolution misses, or API handlers on
  zone/blacklist/feed edits) holds the mutable cache (`MutableCacheMap`,
  `src/dns/cache_snapshot.rs:109`).
- **Reader**: an `ArcSwap<HashMap>` holds an immutable **snapshot**. XDP workers call
  `load_full()` once per received batch and look up from the frozen copy with zero locking.
- A background **publish loop** (`publish_loop`, `src/dns/cache_snapshot.rs:364`) clones the
  mutable map every **10 ms**, evicts expired entries, and atomically swaps the snapshot in.

### Skipping the clone when nothing changed (PERF-1 / #135)

Cloning the whole map every 10 ms is wasteful when no inserts happened. A monotonic
`CACHE_WRITE_GEN` counter (`src/dns/cache_snapshot.rs:120`) is bumped on every insert; the
publish loop compares it to its last-seen value and **skips the O(n) clone** when unchanged
(`src/dns/cache_snapshot.rs:374`). A forced eviction pass still runs every 256 ticks
(~2.5 s) to drop TTL-expired entries even when nothing new was inserted.

## 5.2 Keys: CRC32c → u64 + IdentityHasher

The snapshot is `HashMap<u64, CacheEntry, IdentityHasherBuilder>`
(`CacheSnapshot`, `src/dns/cache_snapshot.rs:82`). The key is the wire-QNAME pre-hashed to
u64 with the same CRC32c SSE4.2 routine as `answer_dns_wire` — **one ASM lookup path for
both local zones and cache**. `IdentityHasher` then avoids re-hashing an already-good
64-bit key (§3.2).

Because CRC32c is a 32→64-bit hash, a collision is astronomically rare but possible, so
`CacheEntry` carries `wire_qname` bytes (`src/dns/cache_snapshot.rs:66`) and the lookup
confirms them with the SIMD `bytes_eq` after the hash hit (`QuestionKey::eq` at `:48-53`).
This is correctness insurance, not paranoia: a silent collision would serve the wrong
record.

## 5.3 Zero-copy payloads

`CacheEntry.wire_payload` is a `bytes::Bytes` (an `Arc<[u8]>` internally) holding the full
response datagram with the query ID zeroed; the worker patches bytes [0..2] with the real
QID before sending (`src/dns/cache_snapshot.rs:59-60`). Cloning an entry during the snapshot
publish is therefore O(1) — just an Arc refcount bump.

## 5.4 Eviction and sizing

On insert when full, Runbound evicts the **first expired** entry; if none is expired it
**skips the insert** (backpressure) rather than evicting a live entry
(`cache_insert`, `src/dns/cache_snapshot.rs:171`). Cache sizing respects cgroup v2
`memory.max` so a container does not OOM.

## 5.5 Accounting

`XDP_CACHE_SNAPSHOT_HITS/MISSES/ENTRIES` (`src/dns/cache_snapshot.rs:113-116`) are atomic
counters read by `/api/system` and the Prometheus handler. With `xdp: yes`, a per-worker
miss counter `XDP_WORKER_MISS[64]` (`:143`) mirrors the existing per-worker
`XDP_WORKER_PKTS[64]` (`:133`, served = hits); the hit *rate* is computed in Rust off the
hot path, so the hot path only does a `fetch_add` on the miss/fallback branch.

## 5.6 Persistence (#29)

`save_xdp_cache`/`load_xdp_cache` serialise the DashMap to disk with `rkyv` (zero-copy
binary), prefixed with a 4-byte magic `b"RBv1"` for format detection.

## 5.7 Recursor infrastructure cache (#230)

Everything above is the **answer** (packet) cache. Under `resolution: full-recursion`
the iterative resolver additionally keeps an **infrastructure** cache
(`src/dns/infra_cache.rs`, added in #230) so a cache *miss* no longer re-walks from the
root every time. Before #230 each miss re-fetched every zone-cut NS set and the whole
DNSSEC chain — ~70 % of miss traffic hit the root servers and each miss cost 325 ms–1.3 s.

- **Zone-cut cache** — `zone → resolved NS addresses`, learned from referrals and consulted
  by `resolve_once`/`resolve_message` (`src/dns/recursor_wire.rs`, via `zone_cut_start` /
  `zone_cut_learn`). A descent starts at the deepest cached enclosing cut instead of the
  root; a stale/dead cached cut is forgotten (`zone_cut_forget`) and the descent falls back
  to a fresh root walk — the cache can only speed resolution up, never break it. A **DS**
  query is anchored at the *parent* zone (`cached_start`), never at the zone's own cut,
  otherwise it would ask the child for its own DS and fail the chain to Bogus.
- **Validated-DNSKEY cache** — `zone → DNSSEC-validated DNSKEY rdatas`
  (`src/dns/dnssec_chain.rs::trusted_keys_for`), reusing cuts it already validated (the root
  DNSKEY effectively once per ~48 h, not per miss).

Both are TTL-honouring (`min(record TTL, cap)`; DNSKEY entries additionally bounded by their
RRSIG signature-expiry so a rolled/revoked key is not reused past its signature validity),
bounded, and evicted sampled-LRU. **Fail-closed is preserved**: a DNSKEY is cached only
after a Secure result, an expired entry is ignored (forcing re-validation), and every served
answer is still DNSSEC-validated regardless of which cached cut was used. Measured on the
production master: three NXDOMAIN misses under the same parent collapse from ~240 ms (cold)
to ~55 ms (warm).
