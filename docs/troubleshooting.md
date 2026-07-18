# Troubleshooting

Common operational issues and their resolutions.

---

## Memory pressure under low-memory systems

**Behaviour:** The general query-answer cache **is** the fast-path snapshot (`xdp_cache`,
`src/dns/cache_snapshot.rs`): it stores positive **and** RFC 2308 negative answers keyed by
`(name, qtype)`, and is what `cache-size` / `cache-min-entries` / RAM-based auto-sizing cap.
`ForwardPool` (`src/dns/forward.rs`) additionally only pools upstream DoT/UDP connections and
races them — it does not cache answers. Separately, `stale_cache_wire`
(`src/dns/server.rs`) is the **serve-stale fallback store**: a
`DashMap` of the last-known-good answer per `(name, qtype)`, used only to answer queries
when all upstreams are unreachable (RFC 8767). It is sized **once at startup** — a
ceiling derived from available RAM (cgroup-aware: `memory.max` inside a container,
`/proc/meminfo` `MemAvailable` otherwise), clamped to [8192, 64M] entries. It fills as
queries arrive and evicts its own genuine-oldest entry on overflow at insert time —
it is **not** touched by the memory-pressure watchdog below (that's `xdp_cache`'s job).

The 30 s memory-pressure monitor (`memory_guard_loop`) actively shrinks `xdp_cache`
under pressure, oldest-entries-first (soonest-to-expire, via
`cache_snapshot::evict_oldest`) — `local-data` entries are never evicted. Two
watermarks (`MEM_MOD_WATERMARK` / `MEM_HIGH_WATERMARK`):

| Used memory | Action |
|---|---|
| < 70 % | No action (stable). |
| 70–80 % | `xdp_cache` is halved, floored at `cache-min-entries` (default 2048). |
| ≥ 80 % | `xdp_cache` is shrunk to a ceiling recomputed from **current** available RAM (same formula as the startup auto-sizer), floored at `cache-min-entries`; `ForwardPool` is also rebuilt (refreshes upstream/DoT connections) and the rate limiter's bucket table is cleared: |

```
WARN memory pressure high: pool rebuilt, rate limiter cleared, cache trimmed to current RAM  used_pct=82.1%  freed_buckets=4096  cache_evicted=18234  cache_len=42000
WARN memory pressure moderate: cache halved  used_pct=74.2%  cache_evicted=21000  cache_len=21000
```

Both actions only ever shrink the cache (never grow it back), and never evict below
`cache-min-entries` — a sustained high-pressure host converges to the floor within a
few 30 s ticks rather than oscillating or evicting forever. If pressure stays ≥ 80 %
even after `xdp_cache` has reached the floor, the eviction has done what it can; the
next steps below apply.

**If you are still low on memory:**
- Raise `cache-min-entries` down or leave it at the default (2048) — a lower floor lets
  the watchdog claw back more RAM under sustained pressure, at the cost of a colder
  cache (more upstream re-queries).
- Add a `MemoryMax=` directive to the systemd service file (e.g. `MemoryMax=512M` under
  `[Service]` in `runbound.service`) — the shipped unit does not set one by default, so
  the cgroup is otherwise unbounded and Runbound sizes its startup ceiling from all
  available host RAM.
- Set an explicit `cache-size:` in `runbound.conf` to cap `xdp_cache` regardless of
  available RAM.
- Reduce the workload of other processes sharing the host.
- Add swap space as a last resort.

---

## Upstream DNS unreachable — log spam every 30 s

**Symptom:** Logs show the same warning every 30 seconds indefinitely:

```
WARN Upstream DNS health check failed  upstream=2a01:cc00:2:24a::b
WARN Upstream DNS health check failed  upstream=2a01:cc00:2:24a::b
...
```

**Cause:** A permanently unreachable upstream (firewall, downed server, IPv6-only host
on an IPv4-only network) is probed repeatedly by the health check loop.

**Behaviour:** Exponential backoff is applied automatically:

| Consecutive failures | Next probe interval |
|---|---|
| 1 | 30 s (unchanged) |
| 2 | 60 s |
| 3 | 120 s |
| 4+ | 300 s (cap) |

```
WARN Upstream DNS health check failed (attempt 4) — next check in 300s  upstream=2a01:cc00:2:24a::b
```

When the upstream recovers, the backoff resets and an `INFO` message is emitted:

```
INFO upstream recovered after 8 failure(s)  upstream=2a01:cc00:2:24a::b
```

**Root cause resolution:** Check network connectivity to the upstream, verify the
forward-addr is reachable from the Runbound host, and confirm IPv6 is available if
the address is an IPv6 address.

---

## Firefox ignores Runbound — ads/tracking not blocked

**Symptom:** Runbound blocks ads correctly in Safari, Chrome, and other browsers, but
Firefox still loads ads on sites that should be blocked. Disabling Runbound has no
effect on Firefox behaviour.

**Cause:** Firefox has built-in **DNS over HTTPS (DoH)** enabled by default in many
regions. It sends DNS queries directly to a remote DoH provider (Cloudflare or Mozilla)
instead of using the system resolver. Runbound — like Unbound, Pi-hole, or any local
DNS server — is completely bypassed.

This is a Firefox policy decision, not a Runbound issue. Any local DNS resolver is
affected identically.

**Fix — disable DoH in Firefox:**

1. Open `about:preferences#privacy`
2. Scroll to **DNS over HTTPS**
3. Set to **Off**

Or via `about:config`:

```
network.trr.mode = 5
```

| `network.trr.mode` value | Behaviour |
|---|---|
| `0` | Default (DoH off, uses system DNS) |
| `2` | DoH preferred, system DNS fallback |
| `3` | DoH only — system DNS never used |
| `5` | DoH explicitly disabled |

**Alternative — point Firefox DoH at Runbound:**

If you have TLS configured (see [tls.md](tls.md)), you can keep DoH active in Firefox
but route it through Runbound instead of Cloudflare:

1. Generate a certificate: `runbound --gen-cert dns.home.arpa`
2. Add the cert to Firefox's trusted store
3. In `about:preferences#privacy` → DNS over HTTPS → **Custom** → enter `https://dns.home.arpa/dns-query`

This keeps queries encrypted while still going through your local filter.
