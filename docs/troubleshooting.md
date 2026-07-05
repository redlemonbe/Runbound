# Troubleshooting

Common operational issues and their resolutions.

---

## Memory pressure under low-memory systems

**Behaviour:** There is no general query-answer cache in this architecture (outside the
XDP fast-path snapshot). `ForwardPool` (`src/dns/forward.rs`) only pools upstream
DoT/UDP connections and races them — it does not cache answers. The structure that
`cache-min-entries` / `cache-size` / RAM-based auto-sizing actually govern is
`stale_cache_wire`, the **serve-stale fallback store** (`src/dns/server.rs`): a
`DashMap` of the last-known-good answer per `(name, qtype)`, used only to answer queries
when all upstreams are unreachable (RFC 8767). It is sized **once at startup** — a
ceiling derived from available RAM (cgroup-aware: `memory.max` inside a container,
`/proc/meminfo` `MemAvailable` otherwise), clamped to [8192, 64M] entries. It fills as
queries arrive; it is never forcibly shrunk at runtime.

**This entire section only matters if serve-stale is enabled** (`serve-stale: yes`,
which is the default — check your `runbound.conf` if unsure). `stale_cache_wire` is
only allocated when serve-stale is on; with `serve-stale: no`, none of the
sizing/watermark logic below touches anything real — every query goes straight
upstream, uncached, on every request. The `cache-min-entries` config directive still
parses and round-trips for backward compatibility with existing config files, but has
no runtime effect (there is nothing to floor).

The 30 s memory-pressure monitor (`memory_guard_loop`) still runs, with 70 % / 80 %
watermarks (`MEM_MOD_WATERMARK` / `MEM_HIGH_WATERMARK`), but its actions changed:

| Used memory | Action |
|---|---|
| < 70 % | No action (stable). |
| 70–80 % | Logged at `debug` only — no cache resize. |
| ≥ 80 % | `ForwardPool` is rebuilt with the same target size (refreshes upstream/DoT connections), cache stats counters are reset, and the rate limiter's bucket table is cleared to free memory: |

```
WARN memory pressure high: pool rebuilt, rate limiter cleared  used_pct=82.1%  freed_buckets=4096
```

**If you are still low on memory:**
- Add a `MemoryMax=` directive to the systemd service file (e.g. `MemoryMax=512M` under
  `[Service]` in `runbound.service`) — the shipped unit does not set one by default, so
  the cgroup is otherwise unbounded and Runbound sizes its startup ceiling from all
  available host RAM.
- Set an explicit `cache-size:` in `runbound.conf` to cap the serve-stale store
  regardless of available RAM (only relevant if `serve-stale: yes`).
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
