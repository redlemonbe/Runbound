# Troubleshooting

Common operational issues and their resolutions.

---

## Cache shrinks to zero on low-memory systems

**Symptom:** Logs show repeated `memory pressure — cache halved` messages every 30 s,
the cache eventually reaches 0, and all queries go upstream.

```
WARN memory pressure — cache halved  used_pct=73.2%  cache_from=65536  cache_to=32768
WARN memory pressure — cache halved  used_pct=72.8%  cache_from=32768  cache_to=16384
WARN memory pressure — cache halved  used_pct=72.6%  cache_from=16384  cache_to=8192
...
```

**Cause:** Runbound monitors system-wide RAM pressure via `/proc/meminfo`. On systems
with less than 4 GB RAM where other processes consume significant memory, the 70 %
pressure threshold may be permanently exceeded. Cache eviction frees Rust allocations,
but jemalloc retains freed memory in its pool — system RSS does not decrease enough to
clear the threshold, so halvings continue indefinitely.

**Fix (v0.5.0 and earlier):** Add to `unbound.conf`:

```
server:
    cache-min-entries: 2048
```

**Fix (v0.5.1+):** The cache floor, cooldown, and no-effect detection are enforced
automatically. The default `cache-min-entries: 2048` prevents the cache from being
destroyed. If halvings have no measurable effect, Runbound logs a single `WARN` and
stops halving:

```
WARN cache halving has no effect on memory pressure (pct before=73.0% after=72.6%) —
     cache floor reached, consider increasing MemoryMax in the service file or reducing other workloads
```

**Root cause resolution:** If the warning persists, the system is genuinely memory-
constrained. Options:
- Increase `MemoryMax` in the systemd service file (e.g. `MemoryMax=512M`)
- Reduce the workload of other processes sharing the host
- Lower `cache-min-entries` to `1024` or `512` to free more cache memory
- Add swap space as a last resort

---

## Upstream DNS unreachable — log spam every 30 s

**Symptom:** Logs show the same warning every 30 seconds indefinitely:

```
WARN Upstream DNS health check failed  upstream=2a01:cc00:2:24a::b
WARN Upstream DNS health check failed  upstream=2a01:cc00:2:24a::b
...
```

**Cause (v0.5.0 and earlier):** The health check loop probed every upstream every 30 s
regardless of how many consecutive failures had occurred. A permanently unreachable
upstream (firewall, downed server, IPv6-only host on an IPv4-only network) produced
120+ log lines per hour.

**Fix (v0.5.1+):** Exponential backoff is applied automatically:

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
