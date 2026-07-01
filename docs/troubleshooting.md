# Troubleshooting

Common operational issues and their resolutions.

---

## Memory pressure under low-memory systems (cache no longer shrinks to zero)

**Historical symptom (v0.5.0 and earlier, hickory-based resolver cache):** Logs showed
repeated `memory pressure — cache halved` messages every 30 s, and on RAM-constrained
hosts the cache could eventually be halved down to 0, sending all queries upstream.
This was fixed in v0.5.1 with a floor (`cache-min-entries`), a 5-minute cooldown, and
no-effect detection.

**Current behaviour (current de-hickory architecture, v0.23.x):** The DNS cache now lives in
`ForwardPool` and is sized **once at startup** — a ceiling derived from available RAM
(cgroup-aware: `memory.max` inside a container, `/proc/meminfo` `MemAvailable`
otherwise), clamped to [8192, 64M] entries. It fills as queries arrive; it is never
forcibly shrunk at runtime, so the "cache halved to 0" failure mode described above
cannot recur. The `cache-min-entries` config directive still parses and round-trips
for backward compatibility with existing config files, but no longer has any runtime
effect (there is nothing left to floor).

The 30 s memory-pressure monitor (`memory_guard_loop`) still runs, with the same 70 %
/ 80 % watermarks, but its actions changed:

| Used memory | Action |
|---|---|
| < 60 % | No action (stable). |
| 60–80 % | Logged at `debug` only — no cache resize. |
| ≥ 80 % | `ForwardPool` is rebuilt with the same target size (refreshes upstream/DoT connections), cache stats counters are reset, and the rate limiter's bucket table is cleared to free memory: |

```
WARN memory pressure high: pool rebuilt, rate limiter cleared  used_pct=82.1%  freed_buckets=4096
```

**If you are still low on memory:**
- Increase `MemoryMax` in the systemd service file (e.g. `MemoryMax=512M`) so the
  cgroup gives Runbound more headroom to size its startup cache ceiling from.
- Set an explicit `cache-size:` in `runbound.conf` to cap the cache regardless of
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
