# REST API Reference

Runbound exposes a REST API on **localhost only** (HTTP). The port defaults to
**8080** and is configurable with `api-port` in `runbound.conf`. All endpoints
require a Bearer token. `GET /health` is the only unauthenticated endpoint (liveness probe).

> **Looking for a GUI?** A ready-made browser dashboard is served directly by Runbound (default `https://<host>:8091`). See [web-ui.md](web-ui.md).

---

## Authentication

```bash
export RUNBOUND_API_KEY="$(cat /etc/runbound/api.key)"
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/dns
```

Timing-safe comparison is used server-side (constant-time, immune to timing attacks).

**Rate limiting:** The API is rate-limited to **30 requests/second per IP** with a burst allowance of 60.

**Request body size:** All `POST` requests must be ≤ **64 KiB**. Larger payloads return HTTP `413 Content Too Large`.

---

## Endpoints

### DNS entries

Local DNS records — equivalent to `local-data` in the config file, but live.
Changes take effect immediately. No restart required.

> **Write performance:** The zone store uses a copy-on-write design (`ArcSwap`). Each
> `POST` or `DELETE` clones the full zone map, applies the change, then atomically
> swaps the pointer. Active DNS queries keep their old snapshot until they finish;
> new queries immediately see the updated zone. Read throughput is unaffected during
> writes — there are no locks on the hot query path.

#### `GET /api/dns`

List all local DNS entries.

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/dns
```

```json
{
  "entries": [
    {"id": "550e8400-...", "name": "nas.home.", "type": "A", "value": "192.168.1.10", "ttl": 300}
  ],
  "total": 1
}
```

#### `GET /api/dns/:id`

Fetch a single local DNS entry by its UUID (the `id` field from `GET /api/dns`).
Returns `404` if no entry has that id.

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  http://localhost:8080/api/dns/550e8400-e29b-41d4-a716-446655440000
```

```json
{"entry": {"id": "550e8400-...", "name": "nas.home.", "type": "A", "value": "192.168.1.10", "ttl": 300}}
```

The entry is wrapped in an `"entry"` object. Its fields mirror one element of the
`entries` array from `GET /api/dns`: `id`, `name`, `type`, `ttl`, plus whatever
record-specific fields apply (`value` for A/AAAA/CNAME/TXT/PTR/NS, `priority` for
MX/SRV, `weight`/`port` for SRV, `flags`/`tag` for CAA, etc.). Optional fields are
omitted when unset.

#### `POST /api/dns`

Add a local DNS entry.

```bash
curl -X POST http://localhost:8080/api/dns \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"nas.home.","type":"A","value":"192.168.1.10","ttl":300}'
```

```json
{"status": "ok", "entry": {"id": "550e8400-...", ...}, "rr": "nas.home. 300 A 192.168.1.10"}
```

**Supported types:** `A`, `AAAA`, `CNAME`, `TXT`, `MX`, `SRV`, `CAA`, `PTR`,
`NAPTR`, `SSHFP`, `TLSA`, `NS`

**TTL:** Optional. Default: 3,600 s (1 hour). Must be in range 0–2,147,483,647 (RFC 2181 §8). Capped at 86,400 s (24 h) server-side. Returns `422 INVALID_TTL` if out of range.

**Limit:** Maximum 10,000 entries. Returns `422` when exceeded.

#### `DELETE /api/dns/:id`

Remove an entry by its UUID (from the `id` field of `GET /dns`).

```bash
# First get the UUID:
ID=$(curl -s -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/dns \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['entries'][0]['id'])")

curl -X DELETE "http://localhost:8080/api/dns/$ID" \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

```json
{"status": "ok", "deleted_id": "550e8400-..."}
```

#### `POST /api/dns/lookup`

Perform a live DNS resolution via the configured resolver, with cache visibility.
Useful for debugging and validating blocklist/DNSSEC behaviour from the UI or API.

```bash
curl -X POST http://localhost:8080/api/dns/lookup \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"google.com","type":"A"}'
```

```json
{
  "name":       "google.com",
  "type":       "A",
  "answers": [
    {"ttl": 300, "data": "142.250.179.46"}
  ],
  "status":     "NOERROR",
  "elapsed_ms": 14,
  "from_cache": false
}
```

Blocked domain example (matches a local blacklist / block-page zone):

```json
{
  "name":       "ads.example.com",
  "type":       "A",
  "answers":    [],
  "status":     "BLOCKED",
  "elapsed_ms": 0,
  "from_cache": false
}
```

**Response fields:**

| Field | Type | Notes |
|-------|------|-------|
| `name` | string | Echoes the requested name (as sent, trailing dot preserved). |
| `type` | string | Echoes the requested record type. |
| `answers` | array | Zero or more `{ "ttl": u32, "data": "<presentation-form rdata>" }`. Empty for a blocked, NXDOMAIN, NODATA, REFUSED or SERVFAIL result. |
| `status` | string | `"NOERROR"`, `"BLOCKED"` (matched a local block rule), `"NXDOMAIN"`, `"NODATA"`, `"REFUSED"`, or `"SERVFAIL"`. |
| `elapsed_ms` | u64 | Resolution time in milliseconds (`0` when answered locally). |
| `from_cache` | bool | `true` when served from a local static zone, or when the upstream answer came back fast enough (< cache-hit threshold) to be counted as a cache hit. |

**Fields:**

| Field | Required | Default | Notes |
|-------|----------|---------|-------|
| `name` | Yes | — | Domain name (trailing dot optional) |
| `type` | No | `"A"` | Record type: `A`, `AAAA`, `MX`, `TXT`, `CNAME`, `PTR`. Returns `400 INVALID_TYPE` for anything else (`NS`/`SOA` are **not** supported by this endpoint). |

---

### Blacklist

Block domains — equivalent to `local-zone: "domain." always_nxdomain`, but live.

#### `GET /api/blacklist`

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/blacklist
```

```json
{"blacklist": [{"id": "...", "domain": "ads.example.com", "action": "nxdomain"}], "total": 1}
```

#### `POST /api/blacklist`

```bash
curl -X POST http://localhost:8080/api/blacklist \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain":"ads.example.com","action":"nxdomain"}'
```

**Actions:** `refuse` (REFUSED response), `nxdomain` (NXDOMAIN response)

**Limit:** Maximum 100,000 entries. Returns `422` when exceeded.

#### `DELETE /api/blacklist/:id`

Remove by UUID.

```bash
curl -X DELETE "http://localhost:8080/api/blacklist/$ID" \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

#### XDP fast-path blacklist

When XDP is active, blacklisted domains are pushed into a BPF hash map
(`dns_blacklist`, 500 000 entries). IPv4 DNS queries matching a blocked domain are
answered with **NXDOMAIN in-place at the XDP layer** — no kernel stack, no slow-path
overhead (~1 µs RTT).

- IPv6 queries for blocked domains fall through to the wire-native slow path (still blocked).
- The map is updated atomically after every `POST /api/blacklist` and `DELETE /api/blacklist/:id`.
- `GET /api/blacklist` includes `xdp_active: true` when the BPF map is loaded.

---

### Feeds

Subscribe to remote block-list feeds. Feeds auto-refresh every 24 hours.

#### `GET /api/feeds`

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/feeds
```

```json
{
  "feeds": [
    {
      "id": "...",
      "name": "urlhaus",
      "url": "https://...",
      "enabled": true,
      "entry_count": 8432,
      "blocked_count": 8432,
      "last_updated": "2026-05-16T10:00:00Z",
      "last_error": null
    }
  ],
  "total": 1
}
```

`last_error` is `null` on success, or a short error string (e.g. `"connection timeout"`) when the last refresh failed. A feed with a non-null `last_error` still serves its previously loaded entries.

`blocked_count` is the number of domains from this feed currently active in the blocklist (always ≤ `entry_count`; can differ if duplicate domains are deduplicated across feeds).

#### `POST /api/feeds`

Subscribe to a new feed. **Limit: 100 feeds maximum.**

```bash
curl -X POST http://localhost:8080/api/feeds \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"urlhaus","url":"https://urlhaus.abuse.ch/downloads/hostfile/","format":"hosts","action":"nxdomain"}'
```

**formats:** `hosts` (default), `domains`, `adblock`  
**Security:** Only HTTPS is accepted. HTTP URLs are **rejected** (HTTP 400). Redirects to private IPs or internal hostnames are blocked.

#### `GET /api/feeds/presets`

List built-in feed presets (OISD, StevenBlack, Hagezi, URLhaus, AdGuard...).

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/feeds/presets
```

#### `DELETE /api/feeds/:id`

Remove a feed subscription by UUID.

```bash
curl -X DELETE "http://localhost:8080/api/feeds/$ID" \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

#### `POST /api/feeds/update`

Refresh all enabled feeds immediately.

```bash
curl -X POST http://localhost:8080/api/feeds/update \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

```json
{"status": "ok", "results": [...], "summary": {"updated": 2, "errors": 0}}
```

#### `POST /api/feeds/:id/update`

Refresh a single feed by UUID.

```bash
curl -X POST "http://localhost:8080/api/feeds/$ID/update" \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

---

### `GET /health`

Liveness probe. **No authentication required.**

```bash
curl http://localhost:8080/health
```

```json
{
  "status":              "ok",
  "node":                "a1b2c3d4-e5f6-...",
  "uptime_secs":         3600,
  "xdp_active":          true,
  "upstreams_healthy":   4,
  "upstreams_total":     4,
  "cache_entries":       48231,
  "reason":              null
}
```

---

### `GET /api/stats`

Query statistics snapshot: counters, QPS, latency percentiles, cache metrics.

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/stats
```

```json
{
  "total":           125432,
  "total_queries":   125432,
  "blocked":         8921,
  "forwarded":       112000,
  "nxdomain":        4500,
  "stale_served":    12,
  "refused":         8921,
  "servfail":        11,
  "local_hits":      3200,
  "blocked_percent": 7.1,
  "uptime_secs":     3600,
  "qps_1m":          34.7,
  "qps_5m":          31.2,
  "qps_peak":        410,
  "latency_p50_ms":  0.3,
  "latency_p95_ms":  4.2,
  "latency_p99_ms":  22.5,
  "latency_min_ms":  0.1,
  "latency_avg_ms":  1.4,
  "latency_max_ms":  55.0,
  "cache_hit_rate":  68.4,
  "cache_hits":      76500,
  "cache_misses":    35500,
  "xdp_cache_hits":  0,
  "cache_entries":   2941,
  "dnssec": {
    "secure":   1042,
    "bogus":    3,
    "insecure": 897
  },
  "latency_windows": {
    "1m":  {"min_ms": 0.1, "avg_ms": 1.2, "max_ms": 42.0, "count": 2081},
    "5m":  {"min_ms": 0.1, "avg_ms": 1.4, "max_ms": 55.0, "count": 10402}
  },
  "qtype_stats": [
    {"type": "A",    "count": 90211},
    {"type": "AAAA", "count": 30122}
  ],
  "xdp_ifaces": [],
  "xdp_queues": []
}
```

> `xdp_ifaces` and `xdp_queues` are added by the `GET /api/stats` handler only —
> they are **not** part of the raw stats snapshot and are absent from the
> `GET /api/stats/stream` payload (see below).

**Counter semantics:**

| Field | What it counts |
|---|---|
| `blocked` | Queries answered with **REFUSED** — blacklist / feeds / local-zone with `action: refuse`, or a subnet policy (#8) |
| `nxdomain` | Queries answered with **NXDOMAIN** — blacklist / feeds with `action: nxdomain`, or upstream NXDOMAIN |
| `forwarded` | Queries sent to an upstream resolver (network round-trip) |
| `local_hits` | Queries answered from local zone data (config + `POST /dns`) without upstream |
| `servfail` | Upstream returned SERVFAIL or DNSSEC validation failed |
| `blocked_percent` | `blocked / total × 100` — REFUSED blocking rate (f64, one decimal place) |
| `qps_1m` / `qps_5m` | Average queries/second over the last 1 and 5 minutes |
| `qps_peak` | All-time highest queries in any single second |
| `latency_p50/95/99_ms` | Latency percentiles from a fixed 10-bucket histogram (zero-alloc) |
| `cache_hit_rate` | Percentage of lookups served from the in-process DNS cache (`cache_hits / (cache_hits + cache_misses) × 100`) |
| `cache_hits` / `cache_misses` | Canonical cache hit/miss counters (slow path + XDP fast-path workers, summed) |
| `xdp_cache_hits` | Cache hits served specifically by the XDP fast path (subset of `cache_hits`) |
| `cache_entries` | Approximate distinct domains cached |
| `total_queries` | Alias of `total` (same value; kept for dashboard compatibility) |
| `stale_served` | Answers served from an expired cache entry (serve-stale, RFC 8767) |
| `latency_min_ms` / `latency_avg_ms` / `latency_max_ms` | Min / mean / max response latency (ms) since start |
| `latency_windows` | Per-window `{min_ms, avg_ms, max_ms, count}` latency map (e.g. `1m`, `5m`) |
| `qtype_stats` | Array of `{type, count}` — per-record-type query counters |
| `xdp_ifaces` / `xdp_queues` | Per-interface / per-queue AF_XDP state; `[]` when XDP is inactive. Present only on `GET /api/stats`, not on the stream. |
| `dnssec.secure` | Queries validated with a full RRSIG chain (requires `dnssec-validation: yes`) |
| `dnssec.bogus` | Queries where DNSSEC validation failed — potential tampering or misconfiguration |
| `dnssec.insecure` | Queries for zones with no DNSSEC signatures (unsigned delegations) |

**Total blocked = `blocked` + `nxdomain`.** The split exists because `refuse` and `nxdomain` are distinct DNS responses. Use `blocked_percent` or sum both fields for an aggregate blocking rate.

**DNSSEC counters** are always present in the response but are meaningful only when `dnssec-validation: yes` is configured.

---

### `GET /api/stats/stream`

Live stats as Server-Sent Events — one JSON snapshot per second. Ideal for dashboards.

```bash
curl -N -H "Authorization: Bearer $RUNBOUND_API_KEY" \
     http://localhost:8080/api/stats/stream
```

```
data: {"total":125432,"blocked":8921,...,"qps_1m":34.7,"latency_p50_ms":0.3}

data: {"total":125465,"blocked":8921,...,"qps_1m":34.9,"latency_p50_ms":0.3}
```

The stream is a standard SSE event stream (`Content-Type: text/event-stream`). The connection stays open until the client closes it.

> **Not identical to `GET /api/stats`.** Each `data:` line is the raw stats snapshot
> (`snapshot_to_json`): it carries `total`, `blocked`, `qps_*`, `latency_*`, `cache_*`,
> `dnssec`, `latency_windows`, `qtype_stats`, etc., but **omits** the `xdp_ifaces` and
> `xdp_queues` keys, which the non-streaming `GET /api/stats` handler appends on top.

> The `-N` flag disables curl's output buffering — required to see events in real time.

---

### `GET /api/stats/top-domains`

Most-queried domain names since process start, sorted by query count descending.
Tracks up to 10,000 distinct domains. Counter is cumulative (not windowed).

> Slow-path domain counting is done on the in-house wire serving path (`serve_wire`), so
> top-domains is populated on every path (forward, full-recursion, local, etc.).

| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | integer | 10 | Number of results (1–100) |

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" \
     "http://localhost:8080/api/stats/top-domains?limit=20"
```

```json
{
  "top_queried": [
    { "domain": "google.com.", "count": 4821 },
    { "domain": "cloudflare.com.", "count": 3102 },
    { "domain": "github.com.", "count": 1844 }
  ],
  "tracked_domains": 312
}
```

`tracked_domains` is the current number of distinct domains in the in-memory map (max 10,000).
Once the cap is reached, new domains are silently ignored until the process restarts.

---

### `GET /api/logs`

Recent DNS query log, newest first. Entries are kept in a fixed-size ring buffer pre-allocated at startup (zero allocation per query). The buffer size is controlled by `log-retention` in `runbound.conf` (default: **1,000**, compile-time max: 10,000). Set to `0` to disable the buffer entirely.

> Query logging is populated by the in-house wire serving path (`serve_wire`): every served
> query is logged on every path (forward, full-recursion, local, AXFR, DDNS, TSIG, etc.).

```bash
# Last 100 queries (default)
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/logs

# Blocked queries only
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" \
     "http://localhost:8080/api/logs?action=blocked&limit=50"

# Filter by client IP
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" \
     "http://localhost:8080/api/logs?client=192.168.1.10"

# Queries since a Unix timestamp
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" \
     "http://localhost:8080/api/logs?since=1747483200"
```

```json
{
  "entries": [
    {
      "ts":         "2026-05-17T14:23:05Z",
      "name":       "ads.example.com.",
      "client":     "192.168.1.42",
      "qtype":      1,
      "action":     "blocked",
      "elapsed_ms": 0
    },
    {
      "ts":         "2026-05-17T14:23:04Z",
      "name":       "google.com.",
      "client":     "192.168.1.10",
      "qtype":      1,
      "action":     "forwarded",
      "elapsed_ms": 23
    }
  ],
  "total": 2,
  "page":  0,
  "limit": 100
}
```

**Query parameters:**

| Parameter | Default | Description |
|---|---|---|
| `limit` | `100` | Max entries per page (1–1000). Returns `422` if > 1000. |
| `page` | `0` | Zero-based page number. |
| `action` | — | Filter by action: `forwarded`, `cached`, `local`, `blocked`, `nxdomain`, `refused`, `servfail`. Returns `400` if invalid. |
| `client` | — | Filter by client IP address. Returns `400` if not a valid IP. |
| `since` | — | Return only entries with `ts ≥ since` (Unix timestamp in seconds). |

**Action values:**

| Action | Meaning |
|---|---|
| `forwarded` | Network round-trip to upstream (cache miss) |
| `cached` | Served from the in-process DNS cache (< 2 ms) |
| `local` | Answered from local zone data (config or `POST /dns`) |
| `blocked` | Domain blocked by blacklist, feeds, or a subnet policy (#8) |
| `nxdomain` | NXDOMAIN from upstream or local zone |
| `refused` | REFUSED (ACL, rate limit, CHAOS class, etc.) |
| `servfail` | SERVFAIL (resolver error or private-address block) |

**Note:** the `name` field is truncated to 253 characters (RFC 1035 max); `qtype` is the raw DNS RR type number (1 = A, 28 = AAAA, 15 = MX, etc.).

The ring buffer capacity is controlled by `log-retention` in `runbound.conf` (default: 1000). Set to `0` to disable it entirely. When `log-client-ip: no` is set, the `client` field contains `[redacted]` instead of the real IP.

---

### `DELETE /api/logs`

Clear the in-memory query log ring buffer immediately. Useful for responding to a
GDPR right-to-erasure request.

```bash
curl -X DELETE -H "Authorization: Bearer $RUNBOUND_API_KEY" \
     http://localhost:8080/api/logs
```

```json
{
  "message":         "log buffer cleared",
  "entries_deleted": 47
}
```

**Notes:**
- Clears only the **in-memory ring buffer** — does not truncate the logfile on disk (manage those with `logrotate`).
- Does **not** clear the audit log. The deletion is recorded in the audit log as `event: "logs_clear"` with `entries_deleted`, providing a tamper-evident trace.

---

### `GET /api/config`

Dump active configuration (sanitised — API key is omitted).

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/config
```

```json
{
  "port": 53,
  "interfaces": ["0.0.0.0"],
  "forward_zones": [{"name": ".", "addrs": ["1.1.1.1@853"], "tls": true}],
  "file_local_zones": 2,
  "file_local_data": 4,
  "api_dns_entries": 3,
  "api_blacklist": 12,
  "api_feeds": 2,
  "access_control": ["192.168.1.0/24 allow"],
  "private_addresses": ["10.0.0.0/8"],
  "rate_limit": 200,
  "rate_limit_burst": 400,
  "cache_max_ttl": 86400,
  "dnssec_validation": false,
  "resolution_mode": "forward",
  "log_retention": 1000,
  "log_client_ip": true,
  "api_port": null,
  "logfile": null,
  "hsm": {
    "active": false,
    "pkcs11_lib": null,
    "slot": 0,
    "pin": null,
    "api_key_label": null,
    "store_key_label": null
  }
}
```

**Note on entry counts:** `file_local_data` and `file_local_zones` reflect only what is
in `runbound.conf`. Entries added via REST API (`POST /dns`, `POST /blacklist`, feeds)
appear in `api_dns_entries`, `api_blacklist`, and `api_feeds`. Use `GET /dns` and `GET /blacklist`
for the full live lists.

**Note on `rate_limit` / `rate_limit_burst`:** these are the *live* DNS rate-limiter
values (steady-state rps and burst ceiling), read from the running limiter — not the
static config-file value. They are live-editable via `PATCH /api/config` (see below).
`rate_limit: 0` means the DNS rate limiter is disabled.

---


### `PATCH /api/config`

Toggle runtime settings without restarting. Supports DNSSEC validation and the DNS
rate limiter. Each field is optional; omitted fields keep their current value. When
DNSSEC validation is toggled and full-recursion is active, the sovereign recursor is
rebuilt so the new policy takes effect. Changes are applied immediately and propagated
to all registered slaves.

```bash
# Toggle DNSSEC validation
curl -X PATCH http://localhost:8080/api/config \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"dnssec_validation": true}'

# Live-edit the DNS rate limiter (steady-state rps + burst ceiling)
curl -X PATCH http://localhost:8080/api/config \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"rate_limit": 500, "rate_limit_burst": 1000}'
```

The response always reports the current value of every runtime-editable field, whether
or not it was in the request body:

```json
{"ok": true, "dnssec_validation": true, "rate_limit": 500, "rate_limit_burst": 1000}
```

| Field | Type | Description |
|---|---|---|
| `dnssec_validation` | bool | Enable or disable DNSSEC validation at runtime |
| `rate_limit` | u64 | DNS rate limiter steady-state rps applied live to the limiter shared with the XDP fast path. `0` disables it. Clamped to a max of 1,000,000. |
| `rate_limit_burst` | u64 | DNS rate limiter burst ceiling, applied live. Clamped to a max of 2,000,000. |

**Note:** The change **is** persisted — the handler rewrites `runbound.conf` (via the atomic config writer) so it survives a restart. The one exception is **slave mode**, where config is driven by the master and the persist step returns early (no local rewrite). DNSSEC toggles are also propagated to all registered slaves over the relay. (Live rate-limit edits are persisted locally but are not currently pushed to slaves over the relay.)

---

### `GET /api/resolution`

Current resolution mode (#202) and whether the sovereign recursor is live.

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/resolution
```

```json
{"mode": "full-recursion", "recursor_active": true}
```

---

### `PUT /api/resolution`

Switch between `forward` and `full-recursion` at runtime (#202) — no restart. **Admin only.** Propagated to slaves over the relay. See [configuration.md](configuration.md).

```bash
curl -X PUT http://localhost:8080/api/resolution \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" -H "Content-Type: application/json" \
  -d '{"mode":"full-recursion"}'
```

```json
{"ok": true, "mode": "full-recursion", "recursor_active": true}
```

---

### `POST /api/reload`

Hot-reload: re-parse `runbound.conf` and rebuild all in-memory DNS data without dropping connections.
Equivalent to `systemctl reload runbound` (SIGHUP).

```bash
curl -X POST http://localhost:8080/api/reload \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

```json
{"status": "ok", "cfg_path": "/etc/runbound/runbound.conf", "local_zones": 5, "local_data": 12, "alert_rules": 2}
```

**Note:** ACL rules, forward-zone upstreams, and privacy settings (`log-retention`, `log-client-ip`) require a full restart. Alert rules **are** reloaded by `POST /api/reload` without a restart.

---

### `GET /api/metrics`

Prometheus/OpenMetrics exposition. Returns all counters and gauges from `GET /stats` in
Prometheus text format (`text/plain; version=0.0.4`). Compatible with any Prometheus
scraper, Grafana Agent, VictoriaMetrics, and OTEL Collector.

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/metrics
```

```
# HELP runbound_queries_total Total DNS queries received
# TYPE runbound_queries_total counter
runbound_queries_total 125432
# HELP runbound_queries_blocked_total Queries blocked by blocklist
# TYPE runbound_queries_blocked_total counter
runbound_queries_blocked_total 8921
# HELP runbound_queries_forwarded_total Queries forwarded to upstreams
# TYPE runbound_queries_forwarded_total counter
runbound_queries_forwarded_total 112000
# HELP runbound_queries_nxdomain_total Queries answered NXDOMAIN
# TYPE runbound_queries_nxdomain_total counter
runbound_queries_nxdomain_total 4500
# HELP runbound_queries_servfail_total Queries answered SERVFAIL
# TYPE runbound_queries_servfail_total counter
runbound_queries_servfail_total 11
# HELP runbound_queries_local_hits_total Queries answered from local zones
# TYPE runbound_queries_local_hits_total counter
runbound_queries_local_hits_total 3200
# HELP runbound_qps_1m Queries per second (1 minute average)
# TYPE runbound_qps_1m gauge
runbound_qps_1m 34.7
# HELP runbound_qps_peak Peak queries per second observed
# TYPE runbound_qps_peak gauge
runbound_qps_peak 410
# HELP runbound_latency_p50_ms DNS response latency p50 in milliseconds
# TYPE runbound_latency_p50_ms gauge
runbound_latency_p50_ms 0.3
# HELP runbound_latency_p95_ms DNS response latency p95 in milliseconds
# TYPE runbound_latency_p95_ms gauge
runbound_latency_p95_ms 4.2
# HELP runbound_latency_p99_ms DNS response latency p99 in milliseconds
# TYPE runbound_latency_p99_ms gauge
runbound_latency_p99_ms 22.5
# HELP runbound_cache_hit_rate Cache hit rate as a percentage (0 to 100)
# TYPE runbound_cache_hit_rate gauge
runbound_cache_hit_rate 68.4
# HELP runbound_cache_entries Current number of entries in DNS cache
# TYPE runbound_cache_entries gauge
runbound_cache_entries 2941
# HELP runbound_cache_hits_total Total cache hits
# TYPE runbound_cache_hits_total counter
runbound_cache_hits_total 76500
# HELP runbound_cache_misses_total Total cache misses
# TYPE runbound_cache_misses_total counter
runbound_cache_misses_total 35500
# HELP runbound_cache_evictions_total Total cache evictions
# TYPE runbound_cache_evictions_total counter
runbound_cache_evictions_total 18
# HELP runbound_uptime_seconds Service uptime in seconds
# TYPE runbound_uptime_seconds gauge
runbound_uptime_seconds 3600
# HELP runbound_xdp_active Whether XDP fast path is active (1=yes, 0=no)
# TYPE runbound_xdp_active gauge
runbound_xdp_active 1
# HELP runbound_xdp_cache_hits_total DNS responses served from the fast-path cache
# TYPE runbound_xdp_cache_hits_total counter
runbound_xdp_cache_hits_total 0
# HELP runbound_xdp_cache_misses_total XDP fast-path cache lookups that missed
# TYPE runbound_xdp_cache_misses_total counter
runbound_xdp_cache_misses_total 0
# HELP runbound_xdp_kernel_snapshot_hits_total DNS responses answered directly by the in-kernel eBPF cache snapshot
# TYPE runbound_xdp_kernel_snapshot_hits_total counter
runbound_xdp_kernel_snapshot_hits_total 0
# HELP runbound_xdp_kernel_snapshot_misses_total Lookups the in-kernel eBPF cache snapshot could not answer
# TYPE runbound_xdp_kernel_snapshot_misses_total counter
runbound_xdp_kernel_snapshot_misses_total 0
# HELP runbound_xdp_cache_entries Current live entries in XDP wire-format cache
# TYPE runbound_xdp_cache_entries gauge
runbound_xdp_cache_entries 0
# HELP runbound_nic_rx_ring NIC RX ring depth currently applied (descriptors)
# TYPE runbound_nic_rx_ring gauge
runbound_nic_rx_ring 4096
# HELP runbound_nic_rx_ring_max Maximum NIC RX ring depth supported by the driver
# TYPE runbound_nic_rx_ring_max gauge
runbound_nic_rx_ring_max 4096
# HELP runbound_nic_rx_dropped_total Hardware RX drops at NIC level (pre-XDP)
# TYPE runbound_nic_rx_dropped_total counter
runbound_nic_rx_dropped_total 0
# HELP runbound_queries_by_type_total DNS queries by record type
# TYPE runbound_queries_by_type_total counter
runbound_queries_by_type_total{type="A"} 90211
runbound_queries_by_type_total{type="AAAA"} 30122
# HELP runbound_upstream_healthy Whether upstream is healthy (1=yes, 0=no)
# TYPE runbound_upstream_healthy gauge
runbound_upstream_healthy{id="550e8400-...",addr="1.1.1.1",port="853",protocol="dot"} 1
# HELP runbound_upstream_latency_ms Last measured upstream latency in milliseconds
# TYPE runbound_upstream_latency_ms gauge
runbound_upstream_latency_ms{id="550e8400-...",addr="1.1.1.1",port="853",protocol="dot"} 14
# HELP runbound_icmp_handled_total ICMP echo requests handled by XDP
# TYPE runbound_icmp_handled_total counter
runbound_icmp_handled_total 0
# HELP runbound_icmp_replied_total ICMP echo replies sent by XDP
# TYPE runbound_icmp_replied_total counter
runbound_icmp_replied_total 0
# HELP runbound_icmp_dropped_total Packets dropped from banned source IPs at XDP
# TYPE runbound_icmp_dropped_total counter
runbound_icmp_dropped_total 0
# HELP runbound_icmp_rate_limited_total Packets rate-limited at the XDP ICMP gate
# TYPE runbound_icmp_rate_limited_total counter
runbound_icmp_rate_limited_total 0
# HELP runbound_banned_ips Source IPs currently banned in the XDP map
# TYPE runbound_banned_ips gauge
runbound_banned_ips 0
# HELP runbound_alert_blocked_ips Source IPs currently blocked by an alert rule / manual ban
# TYPE runbound_alert_blocked_ips gauge
runbound_alert_blocked_ips 3
# HELP runbound_alert_tarpitted_ips Source IPs currently tarpitted
# TYPE runbound_alert_tarpitted_ips gauge
runbound_alert_tarpitted_ips 1
# HELP runbound_tcp_connections_active Active TCP/DoT/DoH relay connections (listener saturation)
# TYPE runbound_tcp_connections_active gauge
runbound_tcp_connections_active 12
```

> There is no `runbound_dnssec_total` metric — DNSSEC secure/bogus/insecure counts are
> exposed via `GET /api/stats` (`dnssec` object) and the WebUI, not the OpenMetrics
> endpoint. `runbound_node_info{node="..."}` is emitted first when a node id is configured.

**Metric families:** node identity (`runbound_node_info`); query totals (`runbound_queries_total`) + per-type (`runbound_queries_by_type_total`) + rcode (`runbound_queries_blocked_total`, `runbound_queries_forwarded_total`, `runbound_queries_nxdomain_total`, `runbound_queries_servfail_total`, `runbound_queries_local_hits_total`); QPS (`runbound_qps_1m`, `runbound_qps_peak` — distinct metrics, no `window`/`quantile` labels); latency (`runbound_latency_p50_ms`, `runbound_latency_p95_ms`, `runbound_latency_p99_ms`); cache (`runbound_cache_hit_rate`, `runbound_cache_hits_total`, `runbound_cache_misses_total`, `runbound_cache_evictions_total`, `runbound_cache_entries`); XDP cache (`runbound_xdp_cache_hits_total`, `runbound_xdp_cache_misses_total`, `runbound_xdp_kernel_snapshot_hits_total`, `runbound_xdp_kernel_snapshot_misses_total`, `runbound_xdp_cache_entries`, `runbound_xdp_active`); NIC (`runbound_nic_rx_ring`, `runbound_nic_rx_ring_max`, `runbound_nic_rx_dropped_total`); uptime (`runbound_uptime_seconds`); **DDoS/abuse** (`runbound_icmp_handled_total`, `runbound_icmp_replied_total`, `runbound_icmp_dropped_total`, `runbound_icmp_rate_limited_total`, `runbound_banned_ips`, `runbound_alert_blocked_ips`, `runbound_alert_tarpitted_ips`); **listener saturation** (`runbound_tcp_connections_active`); per-upstream health + latency (`runbound_upstream_healthy`, `runbound_upstream_latency_ms`). There is **no** `runbound_dnssec_total` metric.

**Prometheus scrape config:**

```yaml
# prometheus.yml
scrape_configs:
  - job_name: runbound
    static_configs:
      - targets: ["localhost:8080"]
    authorization:
      type: Bearer
      credentials: <your-api-key>
    metrics_path: /api/metrics
```

---

### `POST /api/rotate-key`

Atomically replace the active Bearer token **without restarting Runbound**. The old token
is invalidated the instant this endpoint returns. Designed for PCI-DSS / NIS2 key
rotation requirements.

**Request body (JSON):**

```json
{"new_key": "your-new-key-minimum-32-characters"}
```

**Procedure:**

```bash
NEW_KEY="$(openssl rand -hex 32)"

# Call with the CURRENT (old) key in Authorization, new key in the body:
curl -X POST http://localhost:8080/api/rotate-key \
  -H "Authorization: Bearer $OLD_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"new_key\": \"$NEW_KEY\"}"

# All subsequent calls must use NEW_KEY.
```

```json
{"status": "ok", "message": "API key rotated — old token is immediately invalid"}
```

**How it works:** The new key is read from the JSON body, validated, and atomically
swapped into memory. No restart, no DNS service interruption. The change is persisted to
the `api.key` file in the runtime directory (mode `0600`). The rotation is recorded in the
audit log as a `config_reload` event.

**Errors:**

| Code | Body | Meaning |
|---|---|---|
| `400 WEAK_KEY` | `{"error":"WEAK_KEY"}` | `new_key` is shorter than 32 characters |
| `400 INVALID_KEY` | `{"error":"INVALID_KEY"}` | `new_key` contains non-printable or DEL characters |
| `401` | — | `Authorization` header missing or wrong |

---

### `GET /api/tls`

DoT/DoH/DoQ protocol status.

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/tls
```

```json
{
  "dot": {"enabled": true, "port": 853, "rfc": "RFC 7858"},
  "doh": {"enabled": true, "port": 443, "rfc": "RFC 8484"},
  "doq": {"enabled": true, "port": 853, "rfc": "RFC 9250"},
  "cert": "/etc/runbound/cert.pem",
  "hostname": "dns.example.com"
}
```

`cert` is `"not configured"` and `hostname` defaults to `"runbound.local"` when no
certificate is set.

---

### `GET /api/tls/cert`

Encrypted-DNS certificate status: `active` (what the running server booted with) vs `configured` (persisted), the ports, hostname, and the parsed certificate (subject/issuer CN, validity, SHA-256 fingerprint, SANs). The DoT/DoH/DoQ listeners are (re)bound live on every change (no restart), so `restart_required` is always `false`.

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/tls/cert
```

```json
{
  "active": true, "configured": true, "restart_required": false,
  "dot_port": 853, "doh_port": 443, "doq_port": 853, "hostname": "dns.example.com",
  "cert_path": "/etc/runbound/cert.pem",
  "cert": { "subject_cn": "dns.example.com", "issuer_cn": "dns.example.com", "self_signed": true,
            "not_before": 1756464000, "not_after": 1788000000,
            "days_remaining": 365, "expired": false, "fingerprint_sha256": "AB:CD:...", "sans": ["dns.example.com"] }
}
```

---

### `GET /api/tls/ca`

Download the Runbound Local CA certificate (PEM) that signs the embedded Web UI / self-signed leaf. Served as `application/x-pem-file` with `Content-Disposition: attachment; filename="runbound-ca.pem"`, so it can be imported into a browser/OS trust store to clear TLS warnings on the Web UI and self-signed DoH. No request body; the CA is created on first use if absent. Returns `500` if the CA cannot be read or generated.

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  http://localhost:8080/api/tls/ca -o runbound-ca.pem
```

```
-----BEGIN CERTIFICATE-----
MIIBozCCAUmg... (Runbound Local CA)
-----END CERTIFICATE-----
```

---

### `POST /api/tls/self-signed`

Generate a self-signed certificate + key for `hostname` and enable DoT/DoH/DoQ. The key is written `0600` (atomic) in `base_dir`; the config is updated. **Admin only.** The DoT/DoH/DoQ listeners are (re)bound live via the TLS-apply channel, so `restart_required` is `false`. The response is `{"ok": true, "mode": "self-signed", "restart_required": false, "cert": { ... }}` (the `cert` object is the same shape as `GET /api/tls/cert`).

```bash
curl -X POST http://localhost:8080/api/tls/self-signed \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" -H "Content-Type: application/json" \
  -d '{"hostname":"dns.example.com","dot_port":853,"doh_port":443,"doq_port":853}'
```

| Field | Type | Description |
|---|---|---|
| `hostname` | string | required — TLS SNI / DoH host (1..253 chars, no control chars) |
| `dot_port` / `doh_port` / `doq_port` | u16 | optional port overrides |

---

### `POST /api/tls/import`

Import an existing certificate + key (e.g. Lets Encrypt). The pair is validated against rustls (the key must match the leaf certificate) before being written; a mismatch returns `400`. Key written `0600`. **Admin only.** Listeners are re-bound live, so `restart_required` is `false`. Response: `{"ok": true, "mode": "import", "restart_required": false, "cert": { ... }}`.

```bash
curl -X POST http://localhost:8080/api/tls/import \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" -H "Content-Type: application/json" \
  -d '{"cert_pem":"-----BEGIN CERTIFICATE-----\n...","key_pem":"-----BEGIN PRIVATE KEY-----\n...","hostname":"dns.example.com"}'
```

---

### `DELETE /api/tls`

Disable encrypted DNS (clears `tls-service-pem` / `tls-service-key`). **Admin only.** Listeners are unbound live, so `restart_required` is `false`. Response: `{"ok": true, "restart_required": false}`.

---

### `GET /api/dnssec/ds`

DS record(s) for the DNSSEC-signed local zones (`local-zone-dnssec: yes` — see [configuration.md](configuration.md)). Publish these at the parent zone. Reads the live in-memory signer (no key generation on this read path).

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/dnssec/ds
```

```json
{"enabled": true, "ds": [{"zone": "home.", "ds": "12345 13 2 <sha256-digest>"}]}
```

---

### `GET /api/system`

Runtime system metrics.

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/system
```

```json
{
  "version": "0.9.1",
  "uptime_secs": 3600,
  "xdp_active": true,
  "xdp_mode": "drv",
  "cpu_cores": 64,
  "cpu_percent": 1.2,
  "mem_total_mb": 65536,
  "mem_avail_mb": 62000,
  "cache_entries": 48231,
  "workers": 8,
  "prefetch_enabled": true,
  "upstreams_healthy": 3,
  "upstreams_total": 3,
  "dot_reconnects_total": 2,
  "last_reconnect_at": "2026-05-22T15:00:00Z",
  "dnssec_validation": true,
  "xdp_cache_entries": 12000,
  "xdp_cache_hits": 0,
  "xdp_cache_misses": 0,
  "xdp_cache_hit_rate": 0.0,
  "xdp_kernel_snapshot_hits": 0,
  "xdp_kernel_snapshot_misses": 0,
  "xdp_domain_routing": false,
  "xdp_worker_distribution": [0, 0, 0, 0],
  "nic_rx_ring": 4096,
  "nic_rx_ring_max": 4096,
  "xsk_rx_dropped": 0,
  "xsk_rx_fill_ring_empty": 0,
  "xsk_rx_ring_full": 0,
  "upstream_racing": true,
  "upstream_racing_wins": { "1.1.1.1@853": 8123, "9.9.9.9@853": 5012 },
  "anycast": { "configured": true, "address": "198.51.100.53/32", "announced": true, "peer": "192.168.1.1", "local_as": 65001 }
}
```

`xdp_mode`: `"drv"` (native zero-copy), `"skb"` (generic fallback), `"disabled"`.

| Field | Type | Description |
|---|---|---|
| `prefetch_enabled` | bool | `true` when `prefetch: yes` is set in `runbound.conf` |
| `upstreams_healthy` | u32 | Count of upstreams with `healthy == true` at last health check |
| `upstreams_total` | u32 | Total registered upstreams (config + API) |
| `dot_reconnects_total` | u64 | Number of DoT reconnect cycles (`POST /api/upstreams/reconnect` + auto-recovery) since start |
| `last_reconnect_at` | string or `null` | Timestamp of the last DoT reconnect, or `null` if none yet |
| `dnssec_validation` | bool | Current runtime DNSSEC-validation state (matches the `PATCH /api/config` toggle) |
| `xdp_cache_entries` | u64 | Live entries in the XDP wire-format cache snapshot |
| `xdp_cache_hits` / `xdp_cache_misses` | u64 | XDP fast-path (per-worker) cache hits / misses — what the XDP datapath served from cache |
| `xdp_cache_hit_rate` | f64 | `xdp_cache_hits / (xdp_cache_hits + xdp_cache_misses) × 100`, one decimal (`0.0` when no XDP traffic) |
| `xdp_kernel_snapshot_hits` / `xdp_kernel_snapshot_misses` | u64 | In-kernel eBPF snapshot hits / misses (`0` when the snapshot path is not serving, e.g. copy mode on a VM) |
| `xdp_domain_routing` | bool | `true` when `xdp-domain-routing` is enabled in `runbound.conf` |
| `xdp_worker_distribution` | `[u64]` | Per-XDP-worker packet counters (one entry per worker) |
| `nic_rx_ring` | u32 | Current RX ring depth applied to the NIC (descriptors). `0` when XDP is disabled or the driver does not support ethtool ring queries. |
| `nic_rx_ring_max` | u32 | Maximum RX ring depth supported by the driver. Equal to `nic_rx_ring` when auto-sizing succeeded. |
| `xsk_rx_dropped` | u64 | AF_XDP socket RX drops (kernel `XDP_STATISTICS` getsockopt), summed across XDP sockets. Valid under zero-copy, unlike the old ethtool/sysfs `rx_dropped` counters which are blind to `XDP_REDIRECT`→XSK traffic. |
| `xsk_rx_fill_ring_empty` | u64 | Count of times the AF_XDP fill ring was empty when the kernel needed a buffer — an early warning that RX buffers aren't being recycled fast enough. |
| `xsk_rx_ring_full` | u64 | Count of times the AF_XDP RX ring was full and packets were dropped before the userspace worker could drain it. |
| `upstream_racing` | bool | `true` when `upstream-racing: yes` is set. |
| `upstream_racing_wins` | object | Per-upstream racing-win counters (#33), `{ "<ip>": count }`. The number of times each upstream returned the first valid answer for a raced query. Empty `{}` until the first raced win. Populated on the default wire serving path. |
| `anycast` | object | Anycast announcer state (see [anycast.md](../docs/anycast.md)). `{ configured, address, peer, local_as, announced }` when an `anycast:` block is set; `{ "configured": false }` otherwise. `announced` is `true` while the exabgp child is up (route advertised). The WebUI **System** tab renders this per node (master + each slave via the relay). |

---

### `POST /api/cache/flush`

Atomically rebuilds the resolver with an empty cache. Caller IP is logged at WARN level.

```bash
curl -X POST -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/cache/flush
```

```json
{"status": "ok", "flushed_entries": 48231}
```

**Cooldown** (`cache-flush-cooldown` in `runbound.conf`, default: 60 s):

If this endpoint is called again before the cooldown expires, it returns:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 58
```
```json
{"error": "FLUSH_COOLDOWN", "retry_after_secs": 58}
```

Set `cache-flush-cooldown: 0` to disable the cooldown entirely.

### `GET /api/cache/stats`

DNS cache operation counters since the last `POST /api/cache/flush` (or process start).

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/cache/stats
```

```json
{
  "entries":      2941,
  "hits":         58432,
  "misses":       3201,
  "evictions":    18,
  "hit_rate_pct": 94.8
}
```

| Field | Type | Description |
|-------|------|-------------|
| `entries` | u64 | Current number of entries in the DNS cache |
| `hits` | u64 | Responses served from cache — slow-path counter plus the summed XDP fast-path worker hits (same canonical sum as `GET /api/stats`) |
| `misses` | u64 | Cache misses forwarded to an upstream |
| `evictions` | u64 | Entries evicted to enforce the cache size limit |
| `hit_rate_pct` | f64 or `null` | `hits / (hits + misses) × 100`, rounded to 1 decimal. `null` when `hits + misses == 0`. |

All counters reset to zero on `POST /api/cache/flush`.

---

### Upstreams

Runtime upstream forwarder management. Changes take effect immediately — the shared
resolver is rebuilt atomically on every add/remove. Runtime upstreams are persisted to
`$BASE_DIR/upstreams.json` and reloaded on startup (merged over config-file entries).

#### `GET /api/upstreams`

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/upstreams
```

```json
{
  "upstreams": [
    {
      "id": "550e8400-...",
      "name": "Cloudflare DoT",
      "addr": "1.1.1.1",
      "port": 853,
      "protocol": "dot",
      "tls_hostname": "one.one.one.one",
      "healthy": true,
      "latency_ms": 14,
      "last_check": "2026-05-22T15:00:00Z",
      "last_error": null,
      "zone": ".",
      "latency_history": [11, 12, 14, 11, 13],
      "dnssec_supported": true,
      "dnssec_stripping": false,
      "source": "api",
      "temporary": false
    }
  ],
  "total": 1,
  "healthy": 1
}
```

| Field | Type | Description |
|-------|------|-------------|
| `source` | `"api"`, `"config"`, or `"resolv.conf"` | `"config"` for upstreams loaded from `forward-zone` in `runbound.conf`; `"api"` for upstreams added via the REST API (the default when not set); `"resolv.conf"` for temporary emergency fallback upstreams injected from `/etc/resolv.conf`. |
| `temporary` | bool | `true` for upstreams injected as emergency fallback from `/etc/resolv.conf`. These upstreams are never persisted to `upstreams.json` and are automatically removed when a primary upstream recovers. Always `false` for normal upstreams. |
| `tls_hostname` | `string` or absent | DoT only. TLS SNI hostname used for certificate validation. Absent when not set (auto-detected from well-known IPs). |
| `last_error` | `string` or `null` | Short description of the last probe failure (`"connection timeout"`, `"tls handshake failed"`, etc.). `null` when the last probe succeeded. |
| `dnssec_supported` | `bool` or absent | `true` if the upstream sets the AD bit in probe responses. Present for any healthy upstream that has been probed (UDP **and** DoT); omitted only when the upstream is unhealthy or not yet probed. |
| `dnssec_stripping` | bool | `true` when the upstream previously advertised DNSSEC (AD bit) but has since stopped — an active-stripping signal (#34). Always serialised; `false` in the normal case. |
| `latency_history` | `[u64]` | Last ≤ 5 successful probe round-trip times (ms). Empty array until the first successful probe. Failed probes do not append. |

#### `POST /api/upstreams`

```bash
curl -X POST http://localhost:8080/api/upstreams \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"Cloudflare DoT","addr":"1.1.1.1","port":853,"protocol":"dot","tls_hostname":"one.one.one.one"}'
```

**Fields:**

| Field | Required | Rules |
|-------|----------|-------|
| `addr` | Yes | Valid IP address. Loopback (`127.x.x.x`, `::1`) and IPv4 link-local (`169.254.x.x`) are rejected (`400 INVALID_ADDR`). Private ranges (RFC 1918) and IPv6 ULA are allowed. |
| `protocol` | Yes | `"udp"` or `"dot"` (`400 INVALID_PROTOCOL` otherwise). |
| `port` | No | 1–65535. Defaults to 53 (UDP) or 853 (DoT) when omitted. Port 0 returns `400 INVALID_PORT`. |
| `name` | No | Human-readable label. Max 64 characters. |
| `tls_hostname` | No | DoT only. SNI hostname for TLS certificate validation. When omitted, Runbound auto-detects from well-known IPs (Cloudflare, Quad9, Google). Set explicitly for private or custom DoT resolvers. |

#### `DELETE /api/upstreams/:id`

```bash
curl -X DELETE -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  http://localhost:8080/api/upstreams/550e8400-...
```

Returns `409 LAST_UPSTREAM` when the target is the only registered upstream — the
resolver must always have at least one forwarder.

#### `PATCH /api/upstreams/:id`

Update an upstream in-place. Patchable fields: `name`, `tls_hostname`.

```bash
# Rename
curl -X PATCH http://localhost:8080/api/upstreams/550e8400-... \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"My Cloudflare"}'

# Set or update the DoT SNI hostname
curl -X PATCH http://localhost:8080/api/upstreams/550e8400-... \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tls_hostname":"dns.example.com"}'
```

- `name`: max 64 characters, no control characters. Empty string or `null` clears the name.
- `tls_hostname`: DoT upstreams only. Empty string or `null` clears it (falls back to auto-detect). Ignored for UDP upstreams.
- Any field other than `name` or `tls_hostname` returns `400 INVALID_FIELD`.
- Unknown id returns `404`.
- Changes are persisted to `upstreams.json` immediately.

#### `GET /api/upstreams/presets`

14 built-in presets: Cloudflare, Cloudflare alt, Cloudflare DoT, Cloudflare DoT alt, Google,
Google alt, Google DoT, Google DoT alt, Quad9, Quad9 alt, Quad9 DoT, Quad9 DoT alt, OpenDNS,
OpenDNS alt. (AdGuard DNS is **not** an upstream preset — it only exists as a feed/blocklist
preset under `GET /api/feeds/presets`.)
Each preset carries a bare IP `addr` and a separate `port` field (no `@port` suffix).

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/upstreams/presets
```

#### `POST /api/upstreams/:id/probe`

Trigger an immediate health probe for one upstream, outside the normal probe schedule.
Returns the result synchronously.

```bash
curl -X POST -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  http://localhost:8080/api/upstreams/550e8400-.../probe
```

```json
{
  "status": "ok",
  "upstream": {
    "id": "550e8400-...",
    "name": "Cloudflare DoT",
    "addr": "1.1.1.1",
    "port": 853,
    "protocol": "dot",
    "tls_hostname": "one.one.one.one",
    "source": "api",
    "healthy": true,
    "latency_ms": 14,
    "last_check": "2026-05-22T15:00:00Z",
    "dnssec_supported": true,
    "dnssec_stripping": false,
    "latency_history": [11, 12, 14, 11, 13],
    "zone": ".",
    "temporary": false
  }
}
```

The response wraps the **full, freshly-probed `UpstreamStatus`** object (same shape as one
element of `GET /api/upstreams`) under `"upstream"`. There is no `probed_at` field — the
probe time is reflected in `last_check`.

On a failed probe the upstream is returned with `"healthy": false`, `"latency_ms": null`,
`dnssec_supported` and `latency_history` omitted/unchanged, and a `"last_error"` string:

```json
{
  "status": "ok",
  "upstream": {
    "id": "550e8400-...",
    "addr": "1.1.1.1",
    "port": 853,
    "protocol": "dot",
    "source": "api",
    "healthy": false,
    "latency_ms": null,
    "last_error": "connection timeout",
    "last_check": "2026-05-22T15:00:00Z",
    "dnssec_stripping": false,
    "zone": ".",
    "temporary": false
  }
}
```

Returns `404` if the upstream id is unknown.

#### `POST /api/upstreams/reconnect`

Force-reconnect all DoT upstreams. Useful when TCP connections have gone idle after a
network interruption or when the `no connections available` error is observed.

```bash
curl -X POST -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  http://localhost:8080/api/upstreams/reconnect
```

```json
{"reconnected": 4, "failed": 0, "warm_up": true, "duration_ms": 182}
```

| Field | Type | Description |
|-------|------|-------------|
| `reconnected` | u32 | DoT upstreams that answered a probe after the rebuild |
| `failed` | u32 | DoT upstreams that failed to probe after the rebuild |
| `warm_up` | bool | Whether the resolver rebuild warmed (pre-opened) the new DoT connections before the swap |
| `duration_ms` | u64 | Total time the reconnect took, in milliseconds |

The shared resolver is atomically rebuilt with fresh connections. All in-flight queries
complete against the old resolver before it is dropped.

---

### `GET /api/sync/slaves`

Lists slaves seen in the last 5 minutes. Returns empty list with a note when not in master mode.

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/sync/slaves
```

```json
{
  "slaves": [
    {
      "addr": "192.168.8.13",
      "status": "connected",
      "last_seen_secs": 4,
      "zones_synced": 12,
      "version": "0.9.1"
    }
  ],
  "total": 1
}
```

`status`: `"connected"` (last seen < 30 s ago), `"disconnected"` (otherwise). There is no
intermediate `"stale"` state for this field — that 3-tier scheme (`ok`/`warn`/`error`) only
applies to `GET /api/events` (see below).

---

### `GET /api/nodes`

Lists all registered slave nodes with their relay information. Slaves register automatically
at startup via `POST /nodes/register` (internal, HMAC-signed). Returns an empty list with
a note when the node is not configured as master.

Requires `sync-port` and `sync-key` on the master.

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/nodes
```

```json
{
  "nodes": [
    {
      "node_id":          "a1b2c3d4-e5f6-...",
      "addr":             "192.168.1.11",
      "relay_host":       "192.168.1.11:8082",
      "cert_fingerprint": "ab:cd:ef:01:...",
      "status":           "connected",
      "last_seen_secs":   5,
      "zones_synced":     42,
      "version":          "0.9.1"
    }
  ],
  "total": 1
}
```

| Field | Description |
|---|---|
| `node_id` | Stable UUID generated by the slave at first start and persisted in `/etc/runbound/node-id`. |
| `addr` | Source IP of the last registration request. |
| `relay_host` | `ip:port` of the slave's relay server. Used by the master for config push and relay forwarding. Absent if the slave has no `sync-port` configured. |
| `cert_fingerprint` | SHA-256 fingerprint of the slave's relay TLS certificate. |
| `status` | `"connected"` (< 30 s since last registration), `"disconnected"` (otherwise). No `"stale"` state for this field — see the note under `GET /api/sync/slaves`. |

---

### `ANY /api/nodes/:node_id/relay/*path`

Forwards any REST API request from the master to a specific registered slave over the
HMAC-signed relay channel. The master signs the forwarded request with `sync-key` and
proxies it to the slave's relay server (`relay_host`). The slave's response is returned
verbatim.

Supports all HTTP methods (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`).

**Requires:** `sync-port` and `sync-key` on the master; slave must be registered in `GET /api/nodes`.

```bash
# Flush the DNS cache on slave a1b2c3d4-...
curl -X POST \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  "http://localhost:8080/api/nodes/a1b2c3d4-.../relay/cache/flush"

# List DNS entries on a specific slave
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  "http://localhost:8080/api/nodes/a1b2c3d4-.../relay/dns"

# Add a DNS entry on a specific slave
curl -X POST \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"test.home.","type":"A","value":"10.0.0.5","ttl":300}' \
  "http://localhost:8080/api/nodes/a1b2c3d4-.../relay/dns"
```

**Error responses:**

| Code | Error | Meaning |
|---|---|---|
| `503 SERVICE_UNAVAILABLE` | `RELAY_DISABLED` | Master has no `sync-key` or `sync-port` configured. |
| `404 NOT_FOUND` | `NODE_NOT_FOUND` | No registered node with the given `node_id`. |
| `422 UNPROCESSABLE_ENTITY` | `NODE_NO_RELAY` | Node registered but has no `relay_host` (slave's `sync-port` not set). |
| `400 BAD_REQUEST` | `RELAY_RECURSION` | Attempted relay to `/relay/*` — forbidden to prevent loops. |
| `502 BAD_GATEWAY` | `RELAY_ERROR` | Connection to the slave failed (timeout, TLS error, etc.). |

---


### `GET /api/events`

Real-time node-status push via Server-Sent Events. Available on the **master only**
(returns `404` on slave and standalone nodes).

```bash
curl -N -H "Authorization: Bearer $RUNBOUND_API_KEY" \
     http://localhost:8080/api/events
```

```
data: {"node_id":"1df6dc2c-94a7-485b-bb80-76b7f5aa438d","addr":"192.168.8.11","status":"ok","reason":"last seen 3s ago","ts":1748131200}

data: {"node_id":"1df6dc2c-94a7-485b-bb80-76b7f5aa438d","addr":"192.168.8.11","status":"warn","reason":"last seen 42s ago","ts":1748131242}
```

An event is emitted whenever a slave node transitions between health categories.

**Health thresholds** (based on `last_seen_secs`):

| Status | Condition | Meaning |
|---|---|---|
| `ok` | < 15 s | Slave is actively syncing |
| `warn` | 15–59 s | One sync cycle missed — may be transient |
| `error` | ≥ 60 s | Slave likely unreachable |

**Event fields:**

| Field | Type | Description |
|---|---|---|
| `node_id` | string | Stable UUID of the slave node (from `/etc/runbound/node-id` on the slave) |
| `addr` | string | Source IP of the slave's last registration |
| `status` | string | `"ok"`, `"warn"`, or `"error"` |
| `reason` | string | Human-readable explanation (e.g. `"last seen 42s ago"`) |
| `ts` | integer | Unix timestamp (seconds) of the status change |

**Keep-alive:** a `: keep-alive` comment line is sent every 15 seconds to prevent
proxy and load-balancer timeouts. These are not data events and should be ignored
by SSE clients.

**Broadcast channel capacity:** 64 events. Slow consumers that fall behind are
disconnected when the channel is full.

> The `-N` flag disables curl's output buffering — required to see events in real time.

---

---

### ICMP echo responder

> Requires XDP (`--features xdp`) compiled binary and `icmp { enable: yes }` in `runbound.conf`.
> When XDP is inactive, endpoints are still available but counters stay at zero.

#### `GET /api/icmp/stats`

Returns cumulative counters polled from the BPF per-CPU array.

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/icmp/stats
```

```json
{"dropped":0,"handled":42,"rate_limited":7,"replied":35}
```

| Field | Description |
|---|---|
| `handled` | Echo requests that reached the XDP handler |
| `replied` | Requests answered with XDP_TX (echo reply sent) |
| `dropped` | Requests dropped before reply (reserved, currently unused) |
| `rate_limited` | Requests dropped by per-source-IP rate limiter |

Counters are updated by the background BPF poll task every second.

---

#### `GET /api/icmp/config`

Returns the current ICMP responder configuration.

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/icmp/config
```

```json
{"burst":8,"enable":true,"rate_limit":20,"ban_threshold":100}
```

---

#### `PUT /api/icmp/config`

Live-update the ICMP responder config. Changes are applied to the BPF map within 1 second
(next background poll tick).

```bash
curl -X PUT -H "Authorization: Bearer $RUNBOUND_API_KEY" \
     -H "Content-Type: application/json" \
     -H "Content-Length: 61" \
     -d '{"enable":true,"rate_limit":20,"burst":8,"ban_threshold":100}' \
     http://localhost:8080/api/icmp/config
```

**Request body** (all fields optional — omitted fields keep their current value):

| Field | Type | Description |
|---|---|---|
| `enable` | bool | Enable/disable the ICMP echo responder |
| `rate_limit` | integer | Max echo requests per second per source IP |
| `burst` | integer | Initial burst tokens granted to new source IPs |
| `ban_threshold` | integer | Echo requests from a single source before the flood detector bans it (default: 100) |

Returns the updated config:

```json
{"burst":8,"enable":true,"rate_limit":20,"ban_threshold":100}
```

---

## Alert thresholds

Monitor client query rates and automatically block abusive sources.
Alert rules are defined in `runbound.conf` (see [Configuration](configuration.md#alert-directives)).
Alert rules are reloaded by `POST /api/reload` — no full restart is required to update them.

### `GET /api/alerts`

Returns active alert rules, currently blocked clients, and recent alert events.

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/alerts
```

```json
{
  "rules": [
    {
      "name": "main",
      "metric": "client-qps",
      "threshold": 100,
      "window_s": 10,
      "action": "block",
      "block_duration_s": 300
    }
  ],
  "blocked_clients": [
    {
      "ip": "203.0.113.42",
      "rule": "main",
      "permanent": false,
      "expires_in_s": 247
    }
  ],
  "recent_alerts": [
    {
      "rule": "main",
      "client_ip": "203.0.113.42",
      "count": 127,
      "action": "block",
      "ts": 1716000000
    }
  ]
}
```

| Field | Description |
|---|---|
| `rules` | Active alert rules loaded from config |
| `blocked_clients` | IPs currently blocked; `permanent: true` means no expiry (blocked until restart or manual unblock) |
| `recent_alerts` | Last 100 alert events (ring buffer) |
| `expires_in_s` | Seconds until the block expires; absent for permanent blocks |

> Bot defense bans appear in `blocked_clients` with `rule` values of `bot-honeypot`, `bot-scanner`,
> or `bot-burst`. They are subject to the configured `bot-ban-duration-secs` expiry.

---

### `PUT /api/alerts/rules`

Replace the full alert-rule set (admin only). The rules are validated, persisted to
`runbound.conf` (whole-config regeneration preserves everything else) and **hot-applied**
without a restart. `action` is one of `log`, `tarpit`, `block`, `notify`.

```bash
curl -X PUT http://localhost:8080/api/alerts/rules \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" -H "Content-Type: application/json" \
  -d '[{"name":"tarpit-abuse","window_s":10,"threshold":5000,"action":"tarpit","block_duration_s":60},
       {"name":"ban-flood","window_s":10,"threshold":20000,"action":"block","block_duration_s":3600}]'
```

Editable from the WebUI **Protection** tab ("Load recommended" pre-fills a sane set).

> **Audit:** every authenticated mutating request is logged as an `admin_action` event
> (`actor`, `method`, `path`, `status`) in the tamper-evident audit log; see `GET /api/audit/tail`.

---

### `PUT /api/alerts/blocked/:ip`

Manually block an IP address. The block is permanent (no expiry) and persisted to `alert-blocks.json`.

```bash
curl -X PUT http://localhost:8080/api/alerts/blocked/203.0.113.42 \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

```json
{"ip": "203.0.113.42", "blocked": true}
```

The IP is blocked immediately at the DNS layer (REFUSED response) and, if XDP is active, at the XDP layer (packet drop).

**Protected addresses.** A loopback (`127.0.0.0/8`, `::1`) or unspecified (`0.0.0.0`, `::`)
address is never banned. The request still returns `200 OK`, but with `blocked: false`
and a `reason`:

```json
{"blocked": false, "ip": "127.0.0.1", "reason": "protected address (loopback/unspecified) is never banned"}
```

A syntactically invalid IP in the path returns `400 Bad Request` with `{"error": "invalid IP"}`.

---

### `DELETE /api/alerts/blocked/:ip`

Unblock a previously blocked IP (manual or rule-triggered).

```bash
curl -X DELETE http://localhost:8080/api/alerts/blocked/203.0.113.42 \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

```json
{"ip": "203.0.113.42", "unblocked": true}
```

Returns `{"unblocked": false}` if the IP was not blocked.

### `GET /api/protection/banned`

Current banned source IPs — the authoritative set enforced on **both** datapaths: the
XDP fast path drops them in eBPF (the `icmp_banned` map, `XDP_DROP`, IPv4), and the
kernel slow path (`xdp: no`) drops them in the data loop. Sources: `IcmpFlood` (flood
detector), `Manual` (API), `Relay` (pushed from the master).

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/protection/banned
```

```json
{
  "count": 1,
  "entries": [
    {"ip": "203.0.113.42", "source": "Manual", "banned_ago_s": 12, "permanent": false}
  ]
}
```

| Field | Meaning |
|-------|---------|
| `source` | `IcmpFlood` \| `Manual` \| `Relay` |
| `banned_ago_s` | Seconds since the ban was applied |
| `permanent` | `true` = blacklisted (never auto-expires); `false` bans expire after `bot-ban-duration-secs` |

### `POST /api/protection/banned/:ip/blacklist`

Promote a ban to **permanent** ("blacklist"): it no longer auto-expires. Propagated to
slaves via the HMAC relay like any other ban. To ban/unban, use `PUT`/`DELETE
/api/alerts/blocked/:ip` (above).

```bash
curl -X POST http://localhost:8080/api/protection/banned/203.0.113.42/blacklist \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

```json
{"blacklisted": true, "ip": "203.0.113.42"}
```

Like `PUT /api/alerts/blocked/:ip`, a loopback/unspecified address is never banned and
returns `200 OK` with `blacklisted: false` and a `reason`; an invalid IP returns
`400 Bad Request` with `{"error": "invalid IP"}`.

```json
{"blacklisted": false, "ip": "127.0.0.1", "reason": "protected address (loopback/unspecified) is never banned"}
```

> **Enforcement.** Banned IPs and the per-source `rate-limit` are enforced on
> **both** the XDP fast path and the kernel slow path (`xdp: no`). The `rate-limit` drops a
> source's *excess* queries for the current 1-second window (transient throttle — no ban);
> a ban drops *all* of a source's queries until it expires (or forever if blacklisted).
> Exceeding the DNS `rate-limit` does **not** ban; only the ICMP flood detector
> (`ban-threshold`) or a manual/blacklist action bans. Bans are in-memory and reset on
> restart.

---

## Slave mode — read-only

When Runbound runs as a slave replica (`mode: slave` in `runbound.conf`), all write
operations are blocked at the API level. Any non-GET request returns:

```json
HTTP 503
{"error": "READ_ONLY", "details": "This node is a slave replica — write operations are disabled"}
```

Changes must be applied on the master. Slaves receive all updates automatically via the
replication protocol (delta journal, polled every `sync-interval` seconds). The `GET`
endpoints (`/dns`, `/blacklist`, `/feeds`, `/stats`, `/logs`, etc.) remain fully available
on slave nodes.

---

## Multi-user mode

Multi-user mode is enabled by creating a `users.json` file in the Runbound data directory and restarting the service. When disabled, all endpoints behave as before and these routes return `{"error":"MULTI_USER_DISABLED"}`.

### User model

| Field | Type | Description |
|-------|------|-------------|
| `id` | string (UUID) | Immutable user identifier |
| `username` | string (1-64 chars) | Display name |
| `api_key` | string (32 hex chars) | Bearer token for this user |
| `zone_prefixes` | string[] | DNS suffixes this user may manage (trailing dot normalised, e.g. `["home.", "internal."]`) |
| `enabled` | bool | Set to false to suspend access without deleting the user |
| `admin` | bool | Admin users bypass zone_prefix checks and have full access |

### Zone isolation

Non-admin users are restricted to entries whose name falls under one of their `zone_prefixes`:

- `GET /api/dns` — returns only entries owned by the user, plus admin-owned entries (backward-compatible: entries with no `owner_user_id` are treated as admin-owned).
- `POST /api/dns` — the name must match a `zone_prefix`; the entry is tagged with `owner_user_id`.
- `DELETE /api/dns/:id` — only allowed for entries the user owns.
- Same rules apply to `GET/POST/DELETE /api/blacklist`.
- `POST/DELETE /api/feeds` — admin-only.

### User management endpoints

All user management endpoints require the master API key (admin context). Callers authenticated with a per-user key can only access `GET /api/users/me` and `POST /api/users/:id/rotate-key` (self only).

#### `GET /api/users`

List all users. Admin only.

```bash
curl -H "Authorization: Bearer $MASTER_KEY" http://localhost:8080/api/users
```

Response — a `{"users": [...]}` envelope. API keys are **not** included (they are only
ever returned once, on creation / rotation):
```json
{
  "users": [
    {
      "id": "a1b2c3d4-...",
      "username": "alice",
      "admin": false,
      "enabled": true,
      "zone_prefixes": ["home.", "internal."],
      "role": "read"
    }
  ]
}
```

`role` is one of `"read"` (default), `"dns"`, `"operator"`, or `"admin"`.

#### `POST /api/users`

Create a user. Returns the new API key — **copy it immediately, it is not shown again**.

```bash
curl -X POST -H "Authorization: Bearer $MASTER_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/users \
  -d '{"username":"alice","zone_prefixes":["home.","internal."],"admin":false,"role":"dns"}'
```

**Request fields:** `username` (required), `zone_prefixes` (optional, default `[]`),
`admin` (optional bool, default `false`), `role` (optional, default `"read"` — one of
`"read"`, `"dns"`, `"operator"`, `"admin"`).

Response: `201 Created`. The `api_key` is returned **once** here and never again:
```json
{
  "id": "a1b2c3d4-...",
  "username": "alice",
  "api_key": "3a7f9e2c...",
  "zone_prefixes": ["home.", "internal."],
  "enabled": true,
  "admin": false,
  "role": "dns"
}
```

#### `DELETE /api/users/:id`

Delete a user. Admin only.

```bash
curl -X DELETE -H "Authorization: Bearer $MASTER_KEY" \
  http://localhost:8080/api/users/a1b2c3d4-...
```

#### `GET /api/users/me`

Returns the profile of the authenticated user (works with both master key and per-user key).

```bash
curl -H "Authorization: Bearer $USER_KEY" http://localhost:8080/api/users/me
```

#### `POST /api/users/:id/rotate-key`

Generate a new API key. The old key is immediately invalidated.

The handler itself authorises an **admin** or the **user themselves** (`caller.id == :id`).
However, this is a write (`POST`), so the RBAC write-middleware runs first: a per-user key
whose `role` does not permit writes to this path is rejected with `403` **before** the
handler runs. The default `"read"` role (and `"dns"` / `"operator"`, whose write scope does
not cover `/api/users/...`) cannot self-rotate — only an `admin` (or `admin: true`) key can.

```bash
curl -X POST -H "Authorization: Bearer $MASTER_KEY" \
  http://localhost:8080/api/users/a1b2c3d4-.../rotate-key
```

Response:
```json
{"api_key": "7c4d1a9e..."}
```

---

### Split-horizon

Editable split-horizon entries (per-client-network answer sets, #10). CRUD persists to
`runbound.conf` **and** is applied **live** — the handler recompiles the editable entries
into the running resolver and evicts affected names from the XDP cache, so no restart is
needed. Slave nodes are read-only (`503`).

Entry shape:

```json
{ "name": "internal", "subnets": ["10.0.0.0/8", "192.168.0.0/16"], "local_data": ["intra.example. A 10.0.0.5"] }
```

#### `GET /api/split-horizon`

List all entries.

```bash
curl -s http://127.0.0.1:8080/api/split-horizon -H "Authorization: Bearer $KEY"
```

#### `POST /api/split-horizon`

Add (or replace by name) an entry. Applied live (no restart).

```bash
curl -s -X POST http://127.0.0.1:8080/api/split-horizon -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name":"internal","subnets":["10.0.0.0/8"],"local_data":["intra.example. A 10.0.0.5"]}'
```

```json
{"status": "ok", "name": "internal", "note": "applied live (no restart)"}
```

#### `DELETE /api/split-horizon/:name`

Remove an entry by name. Applied live (no restart).

```bash
curl -s -X DELETE http://127.0.0.1:8080/api/split-horizon/internal -H "Authorization: Bearer $KEY"
```

```json
{"status": "ok", "removed": 1, "note": "applied live (no restart)"}
```

---

### Subnet policies (#8)

Per-subnet / per-VLAN domain filtering, **additive** to the global blacklist/feeds
filter — a policy only ever blocks *more* for clients in its `subnet`, never less.
A listed domain blocks itself and all of its subdomains. Applied **live** (no
restart required) on the wire serving path. The XDP/kernel fast path is
untouched: a domain blocked only for one subnet is, by design, absent from the
global filter, so it never matches the fast-path lookup and always falls
through to the slow path, which enforces the policy and returns REFUSED — the
answer is never cached, so it cannot leak to a client outside that subnet.
Persisted to `subnet-policies.json`. Slave nodes are read-only (`503
SLAVE_READONLY`). Merged into the WebUI **Subnets** tab alongside split-horizon.

Entry shape:

```json
{ "name": "iot-vlan", "subnet": "192.168.10.0/24", "blacklist_extra": ["ads.example.", "telemetry.example."] }
```

**Limits:** max 256 policies, max 4,096 domains per policy.

#### `GET /api/policies`

List all policies, with a live `blocked` counter (queries this policy has
REFUSED since process start).

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/policies
```

```json
{
  "policies": [
    {"name": "iot-vlan", "subnet": "192.168.10.0/24", "blacklist_extra": ["ads.example."], "blocked": 42}
  ]
}
```

#### `POST /api/policies`

Add (or replace by `name`) a policy.

```bash
curl -X POST http://localhost:8080/api/policies \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" -H "Content-Type: application/json" \
  -d '{"name":"iot-vlan","subnet":"192.168.10.0/24","blacklist_extra":["ads.example."]}'
```

```json
{"status": "ok", "name": "iot-vlan", "note": "applied live (no restart)"}
```

#### `PUT /api/policies/:name`

Update a policy; the `:name` path segment wins over any `name` field in the body.

```bash
curl -X PUT http://localhost:8080/api/policies/iot-vlan \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" -H "Content-Type: application/json" \
  -d '{"subnet":"192.168.10.0/24","blacklist_extra":["ads.example.","telemetry.example."]}'
```

#### `DELETE /api/policies/:name`

```bash
curl -X DELETE http://localhost:8080/api/policies/iot-vlan \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

```json
{"status": "ok", "removed": 1, "note": "applied live (no restart)"}
```

**Validation:** `subnet` must be a valid CIDR (`400 INVALID_SUBNET`); `name` is
required, ≤ 64 characters, no control characters/quotes/backslashes (`400
INVALID`); more than `MAX_POLICIES` distinct names returns `400
TOO_MANY_POLICIES`; each domain in `blacklist_extra` must be a valid DNS name
(`400 INVALID_DOMAIN`); more than `MAX_POLICY_DOMAINS` entries returns `400
TOO_MANY_DOMAINS`.

## HTTP status codes

| Code | Meaning |
|---|---|
| `200` | Success |
| `201` | Created |
| `400` | Bad request — malformed JSON or invalid field value (`INVALID_ADDR`, `INVALID_PORT`, `INVALID_PROTOCOL`, …) |
| `401` | Unauthorized — missing or invalid Bearer token |
| `404` | Not found — UUID does not exist |
| `409` | Conflict — operation refused by a guard (e.g. `LAST_UPSTREAM`: cannot delete the last upstream) |
| `422` | Unprocessable — entry limit reached |
| `429` | Too many requests — rate limit exceeded, or flush cooldown active (`FLUSH_COOLDOWN`) |
| `500` | Internal server error |
| `503` | Service unavailable — slave node (read-only), write operation rejected |


---

### `GET /api/audit/tail`

Return the most recent entries of the per-entry HMAC-SHA256, tamper-evident audit log.
**Admin only** — a non-admin per-user key gets `403`. Query parameter `n` selects how many
trailing entries to return (default `100`, capped at `1000`).

```bash
curl -s "http://localhost:8080/api/audit/tail?n=50" -H "Authorization: Bearer $TOKEN"
```

```json
{
  "lines": [
    {
      "seq": 41,
      "ts": 1747926000,
      "event": "admin_action",
      "fields": {"method": "POST", "path": "/api/dns", "status": 200, "actor": "alice"},
      "mac": "9f2c...e1"
    }
  ],
  "count": 1,
  "enabled": true
}
```

| Field | Type | Description |
|-------|------|-------------|
| `lines` | array | Parsed audit records (oldest → newest within the tail). Each: `seq` (u64 monotonic), `ts` (u64 Unix epoch seconds), `event` (string event name), `fields` (object; event-specific, always carries `actor`), `mac` (hex HMAC-SHA256 over `seq‖ts‖event‖fields`). |
| `count` | integer | Number of entries in `lines`. |
| `enabled` | bool | `false` (with `lines: []`, `count: 0`) when no audit log exists on disk — i.e. audit logging is not enabled. `true` otherwise. |

---

## Additional endpoints

These endpoints are served by the API. All require
the `Authorization: Bearer <api-key>` header (admin role unless noted). The API binds
to localhost only.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/help` | Machine-readable list of all API endpoints (method, path, description). |
| `GET` | `/api/clients` | List observed client IPs with per-client query counters. |
| `GET` | `/api/clients/{ip}` | Detail for one client IP (counts, last seen). |
| `GET` | `/api/clients/{ip}/logs` | Recent query log entries for one client IP. |
| `GET` | `/api/audit/tail` | Tail of the per-entry HMAC-SHA256 audit log (most recent entries). **Admin only** (`403` for a non-admin key in multi-user mode). Query param `n` (default 100, max 1000). Response: `{"lines": [{"seq", "ts", "event", "fields", "mac"}], "count", "enabled"}` — see below. |
| `GET` | `/api/alerts/rules` | Alias of `GET /api/alerts` — identical response (active rules, blocked clients, recent events). |
| `POST` | `/api/upstreams/{id}/probe` | Trigger an immediate health probe of one upstream. |
| `POST` | `/api/webhooks/test` | Send a synthetic test event to the configured webhook targets. |
| `POST` | `/api/users/{id}/rotate-key` | Rotate (regenerate) the API key of a specific user. |
| `GET` | `/api/backup` | List existing backups in `base_dir/backups/`. |
| `POST` | `/api/backup` | Create a snapshot (config + DNS entries + blacklist + feeds). |
| `POST` | `/api/backup/restore` | Restore from a backup snapshot. |
| `DELETE` | `/api/backup/{id}` | Delete a backup snapshot. |
| `GET` | `/api/backup/export` | **Full backup** download (JSON): config + all state/secret files, base64-encoded. Contains secrets — store securely. |
| `POST` | `/api/backup/import` | **Full restore** from an exported backup; writes whitelisted files atomically. Restart to apply. Admin only; slave 503. |
| `GET` | `/api/tls/ca` | Download the Runbound Local CA certificate (PEM) for importing into a browser/OS trust store. |

### Examples

```bash
TOKEN="your-api-key"

# Probe one upstream immediately
curl -s -X POST http://localhost:8080/api/upstreams/<id>/probe \
  -H "Authorization: Bearer $TOKEN"

# Create a backup, then list backups.
# POST /api/backup parses a JSON body (an optional {"label": "..."}), so it MUST send
# Content-Type: application/json and a body — otherwise Axum rejects it with 415.
curl -s -X POST http://localhost:8080/api/backup -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{}'
curl -s        http://localhost:8080/api/backup -H "Authorization: Bearer $TOKEN"

# Tail the audit log
curl -s http://localhost:8080/api/audit/tail -H "Authorization: Bearer $TOKEN"
```
