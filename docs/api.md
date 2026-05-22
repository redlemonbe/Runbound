# REST API Reference

Runbound exposes a REST API on **localhost only** (HTTP). The port defaults to
**8080** and is configurable with `api-port` in `runbound.conf`. All endpoints
require a Bearer token. `GET /health` is the only unauthenticated endpoint (liveness probe).

> **Looking for a GUI?** A ready-made browser dashboard is included at
> `examples/web-ui/index.html`. Setup in [web-ui.md](web-ui.md).

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

---

### Feeds

Subscribe to remote block-list feeds. Feeds auto-refresh every 24 hours.

#### `GET /api/feeds`

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/feeds
```

```json
{"feeds": [{"id": "...", "name": "urlhaus", "url": "https://...", "entry_count": 8432, "last_updated": "2026-05-16T10:00:00Z"}], "total": 1}
```

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

Liveness probe. **No authentication required.** Returns version, uptime, and status.

```bash
curl http://localhost:8080/health
```

```json
{"status": "ok", "version": "0.6.6", "uptime_secs": 3600}
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
  "blocked":         8921,
  "forwarded":       112000,
  "nxdomain":        4500,
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
  "cache_hit_rate":  68.4,
  "cache_entries":   2941,
  "dnssec": {
    "secure":   1042,
    "bogus":    3,
    "insecure": 897
  }
}
```

**Counter semantics:**

| Field | What it counts |
|---|---|
| `blocked` | Queries answered with **REFUSED** — blacklist / feeds / local-zone with `action: refuse` |
| `nxdomain` | Queries answered with **NXDOMAIN** — blacklist / feeds with `action: nxdomain`, or upstream NXDOMAIN |
| `forwarded` | Queries sent to an upstream resolver (network round-trip) |
| `local_hits` | Queries answered from local zone data (config + `POST /dns`) without upstream |
| `servfail` | Upstream returned SERVFAIL or DNSSEC validation failed |
| `blocked_percent` | `blocked / total × 100` — REFUSED blocking rate (f64, one decimal place) |
| `qps_1m` / `qps_5m` | Average queries/second over the last 1 and 5 minutes |
| `qps_peak` | All-time highest queries in any single second |
| `latency_p50/95/99_ms` | Latency percentiles from a fixed 10-bucket histogram (zero-alloc) |
| `cache_hit_rate` | Percentage of forwarded lookups served from hickory's in-process cache (< 2 ms) |
| `cache_entries` | Approximate distinct domains cached (saturates at resolver `cache_size = 8192`) |
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

The stream is a standard SSE event stream (`Content-Type: text/event-stream`). Each `data:` line is the same JSON object as `GET /stats`. The connection stays open until the client closes it.

> The `-N` flag disables curl's output buffering — required to see events in real time.

---

### `GET /api/logs`

Recent DNS query log, newest first. Entries are kept in a fixed-size ring buffer pre-allocated at startup (zero allocation per query). The buffer size is controlled by `log-retention` in `runbound.conf` (default: **1,000**, compile-time max: 10,000). Set to `0` to disable the buffer entirely.

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
| `cached` | Served from hickory's in-process DNS cache (< 2 ms) |
| `local` | Answered from local zone data (config or `POST /dns`) |
| `blocked` | Domain blocked by blacklist or feeds |
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
  "cache_max_ttl": 86400,
  "dnssec_validation": false,
  "log_retention": 1000,
  "log_client_ip": true,
  "api_port": null,
  "logfile": null,
  "prefetch": false,
  "prefetch_threshold": 5
}
```

**Note on entry counts:** `file_local_data` and `file_local_zones` reflect only what is
in `runbound.conf`. Entries added via REST API (`POST /dns`, `POST /blacklist`, feeds)
appear in `api_dns_entries`, `api_blacklist`, and `api_feeds`. Use `GET /dns` and `GET /blacklist`
for the full live lists.

---

### `POST /api/reload`

Hot-reload: re-parse `runbound.conf` and rebuild all in-memory DNS data without dropping connections.
Equivalent to `systemctl reload runbound` (SIGHUP).

```bash
curl -X POST http://localhost:8080/api/reload \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

```json
{"status": "ok", "cfg_path": "/etc/runbound/unbound.conf", "local_zones": 5, "local_data": 12}
```

**Note:** ACL rules, forward-zone upstreams, and privacy settings (`log-retention`, `log-client-ip`) require a full restart.

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
# HELP runbound_blocked_total Queries answered with REFUSED (blacklist/feeds)
# TYPE runbound_blocked_total counter
runbound_blocked_total 8921
# HELP runbound_qps Queries per second
# TYPE runbound_qps gauge
runbound_qps{window="1m"} 34.7
runbound_qps{window="5m"} 31.2
runbound_qps{window="peak"} 410
# HELP runbound_latency_ms DNS query latency percentiles in milliseconds
# TYPE runbound_latency_ms gauge
runbound_latency_ms{quantile="0.5"} 0.3
runbound_latency_ms{quantile="0.95"} 4.2
runbound_latency_ms{quantile="0.99"} 22.5
# HELP runbound_dnssec_total DNSSEC validation results
# TYPE runbound_dnssec_total counter
runbound_dnssec_total{status="secure"} 1000
runbound_dnssec_total{status="bogus"} 5
runbound_dnssec_total{status="insecure"} 100
...
```

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
    metrics_path: /metrics
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
curl -X POST http://localhost:8080/rotate-key \
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
  "cert": "/etc/runbound/cert.pem"
}
```

---

### `GET /api/system`

Runtime system metrics.

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/system
```

```json
{
  "version": "0.6.6",
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
  "upstreams_total": 3
}
```

`xdp_mode`: `"drv"` (native zero-copy), `"skb"` (generic fallback), `"disabled"`.

| Field | Type | Description |
|---|---|---|
| `prefetch_enabled` | bool | `true` when `prefetch: yes` is set in `runbound.conf` |
| `upstreams_healthy` | u32 | Count of upstreams with `healthy == true` at last health check |
| `upstreams_total` | u32 | Total registered upstreams (config + API) |

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
  "cache_hits":      4823,
  "cache_misses":    1247,
  "cache_evictions": 18,
  "hit_rate_pct":    79.4
}
```

| Field | Type | Description |
|-------|------|-------------|
| `cache_hits` | u64 | Responses served from the in-process cache |
| `cache_misses` | u64 | Cache misses forwarded to an upstream |
| `cache_evictions` | u64 | Entries evicted to enforce the cache size limit |
| `hit_rate_pct` | f64 or `null` | `hits / (hits + misses) × 100`, rounded to 1 decimal. `null` when both hits and misses are zero. |

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
      "name": "Cloudflare",
      "addr": "1.1.1.1",
      "port": 53,
      "protocol": "udp",
      "healthy": true,
      "latency_ms": 12,
      "last_check": "2026-05-22T15:00:00Z",
      "zone": ".",
      "dnssec_supported": true,
      "latency_history": [11, 12, 14, 11, 13]
    }
  ],
  "total": 1,
  "healthy": 1
}
```

**New fields (v0.6.5):**

| Field | Type | Description |
|-------|------|-------------|
| `dnssec_supported` | `bool` or absent | `true` if the upstream sets the AD bit in probe responses. Absent (not `null`) when unhealthy or not yet probed. DoT upstreams always omit this field. |
| `latency_history` | `[u64]` | Last ≤ 5 successful probe round-trip times (ms). Empty array until the first successful probe. Failed probes do not append. |

#### `POST /api/upstreams`

```bash
curl -X POST http://localhost:8080/api/upstreams \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"Cloudflare DoT","addr":"1.1.1.1","port":853,"protocol":"dot"}'
```

**Validation:**

| Field | Rules |
|-------|-------|
| `addr` | Valid IP address. Loopback (`127.x.x.x`, `::1`) and IPv4 link-local (`169.254.x.x`) are rejected (`400 INVALID_ADDR`). Private ranges (RFC 1918) and IPv6 ULA are allowed. |
| `protocol` | `"udp"` or `"dot"` (`400 INVALID_PROTOCOL` otherwise). |
| `port` | 1–65535. Defaults to 53 (UDP) or 853 (DoT) when omitted. Port 0 returns `400 INVALID_PORT`. |

#### `DELETE /api/upstreams/:id`

```bash
curl -X DELETE -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  http://localhost:8080/api/upstreams/550e8400-...
```

Returns `409 LAST_UPSTREAM` when the target is the only registered upstream — the
resolver must always have at least one forwarder.

#### `PATCH /api/upstreams/:id`

Rename an upstream in-place. Only the `name` field is patchable.

```bash
curl -X PATCH http://localhost:8080/api/upstreams/550e8400-... \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"My Cloudflare"}'
```

- An empty string or `null` clears the name (`name` becomes absent in the response).
- Any field other than `name` returns `400 INVALID_FIELD`.
- Unknown id returns `404`.
- The rename is persisted to `upstreams.json` immediately.

#### `GET /api/upstreams/presets`

Nine built-in presets: Cloudflare (UDP + DoT), Google, Quad9 (UDP + DoT), OpenDNS, AdGuard DNS.
Each preset carries a bare IP `addr` and a separate `port` field (no `@port` suffix).

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/upstreams/presets
```

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
      "version": "0.6.2"
    }
  ],
  "total": 1
}
```

`status`: `"connected"` (< 30 s), `"stale"` (< 120 s), `"disconnected"` (> 120 s).

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

