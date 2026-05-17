# REST API Reference

Runbound exposes a REST API on **localhost only** (HTTP). The port defaults to
**8081** and is configurable with `api-port` in `runbound.conf`. All endpoints
except `GET /help` require a Bearer token.

---

## Authentication

```bash
export RUNBOUND_API_KEY="$(cat /etc/runbound/api.key)"
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8081/dns
```

Timing-safe comparison is used server-side (constant-time, immune to timing attacks).

---

## Endpoints

### `GET /help`

API documentation and endpoint list. **Requires Bearer authentication.**

```bash
export RUNBOUND_API_KEY="$(cat /etc/runbound/api.key)"
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8081/help
```

---

### DNS entries

Local DNS records — equivalent to `local-data` in the config file, but live.
Changes take effect immediately. No restart required.

#### `GET /dns`

List all local DNS entries.

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8081/dns
```

```json
{
  "entries": [
    {"id": "550e8400-...", "name": "nas.home.", "type": "A", "value": "192.168.1.10", "ttl": 300}
  ],
  "total": 1
}
```

#### `POST /dns`

Add a local DNS entry.

```bash
curl -X POST http://localhost:8081/dns \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"nas.home.","type":"A","value":"192.168.1.10","ttl":300}'
```

```json
{"status": "ok", "entry": {"id": "550e8400-...", ...}, "rr": "nas.home. 300 A 192.168.1.10"}
```

**Supported types:** `A`, `AAAA`, `CNAME`, `TXT`, `MX`, `SRV`, `CAA`, `PTR`,
`NAPTR`, `SSHFP`, `TLSA`, `NS`

**TTL:** Must be ≤ 2,147,483,647 (RFC 2181 §8 maximum). Capped at 86,400 s (24 h) server-side.

**Limit:** Maximum 10,000 entries. Returns `422` when exceeded.

#### `DELETE /dns/:id`

Remove an entry by its UUID (from the `id` field of `GET /dns`).

```bash
# First get the UUID:
ID=$(curl -s -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8081/dns \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['entries'][0]['id'])")

curl -X DELETE "http://localhost:8081/dns/$ID" \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

```json
{"status": "ok", "deleted_id": "550e8400-..."}
```

---

### Blacklist

Block domains — equivalent to `local-zone: "domain." always_nxdomain`, but live.

#### `GET /blacklist`

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8081/blacklist
```

```json
{"blacklist": [{"id": "...", "domain": "ads.example.com", "action": "nxdomain"}], "total": 1}
```

#### `POST /blacklist`

```bash
curl -X POST http://localhost:8081/blacklist \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain":"ads.example.com","action":"nxdomain"}'
```

**Actions:** `refuse` (REFUSED response), `nxdomain` (NXDOMAIN response)

**Limit:** Maximum 100,000 entries. Returns `422` when exceeded.

#### `DELETE /blacklist/:id`

Remove by UUID.

```bash
curl -X DELETE "http://localhost:8081/blacklist/$ID" \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

---

### Feeds

Subscribe to remote block-list feeds. Feeds auto-refresh every 24 hours.

#### `GET /feeds`

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8081/feeds
```

```json
{"feeds": [{"id": "...", "name": "urlhaus", "url": "https://...", "entry_count": 8432, "last_updated": "2026-05-16T10:00:00Z"}], "total": 1}
```

#### `POST /feeds`

Subscribe to a new feed. **Limit: 100 feeds maximum.**

```bash
curl -X POST http://localhost:8081/feeds \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"urlhaus","url":"https://urlhaus.abuse.ch/downloads/hostfile/","format":"hosts","action":"nxdomain"}'
```

**formats:** `hosts` (default), `domains`, `adblock`  
**Security:** Only HTTPS is accepted. HTTP URLs are **rejected** (HTTP 400). Redirects to private IPs or internal hostnames are blocked.

#### `GET /feeds/presets`

List built-in feed presets (OISD, StevenBlack, Hagezi, URLhaus, AdGuard...).

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8081/feeds/presets
```

#### `DELETE /feeds/:id`

Remove a feed subscription by UUID.

```bash
curl -X DELETE "http://localhost:8081/feeds/$ID" \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

#### `POST /feeds/update`

Refresh all enabled feeds immediately.

```bash
curl -X POST http://localhost:8081/feeds/update \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

```json
{"status": "ok", "results": [...], "summary": {"updated": 2, "errors": 0}}
```

#### `POST /feeds/:id/update`

Refresh a single feed by UUID.

```bash
curl -X POST "http://localhost:8081/feeds/$ID/update" \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

---

### TLS status

#### `GET /health`

Liveness probe. Returns uptime and total query count.

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8081/health
```

```json
{"status": "ok", "uptime_secs": 3600, "queries": 125432}
```

---

### `GET /stats`

Query statistics snapshot: counters, QPS, latency percentiles, cache metrics.

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8081/stats
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
  "cache_entries":   2941
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

**Total blocked = `blocked` + `nxdomain`.** The split exists because `refuse` and `nxdomain` are distinct DNS responses. Use `blocked_percent` or sum both fields for an aggregate blocking rate.

---

### `GET /stats/stream`

Live stats as Server-Sent Events — one JSON snapshot per second. Ideal for dashboards.

```bash
curl -N -H "Authorization: Bearer $RUNBOUND_API_KEY" \
     http://localhost:8081/stats/stream
```

```
data: {"total":125432,"blocked":8921,...,"qps_1m":34.7,"latency_p50_ms":0.3}

data: {"total":125465,"blocked":8921,...,"qps_1m":34.9,"latency_p50_ms":0.3}
```

The stream is a standard SSE event stream (`Content-Type: text/event-stream`). Each `data:` line is the same JSON object as `GET /stats`. The connection stays open until the client closes it.

> The `-N` flag disables curl's output buffering — required to see events in real time.

---

### `GET /upstreams`

Health status of each configured `forward-addr` upstream resolver. Probed every 30 seconds with a minimal DNS query (`. IN A`).

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8081/upstreams
```

```json
{
  "upstreams": [
    {
      "addr":       "1.1.1.1",
      "zone":       ".",
      "healthy":    true,
      "latency_ms": 12,
      "last_check": "2026-05-17T14:23:05Z"
    },
    {
      "addr":       "1.0.0.1",
      "zone":       ".",
      "healthy":    true,
      "latency_ms": 14,
      "last_check": "2026-05-17T14:23:05Z"
    }
  ],
  "total":   2,
  "healthy": 2
}
```

`healthy: false` means the last probe timed out or received no valid DNS response. Runbound continues resolving — an unhealthy upstream only affects its own weight in hickory's load balancing. A WARN log is emitted on each failure.

---

### `GET /logs`

Recent DNS query log, newest first. Up to 10,000 entries are kept in a fixed-size ring buffer (pre-allocated at startup, zero allocation per query).

```bash
# Last 100 queries (default)
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8081/logs

# Blocked queries only
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" \
     "http://localhost:8081/logs?action=blocked&limit=50"

# Filter by client IP
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" \
     "http://localhost:8081/logs?client=192.168.1.10"

# Queries since a Unix timestamp
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" \
     "http://localhost:8081/logs?since=1747483200"
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

---

### `GET /config`

Dump active configuration (sanitised — API key is omitted).

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8081/config
```

**Note on entry counts:** `file_local_data` and `file_local_zones` reflect only what is
in `runbound.conf`. Entries added via REST API (`POST /dns`, `POST /blacklist`, feeds)
appear in `api_dns_entries`, `api_blacklist`, and `api_feeds`. Use `GET /dns` and `GET /blacklist`
for the full live lists.

---

### `POST /reload`

Hot-reload: re-parse `runbound.conf` and rebuild all in-memory DNS data without dropping connections.
Equivalent to `systemctl reload runbound` (SIGHUP).

```bash
curl -X POST http://localhost:8081/reload \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

```json
{"status": "ok", "cfg_path": "/etc/runbound/runbound.conf", "local_zones": 5, "local_data": 12}
```

**Note:** ACL rules and forward-zone upstreams require a full restart.

---

### `GET /tls`

DoT/DoH/DoQ protocol status.

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8081/tls
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
| `400` | Bad request — malformed JSON or invalid field value |
| `401` | Unauthorized — missing or invalid Bearer token |
| `404` | Not found — UUID does not exist |
| `422` | Unprocessable — entry limit reached |
| `429` | Too many requests — rate limit exceeded |
| `500` | Internal server error |
| `503` | Service unavailable — slave node (read-only), write operation rejected |

