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
  "rcode":      "NOERROR",
  "action":     "forwarded",
  "from_cache": false,
  "elapsed_ms": 14,
  "records": [
    {"value": "142.250.179.46", "ttl": 300}
  ]
}
```

Blocked domain example:

```json
{
  "rcode":      "NXDOMAIN",
  "action":     "blocked",
  "from_cache": true,
  "elapsed_ms": 0,
  "records":    []
}
```

**Fields:**

| Field | Required | Default | Notes |
|-------|----------|---------|-------|
| `name` | Yes | — | Domain name (trailing dot optional) |
| `type` | No | `"A"` | Record type: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `PTR`, `NS`, `SOA` |
| `value` | Yes | — | Record value (IP for A/AAAA, hostname for CNAME/MX/NS, text for TXT) |
| `ttl` | No | 3600 | TTL in seconds (0–2147483647, capped at 86400) |
| `priority` | No | — | Required for `MX` and `SRV` records (0–65535). Default: 10 if omitted |
| `weight` | No | — | `SRV` only: load-balancing weight |
| `port` | No | — | `SRV` only: target port |

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

#### XDP fast-path blacklist (v0.9.53+)

When XDP is active, blacklisted domains are pushed into a BPF hash map
(`dns_blacklist`, 500 000 entries). IPv4 DNS queries matching a blocked domain are
answered with **NXDOMAIN in-place at the XDP layer** — no kernel stack, no hickory
overhead (~1 µs RTT).

- IPv6 queries for blocked domains fall through to the hickory slow path (still blocked).
- The map is updated atomically after every `POST /api/blacklist` and `DELETE /api/blacklist/:id`.
- `GET /api/stats` includes `xdp_blocked_total` — packets blocked at the XDP layer.
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
  "version":             "0.9.41",
  "uptime_secs":         3600,
  "xdp_active":          true,
  "upstreams_healthy":   4,
  "cache_entries":       48231
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

### `GET /api/stats/top-domains`

Most-queried domain names since process start, sorted by query count descending.
Tracks up to 10,000 distinct domains. Counter is cumulative (not windowed).

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


### `PATCH /api/config`

Toggle runtime settings without restarting. Currently supports DNSSEC validation
(when full-recursion is active the sovereign recursor is rebuilt so the new policy takes effect).
The change is applied immediately and propagated to all registered slaves.

```bash
curl -X PATCH http://localhost:8080/api/config \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"dnssec_validation": true}'
```

```json
{"ok": true, "dnssec_validation": true}
```

| Field | Type | Description |
|---|---|---|
| `dnssec_validation` | bool | Enable or disable DNSSEC validation at runtime |

**Note:** This change is not persisted to `runbound.conf`. To make it permanent, edit `dnssec-validation: yes/no` in the config file and restart.

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

**Note:** ACL rules, forward-zone upstreams, and privacy settings (`log-retention`, `log-client-ip`) require a full restart. As of v0.9.44, alert rules **are** reloaded by `POST /api/reload` without a restart.

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
# HELP runbound_nic_rx_ring NIC RX ring depth currently applied (descriptors)
# TYPE runbound_nic_rx_ring gauge
runbound_nic_rx_ring 4096
# HELP runbound_nic_rx_ring_max Maximum NIC RX ring depth supported by the driver
# TYPE runbound_nic_rx_ring_max gauge
runbound_nic_rx_ring_max 4096
# HELP runbound_nic_rx_dropped_total Hardware RX drops at NIC level (pre-XDP)
# TYPE runbound_nic_rx_dropped_total counter
runbound_nic_rx_dropped_total 0
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
  "cert": "/etc/runbound/cert.pem"
}
```

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
  "cert": { "subject_cn": "dns.example.com", "self_signed": true, "not_after": 1788000000,
            "days_remaining": 365, "expired": false, "fingerprint_sha256": "AB:CD:...", "sans": ["dns.example.com"] }
}
```

---

### `POST /api/tls/self-signed`

Generate a self-signed certificate + key for `hostname` and enable DoT/DoH/DoQ. The key is written `0600` (atomic) in `base_dir`; the config is updated. **Admin only.** Requires a restart to bind the listeners (`restart_required: true`).

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

Import an existing certificate + key (e.g. Lets Encrypt). The pair is validated against rustls (the key must match the leaf certificate) before being written; a mismatch returns `400`. Key written `0600`. **Admin only.** `restart_required: true`.

```bash
curl -X POST http://localhost:8080/api/tls/import \
  -H "Authorization: Bearer $RUNBOUND_API_KEY" -H "Content-Type: application/json" \
  -d '{"cert_pem":"-----BEGIN CERTIFICATE-----\n...","key_pem":"-----BEGIN PRIVATE KEY-----\n...","hostname":"dns.example.com"}'
```

---

### `DELETE /api/tls`

Disable encrypted DNS (clears `tls-service-pem` / `tls-service-key`). **Admin only.** `restart_required: true`.

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
  "version": "0.9.41",
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
  "nic_rx_ring": 4096,
  "nic_rx_ring_max": 4096,
  "nic_rx_dropped": 0,
  "anycast": { "configured": true, "address": "198.51.100.53/32", "announced": true, "peer": "192.168.1.1", "local_as": 65001 }
}
```

`xdp_mode`: `"drv"` (native zero-copy), `"skb"` (generic fallback), `"disabled"`.

| Field | Type | Description |
|---|---|---|
| `prefetch_enabled` | bool | `true` when `prefetch: yes` is set in `runbound.conf` |
| `upstreams_healthy` | u32 | Count of upstreams with `healthy == true` at last health check |
| `upstreams_total` | u32 | Total registered upstreams (config + API) |
| `nic_rx_ring` | u32 | Current RX ring depth applied to the NIC (descriptors). `0` when XDP is disabled or the driver does not support ethtool ring queries. |
| `nic_rx_ring_max` | u32 | Maximum RX ring depth supported by the driver. Equal to `nic_rx_ring` when auto-sizing succeeded. |
| `nic_rx_dropped` | u64 | Hardware-level RX drops read from `/sys/class/net/<iface>/statistics/rx_dropped`. A non-zero value under load indicates the NIC FIFO is overflowing before XDP sees the packets. |
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
  "cache_hits":      58432,
  "cache_misses":    3201,
  "cache_evictions": 18,
  "hit_rate_pct":    94.8
}
```

| Field | Type | Description |
|-------|------|-------------|
| `cache_hits` | u64 | Responses served from the in-process cache |
| `cache_misses` | u64 | Cache misses forwarded to an upstream |
| `cache_evictions` | u64 | Entries evicted to enforce the cache size limit |
| `hit_rate_pct` | f64 or `null` | `cache_hits / (cache_hits + cache_misses) × 100`, rounded to 1 decimal. `null` when both are zero. |

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
      "source": "runtime",
      "temporary": false
    }
  ],
  "total": 1,
  "healthy": 1
}
```

| Field | Type | Description |
|-------|------|-------------|
| `source` | `"runtime"`, `"config"`, or `"resolv.conf"` | `"config"` for upstreams loaded from `forward-zone` in `runbound.conf`; `"runtime"` for upstreams added via API; `"resolv.conf"` for temporary emergency fallback upstreams injected from `/etc/resolv.conf`. |
| `temporary` | bool | `true` for upstreams injected as emergency fallback from `/etc/resolv.conf`. These upstreams are never persisted to `upstreams.json` and are automatically removed when a primary upstream recovers. Always `false` for normal upstreams. |
| `tls_hostname` | `string` or absent | DoT only. TLS SNI hostname used for certificate validation. Absent when not set (auto-detected from well-known IPs). |
| `last_error` | `string` or `null` | Short description of the last probe failure (`"connection timeout"`, `"tls handshake failed"`, etc.). `null` when the last probe succeeded. |
| `dnssec_supported` | `bool` or absent | `true` if the upstream sets the AD bit in probe responses. Absent when unhealthy or not yet probed. DoT upstreams always omit this field. |
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

Nine built-in presets: Cloudflare (UDP + DoT), Google, Quad9 (UDP + DoT), OpenDNS, AdGuard DNS.
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
  "id": "550e8400-...",
  "healthy": true,
  "latency_ms": 14,
  "dnssec_supported": true,
  "probed_at": "2026-05-22T15:00:00Z"
}
```

On failure:

```json
{
  "id": "550e8400-...",
  "healthy": false,
  "latency_ms": null,
  "dnssec_supported": null,
  "last_error": "connection timeout",
  "probed_at": "2026-05-22T15:00:00Z"
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
{"reconnected": 4, "failed": 0}
```

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
      "version": "0.6.2"
    }
  ],
  "total": 1
}
```

`status`: `"connected"` (< 30 s), `"stale"` (< 120 s), `"disconnected"` (> 120 s).

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
      "version":          "0.6.20"
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
| `status` | `"connected"` (< 30 s), `"stale"` (< 120 s), `"disconnected"` (> 120 s) since last registration. |

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
{"burst":8,"enable":true,"rate_limit":20}
```

---

#### `PUT /api/icmp/config`

Live-update the ICMP responder config. Changes are applied to the BPF map within 1 second
(next background poll tick).

```bash
curl -X PUT -H "Authorization: Bearer $RUNBOUND_API_KEY" \
     -H "Content-Type: application/json" \
     -H "Content-Length: 41" \
     -d '{"enable":true,"rate_limit":20,"burst":8}' \
     http://localhost:8080/api/icmp/config
```

**Request body** (all fields optional — omitted fields keep their current value):

| Field | Type | Description |
|---|---|---|
| `enable` | bool | Enable/disable the ICMP echo responder |
| `rate_limit` | integer | Max echo requests per second per source IP |
| `burst` | integer | Initial burst tokens granted to new source IPs |

Returns the updated config:

```json
{"burst":8,"enable":true,"rate_limit":20}
```

---

## Alert thresholds

Monitor client query rates and automatically block abusive sources.
Alert rules are defined in `runbound.conf` (see [Configuration](configuration.md#alert-directives)).
As of v0.9.44, alert rules are reloaded by `POST /api/reload` — a full restart is no longer required to update them.

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

> **Enforcement (v0.16.2+).** Banned IPs and the per-source `rate-limit` are enforced on
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

Response:
```json
[
  {
    "id": "a1b2c3d4-...",
    "username": "alice",
    "api_key": "...",
    "zone_prefixes": ["home.", "internal."],
    "enabled": true,
    "admin": false
  }
]
```

#### `POST /api/users`

Create a user. Returns the new API key — **copy it immediately, it is not shown again**.

```bash
curl -X POST -H "Authorization: Bearer $MASTER_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/users \
  -d '{"username":"alice","zone_prefixes":["home.","internal."],"admin":false}'
```

Response: `201 Created`
```json
{
  "id": "a1b2c3d4-...",
  "username": "alice",
  "api_key": "3a7f9e2c...",
  "zone_prefixes": ["home.", "internal."],
  "enabled": true,
  "admin": false
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

Generate a new API key. Allowed for admins or the user themselves. The old key is immediately invalidated.

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
`runbound.conf`; changes apply on the **next service restart** (the resolver's split-horizon
table is built at boot). Slave nodes are read-only (`503`).

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

Add (or replace by name) an entry.

```bash
curl -s -X POST http://127.0.0.1:8080/api/split-horizon -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name":"internal","subnets":["10.0.0.0/8"],"local_data":["intra.example. A 10.0.0.5"]}'
```

#### `DELETE /api/split-horizon/:name`

Remove an entry by name.

```bash
curl -s -X DELETE http://127.0.0.1:8080/api/split-horizon/internal -H "Authorization: Bearer $KEY"
```

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

## Additional endpoints

These endpoints are served by the API but were previously undocumented. All require
the `Authorization: Bearer <api-key>` header (admin role unless noted). The API binds
to localhost only.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/help` | Machine-readable list of all API endpoints (method, path, description). |
| `GET` | `/api/clients` | List observed client IPs with per-client query counters. |
| `GET` | `/api/clients/{ip}` | Detail for one client IP (counts, last seen). |
| `GET` | `/api/clients/{ip}/logs` | Recent query log entries for one client IP. |
| `GET` | `/api/audit/tail` | Tail of the HMAC-chained audit log (most recent entries). |
| `POST` | `/api/upstreams/{id}/probe` | Trigger an immediate health probe of one upstream. |
| `POST` | `/api/webhooks/test` | Send a synthetic test event to the configured webhook targets. |
| `POST` | `/api/users/{id}/rotate-key` | Rotate (regenerate) the API key of a specific user. |
| `GET` | `/api/backup` | List existing backups in `base_dir/backups/`. |
| `POST` | `/api/backup` | Create a snapshot (config + DNS entries + blacklist + feeds). |
| `POST` | `/api/backup/restore` | Restore from a backup snapshot. |
| `DELETE` | `/api/backup/{id}` | Delete a backup snapshot. |
| `GET` | `/api/backup/export` | **Full backup** download (JSON): config + all state/secret files, base64-encoded. Contains secrets — store securely. |
| `POST` | `/api/backup/import` | **Full restore** from an exported backup; writes whitelisted files atomically. Restart to apply. Admin only; slave 503. |

### Examples

```bash
TOKEN="your-api-key"

# Probe one upstream immediately
curl -s -X POST http://localhost:8080/api/upstreams/<id>/probe \
  -H "Authorization: Bearer $TOKEN"

# Create a backup, then list backups
curl -s -X POST http://localhost:8080/api/backup -H "Authorization: Bearer $TOKEN"
curl -s        http://localhost:8080/api/backup -H "Authorization: Bearer $TOKEN"

# Tail the audit log
curl -s http://localhost:8080/api/audit/tail -H "Authorization: Bearer $TOKEN"
```
