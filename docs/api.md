# REST API Reference

Runbound exposes a REST API on port **8081** (HTTP). All write endpoints require
a Bearer token set via `RUNBOUND_API_KEY`.

---

## Authentication

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8081/stats
```

Timing-safe comparison is used server-side — not vulnerable to timing attacks.

---

## Endpoints

### Health

#### `GET /health`

Liveness probe. No authentication required.

```bash
curl http://localhost:8081/health
```

```json
{"status": "ok"}
```

---

### DNS entries

Local DNS records — equivalent to `local-data` in the config file, but live.
Changes take effect immediately. No restart required.

#### `GET /dns`

List all local DNS entries.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/dns
```

```json
[
  {"name": "nas.home.", "type": "A", "value": "192.168.1.10", "ttl": 300},
  {"name": "printer.home.", "type": "A", "value": "192.168.1.20", "ttl": 300}
]
```

#### `POST /dns`

Add a local DNS entry.

```bash
curl -X POST http://localhost:8081/dns \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"nas.home.","type":"A","value":"192.168.1.10","ttl":300}'
```

```json
{"status": "added", "name": "nas.home."}
```

**Fields:**

| Field | Required | Description |
|---|---|---|
| `name` | ✅ | FQDN (trailing dot required). |
| `type` | ✅ | `A`, `AAAA`, `PTR`, `CNAME`, `MX`, `TXT` |
| `value` | ✅ | Record value. |
| `ttl` | ❌ | TTL in seconds. Default: 300. |

**Limits:** Maximum 10,000 entries. Returns `422` when exceeded.

#### `DELETE /dns/{name}`

Remove a local DNS entry by name.

```bash
curl -X DELETE http://localhost:8081/dns/nas.home. \
  -H "Authorization: Bearer $TOKEN"
```

```json
{"status": "deleted", "name": "nas.home."}
```

---

### Blacklist

Block domains — equivalent to `local-zone: "domain." always_nxdomain`, but live.

#### `GET /blacklist`

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/blacklist
```

```json
["ads.example.com", "tracker.evil.com"]
```

#### `POST /blacklist`

```bash
curl -X POST http://localhost:8081/blacklist \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"ads.example.com"}'
```

```json
{"status": "blocked", "domain": "ads.example.com"}
```

**Limit:** Maximum 100,000 entries. Returns `422` when exceeded.

#### `DELETE /blacklist/{domain}`

```bash
curl -X DELETE http://localhost:8081/blacklist/ads.example.com \
  -H "Authorization: Bearer $TOKEN"
```

```json
{"status": "unblocked", "domain": "ads.example.com"}
```

---

### Feeds

Subscribe to remote block-list feeds (URLhaus, StevenBlack, etc.). Feeds are
fetched periodically and their domains added to the blacklist automatically.

#### `GET /feeds`

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/feeds
```

```json
[
  {
    "name": "urlhaus",
    "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
    "last_updated": "2026-05-16T10:00:00Z",
    "domain_count": 8432
  }
]
```

#### `POST /feeds`

Subscribe to a new feed.

```bash
curl -X POST http://localhost:8081/feeds \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"urlhaus","url":"https://urlhaus.abuse.ch/downloads/hostfile/"}'
```

```json
{"status": "subscribed", "name": "urlhaus"}
```

**Security:** HTTPS is strongly recommended. HTTP feeds trigger a warning in logs.
Redirects to private IPs are blocked server-side (SSRF protection).

#### `DELETE /feeds/{name}`

```bash
curl -X DELETE http://localhost:8081/feeds/urlhaus \
  -H "Authorization: Bearer $TOKEN"
```

#### `POST /feeds/{name}/refresh`

Force an immediate refresh without waiting for the scheduled interval.

```bash
curl -X POST http://localhost:8081/feeds/urlhaus/refresh \
  -H "Authorization: Bearer $TOKEN"
```

```json
{"status": "refreshed", "name": "urlhaus", "domain_count": 8441}
```

---

### Statistics

#### `GET /stats`

Live query counters since last start.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/stats
```

```json
{
  "total": 142857,
  "answered_local": 98432,
  "blocked": 12000,
  "forwarded": 32425,
  "nxdomain": 8432,
  "refused": 21,
  "uptime_seconds": 86400
}
```

---

### Configuration

#### `GET /config`

Dump the active configuration. Secrets (API key, TLS key path) are redacted.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/config
```

```json
{
  "interface": "0.0.0.0",
  "port": 53,
  "rate_limit": 500,
  "access_control": ["127.0.0.0/8 allow", "0.0.0.0/0 refuse"],
  "tls_enabled": true,
  "api_key": "[redacted]"
}
```

#### `POST /reload`

Hot-reload the configuration file without restarting the process. DNS service
stays up during reload — zero downtime.

```bash
curl -X POST http://localhost:8081/reload \
  -H "Authorization: Bearer $TOKEN"
```

```json
{"status": "reloaded"}
```

---

## HTTP status codes

| Code | Meaning |
|---|---|
| `200` | Success |
| `201` | Created |
| `400` | Bad request — malformed JSON or missing field |
| `401` | Unauthorized — missing or invalid Bearer token |
| `404` | Not found — entry or feed does not exist |
| `409` | Conflict — entry already exists |
| `422` | Unprocessable — entry limit reached |
| `500` | Internal server error |

---

## Rate limiting the API

The REST API shares the same rate limiter as DNS. If your management host
is constrained by `rate-limit`, add it to an `allow` subnet or increase the limit.
