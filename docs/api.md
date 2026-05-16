# REST API Reference

Runbound exposes a REST API on **localhost only** (HTTP). The port defaults to
**8081** and is configurable with `api-port` in `runbound.conf`. All endpoints
except `GET /help` require a Bearer token.

---

## Authentication

```bash
export RUNBOUND_API_KEY="$(cat /etc/runbound/env | cut -d= -f2)"
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8081/dns
```

Timing-safe comparison is used server-side (constant-time, immune to timing attacks).

---

## Endpoints

### `GET /help`

API documentation. **No authentication required.**

```bash
curl http://localhost:8081/help
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
**Security:** Only HTTPS is accepted. HTTP triggers a server-side warning. Redirects to private IPs or internal hostnames are blocked.

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

#### `GET /tls`

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

---

## Endpoints missing from this version

The following endpoints were described in early changelog entries but are **not
implemented** in v0.2.3:

| Endpoint | Status |
|---|---|
| `GET /health` | Not implemented — use `systemctl is-active runbound` |
| `GET /stats` | Not implemented — query statistics not collected |
| `GET /config` | Not implemented |
| `POST /reload` | Not implemented — use `systemctl reload runbound` (SIGHUP) |

These are tracked as high-priority items in the security audit (AUDIT-CRIT-01).
