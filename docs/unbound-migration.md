# Unbound Migration Guide

Runbound is designed as a drop-in replacement. In most cases, pointing it at your
existing `unbound.conf` is all you need.

---

## Directive compatibility

### `server:` block

| Directive | Unbound | Runbound | Notes |
|---|:---:|:---:|---|
| `interface` | ✅ | ✅ | |
| `port` | ✅ | ✅ | |
| `do-ip4` | ✅ | ✅ | |
| `do-ip6` | ✅ | ✅ | |
| `do-udp` | ✅ | ✅ | |
| `do-tcp` | ✅ | ✅ | |
| `access-control` | ✅ | ✅ | `allow`, `deny`, `refuse` |
| `local-zone` | ✅ | ✅ | `static`, `always_nxdomain` |
| `local-data` | ✅ | ✅ | A, AAAA, PTR, CNAME, MX, TXT |
| `tls-service-pem` | ✅ | ✅ | DoT port 853 |
| `tls-service-key` | ✅ | ✅ | |
| `rate-limit` | ✅ | ✅ | per-source-IP token bucket |
| `logfile` | ✅ | ✅ | `""` = stdout |
| `verbosity` | ✅ | ✅ | 0–5 |
| `num-threads` | ✅ | ⚠️ | Ignored — Runbound uses Tokio async |
| `cache-max-ttl` | ✅ | ✅ | Since v0.2.2 |
| `private-address` | ✅ | ✅ | Since v0.2.2 — DNS rebinding protection |
| `dnssec-validation` | ✅ | ✅ | Since v0.2.5 — enable only for recursive mode |
| `module-config` | ✅ | ❌ | Unbound modules not supported |
| `python-script` | ✅ | ❌ | No Python scripting |
| `dnstap` | ✅ | ❌ | Not planned |

### `forward-zone:` block

| Directive | Unbound | Runbound | Notes |
|---|:---:|:---:|---|
| `name` | ✅ | ✅ | |
| `forward-addr` | ✅ | ✅ | `ip@port` syntax supported |
| `forward-tls-upstream` | ✅ | ✅ | Since v0.2.2 — DNS-over-TLS to upstream |
| `forward-first` | ✅ | ❌ | |

### Runbound-only directives

| Directive | Description |
|---|---|
| `api-key` | REST API Bearer token (prefer `RUNBOUND_API_KEY` env var) |
| `api-port` | REST API port (default: 8080) |
| `rate-limit` | Per-IP DNS rate limit in q/s (default: 200, max: 1,000,000) |
| `cache-max-ttl` | TTL cap for cached records in seconds (default: 86400) |
| `dnssec-validation` | Enable local DNSSEC re-validation (default: no) |
| `dnssec-log-bogus` | Log WARN on DNSSEC failures (default: no) |
| `log-retention` | In-RAM query log ring buffer size (default: 1000, 0 = disabled) |
| `log-client-ip` | Include client IPs in `/logs` (default: yes — set `no` for GDPR) |
| `audit-log` | Enable HMAC-SHA256 chained audit log (default: no) |
| `audit-log-path` | Path for the audit log file |
| `audit-log-hmac-key` | HMAC key (hex). Auto-generated if omitted |
| `mode` | `master` (default) or `slave` — HA replication role |
| `sync-port` | Master: HTTPS sync server port |
| `sync-master` | Slave: `ip:port` of master |
| `sync-key` | Slave: Bearer token for master auth |
| `sync-interval` | Slave: sync interval in seconds (default: 30) |
| `acme-email` | ACME contact email for Let's Encrypt |
| `acme-domain` | Domain(s) for the certificate (repeat for SANs) |
| `acme-cache-dir` | Directory for ACME credentials and temp files |
| `acme-staging` | Use Let's Encrypt Staging (default: no) |
| `acme-challenge-port` | HTTP-01 challenge port (default: 80) |
| `tls-service-pem` | TLS certificate path for DoT/DoH/DoQ |
| `tls-service-key` | TLS private key path |
| `tls-port` | DNS-over-TLS port (default: 853) |
| `https-port` | DNS-over-HTTPS port (default: 443) |
| `quic-port` | DNS-over-QUIC port (default: 853/UDP) |
| `tls-cert-hostname` | Hostname for TLS SNI and DoH path |
| `private-address` | CIDR ranges to block in resolver responses (rebinding guard) |

---

## Step-by-step migration

### 1. Install Runbound

```bash
# Replace vX.Y.Z with the latest version tag from the releases page
curl -LO https://github.com/redlemonbe/Runbound/releases/latest/download/runbound-vX.Y.Z-x86_64-linux-musl
chmod +x runbound-vX.Y.Z-x86_64-linux-musl
sudo mv runbound-vX.Y.Z-x86_64-linux-musl /usr/local/sbin/runbound
```

### 2. Test against your existing config

```bash
# Run on a non-standard port first to avoid disruption
sudo RUNBOUND_API_KEY="test" runbound \
  --config /etc/unbound/unbound.conf \
  --port 5353

# Verify resolution
dig @127.0.0.1 -p 5353 google.com
dig @127.0.0.1 -p 5353 your-internal-host.corp.
```

### 3. Stop Unbound, start Runbound

```bash
sudo systemctl stop unbound
sudo systemctl disable unbound

sudo systemctl enable --now runbound
```

### 4. Roll back if needed

```bash
sudo systemctl stop runbound
sudo systemctl start unbound
```

---

## Known differences in behaviour

**Default ACL:** Unbound defaults to `refuse` for unknown IPs. Runbound does the same —
if no `access-control` entries match, the request is refused. No change needed.

**IPv4-mapped IPv6:** If a client connects via IPv6 as `::ffff:10.0.0.1`, Runbound
normalises it to `10.0.0.1` before ACL matching. Unbound behaviour varies by version.

**`num-threads`:** Unbound spawns OS threads; Runbound uses a Tokio async runtime
with `SO_REUSEPORT`. Setting `num-threads` in your config is harmless — it's silently
ignored.

**Module config:** If your Unbound config loads modules (`python`, `dynlib`, etc.),
strip those lines before migrating. Runbound will warn about unknown directives.
