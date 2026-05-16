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
| `cache-max-ttl` | ✅ | 🔜 | Planned |
| `private-address` | ✅ | 🔜 | Planned |
| `module-config` | ✅ | ❌ | Unbound modules not supported |
| `python-script` | ✅ | ❌ | No Python scripting |
| `dnstap` | ✅ | ❌ | Not planned |

### `forward-zone:` block

| Directive | Unbound | Runbound | Notes |
|---|:---:|:---:|---|
| `name` | ✅ | ✅ | |
| `forward-addr` | ✅ | ✅ | `ip@port` syntax supported |
| `forward-tls-upstream` | ✅ | 🔜 | Planned |
| `forward-first` | ✅ | ❌ | |

### Runbound-only directives

| Directive | Description |
|---|---|
| `api-key` | REST API Bearer token (prefer `RUNBOUND_API_KEY` env var) |

---

## Step-by-step migration

### 1. Install Runbound

```bash
curl -LO https://github.com/redlemonbe/Runbound/releases/latest/download/runbound-x86_64-linux-musl
chmod +x runbound-x86_64-linux-musl
sudo mv runbound-x86_64-linux-musl /usr/local/bin/runbound
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
