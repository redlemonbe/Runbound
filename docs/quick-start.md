# Quick Start

Up and running in 5 minutes.

---

## 1. Install

```bash
curl -sSf https://raw.githubusercontent.com/redlemonbe/Runbound/main/install.sh | sudo bash
```

That's it — the script detects your architecture (x86_64 / ARM64), downloads the
correct static musl binary from the latest release, installs it to
`/usr/local/sbin/runbound`, creates the `runbound` system user, and installs the
hardened systemd unit file.

**Manual install** (if you prefer not to pipe to bash):

```bash
# Download and inspect first:
curl -sSf -o install.sh https://raw.githubusercontent.com/redlemonbe/Runbound/main/install.sh
less install.sh
sudo bash install.sh
```

---

## 2. Configure

`install.sh` already created `/etc/runbound/runbound.conf` with sensible defaults.
Edit it to match your network:

```bash
sudo nano /etc/runbound/runbound.conf
```

Key settings to review:

```
server:
    interface:  0.0.0.0          # or a specific IP
    access-control: 192.168.0.0/16  allow   # your LAN subnet
    rate-limit: 200              # queries/s per client IP (0 = disabled)

forward-zone:
    name:         "."
    forward-addr: 1.1.1.1@853   # upstream resolver
```

**Migrating from Unbound?** Your existing config works as-is — Runbound reads
the same `server:`, `forward-zone:`, `local-zone:`, and `local-data:` directives.
See [unbound-migration.md](unbound-migration.md) for the full compatibility table.

```bash
# To use your existing Unbound config instead of the default:
sudo cp /etc/unbound/unbound.conf /etc/runbound/runbound.conf
```

---

## 3. Run

```bash
# Foreground (test first):
sudo RUNBOUND_API_KEY="your-key" runbound --config /etc/runbound/runbound.conf

# Verify DNS is working:
dig @127.0.0.1 google.com

# Verify the API is reachable:
curl -s http://localhost:8080/health -H "Authorization: Bearer $RUNBOUND_API_KEY"
# → {"status":"ok","uptime_secs":3,"queries":0}
```

---

## 4. Install as a service (production)

If you used `install.sh` (Step 1), the systemd unit is already installed and the
`runbound` system user already exists. Just enable and start:

```bash
sudo systemctl enable --now runbound
```

For manual installs or a custom hardened unit file, see [systemd.md](systemd.md).

---

## 5. First API calls

```bash
API="http://localhost:8080"
TOKEN="your-key"

# Add a local DNS entry
curl -s -X POST "$API/dns" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"myserver.home.","type":"A","value":"192.168.1.50","ttl":300}'

# Check it resolves
dig @127.0.0.1 myserver.home.

# View stats
curl -s "$API/stats" -H "Authorization: Bearer $TOKEN"
```

That's all. For the full API reference see [api.md](api.md).

---

## Privacy defaults

By default Runbound keeps the last 1,000 queries (with client IPs) in a RAM ring buffer accessible via `GET /logs`. If this doesn't fit your retention policy:

```
server:
    log-retention: 0     # disable the ring buffer entirely
    log-client-ip: no    # or: keep the buffer but redact IPs
```

See [gdpr.md](gdpr.md) for the full GDPR compliance guide.

---

## Master / Slave replication

To replicate state (blacklist, zones, feeds) from a master to one or more slaves,
see [sync.md](sync.md).

> **Quick reminder:** open TCP port 8082 on the master firewall — this is the
> most common reason slave synchronisation fails.
