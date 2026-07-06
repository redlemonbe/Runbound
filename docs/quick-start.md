# Quick Start

Up and running in 5 minutes.

---

## 1. Install

```bash
curl -fsSL https://github.com/redlemonbe/Runbound/releases/latest/download/install.sh | sudo bash
```

That's it — the script detects your architecture (x86_64 / ARM64), downloads the
correct static musl binary from the latest release, installs it to
`/usr/local/sbin/runbound`, creates the `runbound` system user, and installs the
hardened systemd unit file.

**Manual install** (if you prefer not to pipe to bash):

```bash
# Download and inspect first:
curl -fsSL -o install.sh https://github.com/redlemonbe/Runbound/releases/latest/download/install.sh
less install.sh
sudo bash install.sh
```

At the end you'll see your API key and the service URL:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Version:  runbound 0.9.1
 API key:  a1b2c3d4...   ← save this
 Config:   /etc/runbound/runbound.conf
 Logs:     journalctl -u runbound -f
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Save the API key** — you'll need it to use the dashboard and the REST API.

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
    forward-tls-upstream: yes
```

**Migrating from Unbound?** Your existing config works as-is — Runbound reads
the same `server:`, `forward-zone:`, `local-zone:`, and `local-data:` directives.
See [unbound-migration.md](unbound-migration.md) for the full compatibility table.

```bash
# To use your existing Unbound config instead of the default:
sudo cp /etc/unbound/unbound.conf /etc/runbound/runbound.conf
```

---

## Additional capabilities

**Per-subnet / per-VLAN filtering policies (#8)** — `POST /api/policies` blocks extra domains
(and their subdomains) for clients in one subnet/VLAN only, additive to the global
blacklist/feeds filter. Applied live, no restart. Merged into the WebUI **Subnets** tab
alongside split-horizon. See [api.md](api.md#subnet-policies-8).

Recursion and DNSSEC validation are entirely in-house (`src/dns/recursor_wire.rs`,
`src/dns/dnssec_*.rs`) and always compiled in (no Cargo feature gates them) — but OFF by
runtime default: `resolution: forward` and `dnssec-validation: no` are the defaults;
full-recursion and DNSSEC validation are opt-in via config (`resolution: full-recursion`,
`dnssec-validation: yes`), not a build flag. `hickory-proto` is used as a dev-dependency for
differential oracle tests.

Three opt-in capabilities (default-off, toggleable live via the API/WebUI):

**Sign your local zones with DNSSEC (#201)** — `local-zone-dnssec: yes`. Each zone gets an
auto-generated KSK+ZSK; publish the DS shown by `GET /api/dnssec/ds` at the parent. In HA the
master replicates the keys to its slaves. See [configuration.md](configuration.md).

**Become a sovereign recursive resolver (#202)** — `resolution: full-recursion` resolves
iteratively from the root instead of forwarding, so no upstream ever sees your queries (DNSSEC
enforced, anti-SSRF, QNAME-minimisation). Toggle live: `PUT /api/resolution {"mode":"full-recursion"}`.

**Serve encrypted DNS (DoT / DoH / DoQ)** — enable from the WebUI *Settings -> Encrypted DNS*
panel (generate a self-signed cert or import your own), or `POST /api/tls/self-signed`; applies
live — no restart needed to bind the listeners.

## 3. Run

```bash
# Foreground (test first):
sudo RUNBOUND_API_KEY="your-key" runbound /etc/runbound/runbound.conf

# Verify DNS is working:
dig @127.0.0.1 google.com

# Verify the API is reachable:
curl -s http://localhost:8080/api/system \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
# → {"version":"0.9.1","uptime_secs":3,...}
```

---

## 4. Install as a service (production)

If you used `install.sh` (Step 1), the systemd unit is already installed and the
`runbound` system user already exists. Just enable and start:

```bash
sudo systemctl enable --now runbound
sudo journalctl -u runbound -f   # watch logs
```

For manual installs or a custom hardened unit file, see [systemd.md](systemd.md).

---

## 5. First API calls

```bash
API="http://localhost:8080"
TOKEN="your-key"

# Add a local DNS entry
curl -s -X POST "$API/api/dns" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"myserver.home.","type":"A","value":"192.168.1.50","ttl":300}'

# Check it resolves
dig @127.0.0.1 myserver.home.

# View stats
curl -s "$API/api/stats" -H "Authorization: Bearer $TOKEN"

# View service info (version, uptime, XDP status)
curl -s "$API/api/system" -H "Authorization: Bearer $TOKEN"
```

That's all. For the full API reference see [api.md](api.md).

---

## Stop conflicting services first (if needed)

If port 53 is already taken:

```bash
# Check what's using port 53
sudo ss -tlnp | grep :53

# Common culprits
sudo systemctl stop unbound
sudo systemctl stop bind9
sudo systemctl stop dnsmasq
sudo systemctl disable systemd-resolved && sudo systemctl stop systemd-resolved
```

Then re-run the install command.

---

## Uninstall

```bash
curl -fsSL https://github.com/redlemonbe/Runbound/releases/latest/download/install.sh | sudo bash -s -- --uninstall
```

Your config and data in `/etc/runbound` and `/var/lib/runbound` are kept.

---

## Web management console

Runbound includes an embedded web UI with HTTPS. Enable it in the config:

```
server:
    ui-enabled: yes
    ui-port:    8091
```

Restart Runbound, then open `https://YOUR_SERVER_IP:8091`.

On first access your browser will warn about the self-signed certificate.  
**One-time fix:** download the Runbound CA at `https://YOUR_SERVER_IP:8091/webui/ca.crt`
and add it to your OS / browser trust store — no more warnings on any device on your network.

Enter your API key, click **Connect**.

Full setup guide: [web-ui.md](web-ui.md).

---

## Privacy defaults

By default Runbound keeps the last 1,000 queries (with client IPs redacted) in a RAM
ring buffer accessible via `GET /api/logs`. To change this:

```
server:
    log-retention: 0     # disable the ring buffer entirely
    log-client-ip: yes   # include real client IPs (for investigation)
```

See [gdpr.md](gdpr.md) for the full GDPR compliance guide.

---

## Master / Slave replication

To replicate state (blacklist, zones, feeds) from a master to one or more slaves,
see [sync.md](sync.md).

> **Quick reminder:** open TCP port 8082 on the master firewall — this is the
> most common reason slave synchronisation fails.
