# Runbound

**Drop-in Unbound replacement — REST API, XDP kernel-bypass, no restart ever.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE) [![Commercial License](https://img.shields.io/badge/license-commercial-green.svg)](COMMERCIAL_LICENSE.md)
[![GitHub release](https://img.shields.io/github/v/release/redlemonbe/Runbound)](https://github.com/redlemonbe/Runbound/releases/latest)
[![cargo audit](https://img.shields.io/badge/cargo_audit-clean-brightgreen.svg)](docs/audit.md) [![GitHub Sponsors](https://img.shields.io/github/sponsors/redlemonbe?style=flat&logo=github&label=Sponsor)](https://github.com/sponsors/redlemonbe)

Your existing `unbound.conf` works as-is. Runbound adds a live REST API, AF_XDP kernel-bypass, and a browser dashboard on top — without changing anything in your DNS setup.

---

## What you get

| | BIND9 | Unbound | Runbound |
|---|:---:|:---:|:---:|
| Drop-in Unbound config | ❌ | ✅ | ✅ |
| UDP / TCP / DoT / DoH | ✅ | ✅ | ✅ |
| Add / block domains live | ⚠️ | ❌ restart | ✅ API |
| Block-list feed subscriptions | ⚠️ | ❌ manual | ✅ API |
| Real-time stats + Prometheus | ⚠️ | ❌ | ✅ |
| Master/slave replication | ✅ | ❌ | ✅ built-in |
| Automatic TLS (Let's Encrypt) | ❌ | ❌ | ✅ ACME |
| AF/XDP kernel-bypass fast path | ❌ | ❌ | ✅ |
| Linear scaling (no lock contention) | ❌ | ❌ | ✅ |
| Static binary, no dependencies | ❌ | ❌ | ✅ musl |

---

## Install

### Requirements

- Linux x86\_64 or arm64
- systemd
- Port 53 available (stop `unbound`, `bind9`, `dnsmasq` or `systemd-resolved` first if running)
- `curl` or `wget`
- Root access (`sudo`)

### One-line install

```bash
curl -fsSL https://github.com/redlemonbe/Runbound/releases/latest/download/install.sh | sudo bash
```

That's it. The script:
1. Downloads the latest binary for your architecture
2. Creates a `runbound` system user
3. Writes a default config to `/etc/runbound/runbound.conf`
4. Generates a random API key in `/etc/runbound/env`
5. Installs and starts the systemd service

At the end you'll see:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Version:  runbound 0.6.x
 API key:  a1b2c3d4...   ← save this
 Config:   /etc/runbound/runbound.conf
 Logs:     journalctl -u runbound -f
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Save the API key** — you'll need it to use the dashboard and the REST API.

### Verify it works

```bash
# DNS is responding
dig @127.0.0.1 google.com

# Service status
sudo systemctl status runbound

# API is up
curl -s http://127.0.0.1:8080/api/stats \
  -H "Authorization: Bearer YOUR_API_KEY" | python3 -m json.tool
```

### Stop conflicting services first (if needed)

If port 53 is already taken:

```bash
# Check what's using port 53
sudo ss -tlnp | grep :53

# Common culprits
sudo systemctl stop unbound        # Unbound
sudo systemctl stop bind9          # BIND9
sudo systemctl stop dnsmasq        # dnsmasq
sudo systemctl disable systemd-resolved && sudo systemctl stop systemd-resolved  # systemd-resolved
```

Then re-run the install command.

### Uninstall

```bash
curl -fsSL https://github.com/redlemonbe/Runbound/releases/latest/download/install.sh | sudo bash -s -- --uninstall
```

Your config and data in `/etc/runbound` and `/var/lib/runbound` are kept.

---

## Dashboard (Web UI)

Runbound ships with a browser dashboard. To serve it, install nginx:

```bash
sudo apt install nginx

# Create the site config
sudo tee /etc/nginx/sites-enabled/runbound-ui << 'EOF'
server {
    listen 8090;
    server_name _;
    root /var/www/runbound-ui;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }

    location /api/ {
        proxy_pass         http://127.0.0.1:8080;
        proxy_http_version 1.0;
        proxy_set_header   Host $host;
        proxy_read_timeout 30s;
    }
}
EOF

sudo systemctl reload nginx
```

Open `http://YOUR_SERVER_IP:8090` in your browser, enter your API key, click **Connect**.

---

## Manage DNS without touching a file

```bash
TOKEN="your-api-key"

# Add a local DNS entry — live, no restart
curl -s -X POST http://localhost:8080/api/dns \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"nas.home.","type":"A","value":"192.168.1.10","ttl":300}'

# Block a domain
curl -s -X POST http://localhost:8080/api/blacklist \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"ads.example.com"}'

# Subscribe to a block-list feed (auto-refreshed)
curl -s -X POST http://localhost:8080/api/feeds \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"urlhaus","url":"https://urlhaus.abuse.ch/downloads/hostfile/"}'
```

---

## Performance

| Hardware | Mode | QPS |
|----------|------|-----|
| Any CPU | SO_REUSEPORT (no XDP) | scales linearly with cores |
| Intel 10 GbE ixgbe | AF_XDP native zero-copy | up to wire speed (~14 M pps) |

Unlike BIND9 and Unbound, Runbound uses `SO_REUSEPORT` with one socket per physical core and lock-free zone reads via `ArcSwap`. Throughput scales linearly — no shared-lock plateau.

XDP hot path latency: **~1 µs** per query (local zone or cache hit). Full timing breakdown: [docs/internals.md](docs/internals.md).

---

## AF/XDP Fast Path

> **Commercial license required** to activate at runtime. Open-source (AGPL v3) builds include the code — the fast path is disabled without a commercial license.

An eBPF XDP program attaches to the NIC at startup. UDP/53 packets for local zones and cache hits are answered in user space at driver level — zero syscalls on the hot path. All other queries pass through to the normal resolver via `XDP_PASS`.

```bash
# Verify XDP is active
journalctl -u runbound | grep XDP
```

Disable without editing config: `RUNBOUND_DISABLE_XDP=1` — useful if the host becomes unreachable after an XDP attach. Details: [docs/xdp.md](docs/xdp.md).

---

## Documentation

Full index: **[docs/index.md](docs/index.md)**

Quick links: [Quick Start](docs/quick-start.md) · [Configuration](docs/configuration.md) · [REST API](docs/api.md) · [XDP](docs/xdp.md) · [Internals](docs/internals.md) · [Systemd](docs/systemd.md) · [Security Audit](docs/security-audit.md)

---

## Contributing

```bash
cargo clippy --all-targets --features xdp   # zero warnings
cargo test                                   # all tests must pass
```

Pull requests welcome. By submitting a PR you agree to the [CLA](CLA.md).

---

## Support the project

[![GitHub Sponsors](https://img.shields.io/github/sponsors/redlemonbe?style=flat&logo=github&label=Sponsor%20on%20GitHub)](https://github.com/sponsors/redlemonbe)

**Bitcoin** — `3FP8hkkiu4kwCD1PDFgAv2oq1ZTyXwy3yy`  
**Ethereum** — `0xB5eEAf89edA4204Aa9305B068b37A93439cBb680`

---

## License

AGPL v3 — see [LICENSE](LICENSE). Commercial license available for organizations that need to deploy without AGPL obligations: [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md).

---

*Not affiliated with the NLnet Labs Unbound project.*
