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

```bash
sudo bash <(curl -fsSL https://github.com/redlemonbe/Runbound/releases/latest/download/install.sh)
```

Or download a binary directly from the [releases page](https://github.com/redlemonbe/Runbound/releases/latest).

```bash
# Test against your existing Unbound config
sudo ./runbound /etc/unbound/unbound.conf
dig @127.0.0.1 google.com
```

---

## Manage DNS without touching a file

```bash
TOKEN="your-api-key"

# Add a DNS entry — live, no restart
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

A browser dashboard is included — see [docs/web-ui.md](docs/web-ui.md).

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
# INFO runbound: XDP kernel-bypass fast path active iface=eth0
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
