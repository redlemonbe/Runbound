# Runbound

**Drop-in Unbound replacement — with a REST API and 80,000 q/s.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE) [![Commercial License](https://img.shields.io/badge/license-commercial-green.svg)](COMMERCIAL_LICENSE.md)
[![GitHub release](https://img.shields.io/github/v/release/redlemonbe/Runbound)](https://github.com/redlemonbe/Runbound/releases/latest)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/redlemonbe?style=flat&logo=github&label=Sponsor)](https://github.com/sponsors/redlemonbe)

---

You run Unbound. It works. But every time you need to add a DNS entry, block a domain, or subscribe to a block list, you edit a config file, reload the daemon, and hope nothing breaks.

**Runbound does the same job — and lets you manage everything via a REST API, live, without restart.**

Your existing `unbound.conf` works as-is. Zero migration.

---

## What you get

| | BIND9 | Unbound | Runbound |
|---|:---:|:---:|:---:|
| Drop-in Unbound config | ❌ | ✅ | ✅ |
| UDP / TCP / DoT / DoH | ✅ | ✅ | ✅ |
| Add a DNS entry live | ⚠️ nsupdate | ❌ restart | ✅ API |
| Block a domain live | ⚠️ RPZ | ❌ restart | ✅ API |
| Subscribe to block-list feeds | ⚠️ RPZ/manual | ❌ manual | ✅ API |
| Real-time query statistics | ⚠️ XML/JSON channel | ❌ | ✅ API |
| Live query log | ⚠️ via rndc | ❌ | ✅ API |
| SSE live stats stream | ❌ | ❌ | ✅ API |
| Upstream health monitoring | ❌ | ❌ | ✅ API |
| Master/slave replication | ✅ AXFR/IXFR | ❌ | ✅ built-in |
| Automatic TLS (Let's Encrypt) | ❌ external | ❌ external | ✅ built-in ACME |
| Tamper-evident audit log | ❌ | ❌ | ✅ HMAC-SHA256 chain |
| Prometheus metrics | ⚠️ XML/JSON channel | ❌ | ✅ `/metrics` OpenMetrics |
| API key rotation (no restart) | ❌ | ❌ | ✅ `POST /rotate-key` |
| Hot config reload | ✅ rndc reload | ❌ | ✅ API |
| AF/XDP kernel-bypass fast path | ❌ | ❌ | ✅ optional |
| Static binary (no dependencies) | ❌ | ❌ | ✅ musl builds |
| Throughput (recursive) | ~40k q/s | ~50k q/s | **~80k q/s** |

---

## Up and running in 60 seconds

```bash
# 1 — Download the static binary (no dependencies)
#     Replace vX.Y.Z with the latest version tag from the releases page
curl -LO https://github.com/redlemonbe/Runbound/releases/latest/download/runbound-v0.4.3-x86_64-linux-musl
chmod +x runbound-v0.4.3-x86_64-linux-musl

# 2 — One-liner install (downloads automatically, sets up systemd):
#     sudo bash <(curl -fsSL https://github.com/redlemonbe/Runbound/releases/latest/download/install.sh)

# 3 — Or point it at your existing Unbound config
sudo ./runbound-v0.4.3-x86_64-linux-musl /etc/unbound/unbound.conf

# 4 — Test it
dig @127.0.0.1 google.com
```

DNS live on **port 53**. REST API live on **port 8081** (localhost only, requires Bearer token). No config change needed.

The REST API port is configurable with `api-port: 9090` in `runbound.conf`. See the [Configuration Reference](docs/configuration.md#api-key-and-port).

> Raspberry Pi or ARM server? Grab `runbound-v0.4.3-aarch64-linux-musl` instead.

---

## Manage DNS without touching a file

```bash
API="http://localhost:8081"
TOKEN="your-api-key"

# Add a DNS entry — live, no restart
curl -s -X POST "$API/dns" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"nas.home.","type":"A","value":"192.168.1.10","ttl":300}'

# Block a domain — live
curl -s -X POST "$API/blacklist" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"ads.example.com"}'

# Subscribe to URLhaus malware feed — auto-refreshed
curl -s -X POST "$API/feeds" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"urlhaus","url":"https://urlhaus.abuse.ch/downloads/hostfile/"}'

# Live query stats
curl -s "$API/stats" -H "Authorization: Bearer $TOKEN"
```

---

## Performance

Measured on a 4-core VPS (KVM, 8 GB RAM) with [dnsperf](https://www.dns-oarc.net/tools/dnsperf):

| Scenario | Throughput | Avg latency |
|---|---|---|
| Local zone — 1 client | **82,000 q/s** | 83 ms |
| Local zone — 8 clients | **75,000 q/s** | ~1 s (server saturated) |
| Forwarding (Cloudflare) | network-bound | < 5 ms |
| AF/XDP (bare metal, DRV mode) | **500k – 1M+ q/s** | < 1 ms |

→ Full methodology and raw results: [docs/performance.md](docs/performance.md)

---

## Downloads

| Platform | Build | Asset name |
|---|---|---|
| Linux x86_64 | static (musl) — no deps | `runbound-vX.Y.Z-x86_64-linux-musl` |
| Linux x86_64 | dynamic (glibc) | `runbound-vX.Y.Z-x86_64-linux-gnu` |
| Linux ARM64 | static (musl) — Raspberry Pi, servers | `runbound-vX.Y.Z-aarch64-linux-musl` |
| Linux ARM64 | dynamic (glibc) | `runbound-vX.Y.Z-aarch64-linux-gnu` |

All releases: [github.com/redlemonbe/Runbound/releases](https://github.com/redlemonbe/Runbound/releases)

Or build from source: `cargo build --release`  
With AF/XDP fast path: `cargo build --release --features xdp`

---

## Example configurations

Ready-to-use configs for common scenarios:

| Config | Use case |
|---|---|
| [examples/home.conf](examples/home.conf) | Raspberry Pi / home lab — replaces Pi-hole |
| [examples/office.conf](examples/office.conf) | SMB office — split-horizon DNS, VPN, corporate zone |
| [examples/server.conf](examples/server.conf) | Public recursive resolver — VPS / datacenter |
| [examples/secure.conf](examples/secure.conf) | Air-gapped / military-grade — strict ACL, no public forwarding |
| [examples/master.conf](examples/master.conf) | Master node — writes + replication to slaves |
| [examples/slave.conf](examples/slave.conf) | Slave replica — read-only, TOFU TLS, auto delta sync |

**Integration example:**

| Script | What it does |
|---|---|
| [examples/postgres_collector.py](examples/postgres_collector.py) | Polls `/stats` + `/logs` and inserts into PostgreSQL — reference for "how do I store DNS data in my own DB?" |

---

## Documentation

| | |
|---|---|
| [Home Lab Guide](docs/homelab.md) | Raspberry Pi / home server setup — local names, ad blocking, router config |
| [Quick Start](docs/quick-start.md) | Install, configure, run in 5 minutes |
| [Configuration Reference](docs/configuration.md) | Every directive explained, slave/master sync, Unbound compatibility table |
| [REST API Reference](docs/api.md) | All endpoints with curl examples and JSON responses |
| [High Availability](docs/ha.md) | Master/slave replication, VRRP failover, multi-node setup |
| [Performance Guide](docs/performance.md) | Benchmarks, methodology, how to reproduce |
| [TLS Setup](docs/tls.md) | DoT on port 853 — Let's Encrypt, ACME auto-provisioning, internal CA |
| [AF/XDP Fast Path](docs/xdp.md) | Kernel-bypass networking — 500k+ q/s |
| [Systemd Setup](docs/systemd.md) | Production service, hardened unit file, hot reload |
| [Unbound Migration](docs/unbound-migration.md) | Config compatibility, feature mapping, gotchas |
| [Security Architecture](docs/security.md) | ACL, rate limiting, API auth, audit findings |
| [Security Audit](docs/security-audit.md) | White-box audit findings and remediation log |
| [GDPR / Privacy](docs/gdpr.md) | Data inventory, log retention, IP redaction, right-to-erasure |

---

## Contributing

Pull requests welcome. By submitting a pull request you agree to the [Contributor License Agreement](CLA.md).

1. `cargo clippy --all-targets --features xdp` — zero warnings required
2. `cargo test` — all tests must pass
3. Security fixes: document with a `VUL-NN` tag

---

## Support the project

If Runbound saves you time or infrastructure costs:

[![GitHub Sponsors](https://img.shields.io/github/sponsors/redlemonbe?style=flat&logo=github&label=Sponsor%20on%20GitHub)](https://github.com/sponsors/redlemonbe)

**Bitcoin** — `3FP8hkkiu4kwCD1PDFgAv2oq1ZTyXwy3yy`  
**Ethereum** — `0xB5eEAf89edA4204Aa9305B068b37A93439cBb680`

---

## License

Runbound is open source under the [GNU AGPL v3](LICENSE).

**What this means:** if you use Runbound as part of a commercial service,
you must publish your modifications under the same license.

**Commercial license:** organizations that need to use Runbound without
AGPL obligations can purchase a commercial license with priority support.
See [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md).

Copyright (C) 2024-2026 RedLemonBe

---

## Development methodology

Runbound's security posture is reinforced using AI-assisted tooling at every release:

- **Security audit** — white-box code review covering SSRF, injection, timing attacks, DoS vectors, and RFC compliance (see [`docs/security-audit.md`](docs/security-audit.md))
- **Pentest** — black-box API and DNS protocol testing (input validation, amplification, information disclosure, authentication bypass)
- **Performance analysis** — hot-path profiling and allocation review

AI tools are used exclusively as an adversarial review layer. All findings are triaged and patched by the maintainer.

---

*Runbound is not affiliated with the NLnet Labs Unbound project.*
