# Runbound

**Drop-in Unbound replacement — with a REST API and 80,000 q/s.**

[![License: PolyForm NC](https://img.shields.io/badge/License-PolyForm_NC_1.0-blue)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/redlemonbe/Runbound)](https://github.com/redlemonbe/Runbound/releases/latest)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/redlemonbe?style=flat&logo=github&label=Sponsor)](https://github.com/sponsors/redlemonbe)

---

You run Unbound. It works. But every time you need to add a DNS entry, block a domain, or subscribe to a block list, you edit a config file, reload the daemon, and hope nothing breaks.

**Runbound does the same job — and lets you manage everything via a REST API, live, without restart.**

Your existing `unbound.conf` works as-is. Zero migration.

---

## What you get

| | Unbound | Runbound |
|---|:---:|:---:|
| Drop-in config compatibility | ✅ | ✅ |
| UDP / TCP / DoT / DoH | ✅ | ✅ |
| Add a DNS entry live | ❌ restart | ✅ API |
| Block a domain live | ❌ restart | ✅ API |
| Subscribe to block-list feeds | ❌ manual | ✅ API |
| Real-time query statistics | ❌ | ✅ API |
| Hot config reload | ❌ | ✅ API |
| AF/XDP kernel-bypass fast path | ❌ | ✅ optional |
| Static binary (no dependencies) | ❌ | ✅ musl builds |
| Throughput (local zone) | ~50k q/s | **~80k q/s** |

---

## Up and running in 60 seconds

```bash
# 1 — Download the static binary (no dependencies)
curl -LO https://github.com/redlemonbe/Runbound/releases/latest/download/runbound-x86_64-linux-musl
chmod +x runbound-x86_64-linux-musl

# 2 — Point it at your existing Unbound config (or use an example)
sudo ./runbound-x86_64-linux-musl --config /etc/unbound/unbound.conf

# 3 — Test it
dig @127.0.0.1 google.com
```

DNS live on **port 53**. REST API live on **port 8081**. No config change needed.

> Raspberry Pi or ARM server? Grab `runbound-aarch64-linux-musl` instead.

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

| Platform | Build | Download |
|---|---|---|
| Linux x86_64 | static (musl) — no deps | [runbound-x86_64-linux-musl](https://github.com/redlemonbe/Runbound/releases/latest) |
| Linux x86_64 | dynamic (glibc) | [runbound-x86_64-linux-gnu](https://github.com/redlemonbe/Runbound/releases/latest) |
| Linux ARM64 | static (musl) — Raspberry Pi, servers | [runbound-aarch64-linux-musl](https://github.com/redlemonbe/Runbound/releases/latest) |
| Linux ARM64 | dynamic (glibc) | [runbound-aarch64-linux-gnu](https://github.com/redlemonbe/Runbound/releases/latest) |

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

---

## Documentation

| | |
|---|---|
| [Quick Start](docs/quick-start.md) | Install, configure, run in 5 minutes |
| [Configuration Reference](docs/configuration.md) | Every directive explained, Unbound compatibility table |
| [REST API Reference](docs/api.md) | All 14 endpoints with curl examples and JSON responses |
| [Performance Guide](docs/performance.md) | Benchmarks, methodology, how to reproduce |
| [TLS Setup](docs/tls.md) | DoT on port 853 — Let's Encrypt or internal CA |
| [AF/XDP Fast Path](docs/xdp.md) | Kernel-bypass networking — 500k+ q/s |
| [Systemd Setup](docs/systemd.md) | Production service, hardened unit file |
| [Unbound Migration](docs/unbound-migration.md) | Config compatibility, feature mapping, gotchas |
| [Security Architecture](docs/security.md) | ACL, rate limiting, API auth, audit findings |

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

[PolyForm Noncommercial License 1.0.0](LICENSE) for non-commercial use.  
Commercial use: [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) — contact redlemonbe@codix.be.

Copyright (c) 2026 RedlemonBe

---

*Runbound is not affiliated with the NLnet Labs Unbound project.*
