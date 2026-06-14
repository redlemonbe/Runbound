# Runbound

## Unbound-compatible DNS server — XDP kernel-bypass fast path, live REST API, no restart

**Unbound-compatible DNS server — REST API, XDP kernel-bypass, no restart ever.**

[![CI](https://github.com/redlemonbe/Runbound/actions/workflows/ci.yml/badge.svg)](https://github.com/redlemonbe/Runbound/actions/workflows/ci.yml) [![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE) [![Commercial License](https://img.shields.io/badge/license-commercial-green.svg)](COMMERCIAL_LICENSE.md)
[![GitHub release](https://img.shields.io/github/v/release/redlemonbe/Runbound)](https://github.com/redlemonbe/Runbound/releases/latest)
[![cargo audit](https://img.shields.io/badge/cargo_audit-clean-brightgreen.svg)](docs/audit.md) [![GitHub Sponsors](https://img.shields.io/github/sponsors/redlemonbe?style=flat&logo=github&label=Sponsor)](https://github.com/sponsors/redlemonbe)

> ⚠️ **Status: Experimental** — Runbound is under active development and has not yet undergone external human security audit. Not yet recommended for production deployments handling sensitive traffic. See [METHODOLOGY.md](METHODOLOGY.md) for the development approach.

Most existing `unbound.conf` files work as-is. Non-standard or exotic directives are ignored gracefully — see [Unbound compatibility](docs/unbound-migration.md). Runbound adds a live REST API, AF_XDP kernel-bypass, and a browser dashboard on top.

> **Prior art.** DNS-over-XDP is not new — [Knot DNS](https://www.knot-dns.cz/) has had an authoritative XDP mode since 3.0 (2020), and the Knot project ships `kxdpgun`, an XDP DNS load generator. Runbound's contribution is the *combination*: a **drop-in Unbound-compatible resolver** with the XDP fast path on the cache/serve hot path, a **live REST API** (change config with no restart), and a **single static musl binary** — not XDP on its own.

---

## What you get

| | BIND9 | Unbound | Runbound |
|---|:---:|:---:|:---:|
| Drop-in Unbound config | ❌ | ✅ | ✅ |
| UDP / TCP / DoT / DoH | ✅ | ✅ | ✅ |
| Add / block domains live | ⚠️ | ⚠️ unbound-control | ✅ REST API |
| Block-list feed subscriptions | ⚠️ | ❌ manual | ✅ API |
| Real-time stats + Prometheus | ✅ statistics channel (XML/JSON) | ⚠️ unbound-control / exporter | ✅ |
| Master/slave replication | ✅ | ❌ | ✅ built-in*¹ |
| Automatic TLS (Let's Encrypt) | ❌ | ❌ | ✅ ACME |
| Anycast deployment (built-in BGP announcer) | ❌ | ❌ | ✅ v0.19.0 |
| AF/XDP kernel-bypass fast path | ❌ | ❌ | ✅ |
| XDP ICMP echo responder (rate-limited) | ❌ | ❌ | ✅ |
| Embedded browser dashboard | ❌ | ❌ | ✅ no nginx needed |
| Static binary, no dependencies | ❌ | ❌ | ✅ musl |
| Split-horizon DNS (per-subnet answers) | ❌ | ⚠️ views | ✅ v0.9.63 |
| RBAC (read/dns/operator/admin roles) | ❌ | ❌ | ✅ v0.9.62 |
| Webhook notifications (Slack/Discord/ntfy) | ❌ | ❌ | ✅ v0.9.58 |
| Multi-user API with zone isolation | ❌ | ❌ | ✅ v0.9.51 |
| White-label UI branding | ❌ | ❌ | ✅ v0.9.61 |
| Hot backup / restore | ❌ | ❌ | ✅ API |

*¹ Runbound ships both REST API-driven replication and standard AXFR/IXFR zone transfers (RFC 5936, v0.9.13+). AXFR requires explicit ACL configuration — see [docs/configuration.md](docs/configuration.md).

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
curl -fsSL https://raw.githubusercontent.com/redlemonbe/Runbound/main/install.sh | sudo bash
```

That's it. The script:
1. Downloads the latest binary for your architecture
2. Creates a `runbound` system user
3. Writes a default config to `/etc/runbound/runbound.conf`
4. Generates a random API key in `/etc/runbound/env`
5. Installs and starts the systemd service

See **[docs/INSTALL.md](docs/INSTALL.md)** for every option (`--uninstall`, `--purge`, `--help`), integrity verification (SHA256 + minisign), file locations and troubleshooting.

At the end you'll see:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Version:  runbound <version>
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
# Remove Runbound, keep your config and data
curl -fsSL https://raw.githubusercontent.com/redlemonbe/Runbound/main/install.sh | sudo bash -s -- --uninstall

# Remove everything: config, data, and the runbound user/group
curl -fsSL https://raw.githubusercontent.com/redlemonbe/Runbound/main/install.sh | sudo bash -s -- --purge
```

`--uninstall` keeps your config and data in `/etc/runbound` and `/var/lib/runbound`; `--purge` deletes them (and the `runbound` system user/group) as well.

---

## Dashboard (Web UI)

Runbound embeds the dashboard — no nginx needed. Enable it in your config:

```
server:
    ui-enabled: yes
    ui-port:    8091
```

Restart the service, then open `https://YOUR_SERVER_IP:8091`.

On first access your browser will warn about the self-signed certificate. Download the Runbound CA at `https://YOUR_SERVER_IP:8091/webui/ca.crt` and install it once — no more warnings on any device on your network.

Enter your API key and click **Connect**. Full setup guide: [docs/web-ui.md](docs/web-ui.md).

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

Benchmarked under a documented, reproducible methodology — **the truth is the receiver
NIC hardware counters** (`tx_packets`), warm cache, governor pinned, flow-control off,
never the generator's self-report. Full per-run reports: [docs/benchmark/](docs/benchmark/).
Rig (2026-06-13): AMD Threadripper PRO 5995WX receiver, dual Xeon E5-2690 v2 generator
(dnsmark), direct 10 GbE DACs (Intel X710/i40e + X510/ixgbe).

| Runbound v0.18.1 | Served (receiver NIC) | Receiver CPU | Limited by |
|---|---|---|---|
| `xdp: yes` — **dual-link** (X510 + X710) | **~20.28 M qps** | ~24 % | the two 10 G links — **server not saturated** |
| `xdp: yes` — single link (X710) | ~10.1 M qps | ~11 % | 10 G link (response direction) |
| `xdp: no` — kernel slow path (X710) | ~3.71 M qps | ~19 % | kernel-UDP RX + generator |

These figures are **cache-hit / hot-path throughput** (answers served from cache or local
zones over the XDP fast path), not recursion under cache miss — a different workload. In no run
did Runbound reach its own CPU ceiling (≤24 %); the limit is always the link, the NIC RX path,
or the generator. Same-rig kernel-UDP reference resolvers, same cache-hit workload: **unbound
1.22.0 ~2.09 M**, **BIND 9.20.23 ~1.84 M** — both excellent and both bounded by the kernel
socket path here, not their own code (see the [diplomacy of the comparison](docs/benchmark/INDEX.md)).
Runbound's slow path is ~2× and its fast path ~5–6× on the same rig, at lower CPU and lower
latency. Latency, the generator-bound dual-X710 run, and full context:
[docs/benchmark/INDEX.md](docs/benchmark/INDEX.md).

The fast path is **self-configuring**: AF_XDP ring sizes are derived from the NIC
hardware, huge pages are self-provisioned, and NIC queues scale to the CPU
automatically (kept at the driver default on bus-bound Xeon v2 + X520). It is **designed for
linear scaling** — `SO_REUSEPORT`, lock-free config hot-swap (`ArcSwap`), per-core affinity, and
SSE4.2 `CRC32c` + SIMD on the lookup path — though core scaling beyond the 2×10G link ceiling is
not yet demonstrated (every run so far is link-bound at ≤24 % CPU).

## AF/XDP Fast Path

An eBPF XDP program attaches to the NIC at startup. UDP/53 packets for local zones and cache hits are answered in user space at driver level — zero syscalls on the hot path. All other queries pass through to the normal resolver via `XDP_PASS`.

Negative answers (`NODATA` / `NXDOMAIN`) are cached on the fast path too (RFC 2308). AF_XDP ring sizes, huge pages, and NIC queue counts are **configured automatically** at startup — see [docs/xdp.md](docs/xdp.md).

```bash
# Verify XDP is active
journalctl -u runbound | grep XDP
```

Disable without editing config: `RUNBOUND_DISABLE_XDP=1` — useful if the host becomes unreachable after an XDP attach. Details: [docs/xdp.md](docs/xdp.md).

---

## Documentation

Full index: **[docs/index.md](docs/index.md)**

Quick links: [Quick Start](docs/quick-start.md) · [Configuration](docs/configuration.md) · [REST API](docs/api.md) · [XDP](docs/xdp.md) · [Internals](docs/internals.md) · [Systemd](docs/systemd.md) · [Security Audit](docs/security-audit/SECURITY-AUDIT.md) · [Building & Verifying](docs/BUILD.md) · [Security Policy](SECURITY.md) · [Threat Model](THREAT_MODEL.md)

---

## Contributing

CI (`.github/workflows/ci.yml`) runs on every push to `main` and every pull request — build, clippy and tests must all be green:

```bash
cargo build --release                       # xdp is in the default feature set
cargo clippy --all-targets -- -D warnings   # must be warning-free
cargo test                                  # all tests must pass
```

Pull requests welcome. By submitting a PR you agree to the [CLA](CLA.md).

---

*Not affiliated with the NLnet Labs Unbound project.*

---

## Support the project

[![GitHub Sponsors](https://img.shields.io/github/sponsors/redlemonbe?style=flat&logo=github&label=Sponsor%20on%20GitHub)](https://github.com/sponsors/redlemonbe)

**Bitcoin** — `3FP8hkkiu4kwCD1PDFgAv2oq1ZTyXwy3yy`  
**Ethereum** — `0xB5eEAf89edA4204Aa9305B068b37A93439cBb680`

---

## License

AGPL v3 — see [LICENSE](LICENSE). Commercial license available for organizations that need to deploy without AGPL obligations: [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md).
