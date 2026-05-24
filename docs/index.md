# Documentation Index

Complete reference for Runbound v0.9.2+. Each page is self-contained.

---

## Start here

| Page | What you will find |
|------|--------------------|
| [quick-start.md](quick-start.md) | Install, configure, and run Runbound in under 10 minutes |
| [unbound-migration.md](unbound-migration.md) | Drop-in migration from an existing Unbound deployment |
| [configuration.md](configuration.md) | Every directive in `runbound.conf`, with defaults and examples |

---

## Operations

| Page | What you will find |
|------|--------------------|
| [systemd.md](systemd.md) | Production systemd unit — capabilities, hardening, signal handling, log rotation |
| [web-ui.md](web-ui.md) | Browser dashboard setup (nginx reverse proxy, API key, troubleshooting) |
| [tls.md](tls.md) | DoT / DoH / DoQ certificate configuration, Let's Encrypt ACME |
| [troubleshooting.md](troubleshooting.md) | Symptoms, causes, and fixes for common deployment issues |

---

## Networking & architecture

| Page | What you will find |
|------|--------------------|
| [xdp.md](xdp.md) | XDP fast path — how it works, NIC requirements, ring auto-sizing, expected QPS |
| [internals.md](internals.md) | **Expert** — packet lifecycle, timing budget, implemented optimisations, roadmap |
| [ha.md](ha.md) | High-availability topologies — active/passive, anycast-ready |
| [sync.md](sync.md) | Master/slave replication — protocol, zone sync, slave health |
| [proxmox.md](proxmox.md) | Proxmox / bare-metal deployment with bridge and vmbr NICs |
| [homelab.md](homelab.md) | Homelab setup — single server, LAN-only, ad-blocking |

---

## API & integrations

| Page | What you will find |
|------|--------------------|
| [api.md](api.md) | Complete REST API reference — every endpoint, field, and error code |

---

## Security

| Page | What you will find |
|------|--------------------|
| [security.md](security.md) | Security features — ACL, rate limiting, DNS rebinding, DNSSEC, CHAOS class |
| [hardening.md](hardening.md) | systemd hardening deep-dive — every directive explained, what breaks if missing |
| [security-audit.md](security-audit.md) | v0.6.9 audit report — SEC and PERF findings, risk matrix, recommendations |
| [security-audit/v0.9-icmp-webui.md](security-audit/v0.9-icmp-webui.md) | v0.9 audit — WebUI proxy and XDP ICMP handler (7 findings, 3 fixed in v0.9.2) |
| [pentest-2026-05-23.md](pentest-2026-05-23.md) | Black-box pentest v0.6.9 — API + DNS protocol, findings SEC-11 + PERF-11 |
| [audit.md](audit.md) | Supply-chain audit — dependency scanning, cargo-deny, RUSTSEC cadence |
| [hsm.md](hsm.md) | HSM / PKCS#11 integration — hardware key storage, HMAC audit log |
| [gdpr.md](gdpr.md) | GDPR compliance guide — data inventory, `log-client-ip`, retention |

---

## Performance

| Page | What you will find |
|------|--------------------|
| [performance.md](performance.md) | Official benchmark — methodology, results, comparison with BIND9 and Unbound |
| [benchmark-2026-05-20.md](benchmark-2026-05-20.md) | Raw benchmark data — all phases, all servers, full output |

---

## Project

| Page | What you will find |
|------|--------------------|
| [philosophy.md](philosophy.md) | Design rationale — why Rust, why XDP, how Runbound differs from legacy resolvers |
| [code-audit.md](code-audit.md) | Internal code quality audit — unsafe inventory, dependency rationale |
