# Documentation Index

Complete reference for Runbound. Each page covers the current stable release.. Each page is self-contained.

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
| [security-audit/v0.6.9-audit.md](security-audit/v0.6.9-audit.md) | v0.6.9 audit report — SEC and PERF findings, risk matrix, recommendations |
| [security-audit/v0.6.9-pentest.md](security-audit/v0.6.9-pentest.md) | Black-box pentest v0.6.9 — API + DNS protocol, findings SEC-11 + PERF-11 |
| [security-audit/v0.9.1-icmp-webui.md](security-audit/v0.9.1-icmp-webui.md) | v0.9.0–v0.9.1 audit — WebUI proxy and XDP ICMP handler (7 findings) |
| [security-audit/v0.9.3-prerelease.md](security-audit/v0.9.3-prerelease.md) | v0.9.3 pre-release audit — 6 new attack surfaces |
| [security-audit/v0.9.3-gemini.md](security-audit/v0.9.3-gemini.md) | v0.9.3 adversarial audit [AI-ADVERSARIAL] — Gemini 2.5 Pro cross-check |
| [security-audit/v0.9.4-remediation.md](security-audit/v0.9.4-remediation.md) | v0.9.4 remediation verification |
| [security-audit/v0.9.10-audit.md](security-audit/v0.9.10-audit.md) | v0.9.10 security audit — cycle A findings |
| [security-audit/v0.9.15-audit.md](security-audit/v0.9.15-audit.md) | v0.9.15 security audit — cycle B, 17 findings (SEC-B1–SEC-B17) |
| [security-audit/v0.9.15-perf-audit.md](security-audit/v0.9.15-perf-audit.md) | v0.9.15 performance audit — 8 findings toward 5M+ QPS target |
| [audit.md](audit.md) | Supply-chain audit — dependency scanning, cargo-deny, RUSTSEC cadence |
| [hsm.md](hsm.md) | HSM / PKCS#11 integration — hardware key storage, HMAC audit log |
| [gdpr.md](gdpr.md) | GDPR compliance guide — data inventory, `log-client-ip`, retention |

---

## Performance

| Page | What you will find |
|------|--------------------|
| [performance.md](performance.md) | Official benchmark — methodology, results, comparison with BIND9 and Unbound |
| [security-audit/v0.5.4-benchmark.md](security-audit/v0.5.4-benchmark.md) | Raw benchmark data v0.5.4 — all phases, all servers, full output |

---

## Project

| Page | What you will find |
|------|--------------------|
| [philosophy.md](philosophy.md) | Design rationale — why Rust, why XDP, how Runbound differs from legacy resolvers |
| [security-audit/v0.4.5-code-audit.md](security-audit/v0.4.5-code-audit.md) | v0.4.5 internal code quality audit — unsafe inventory, dependency rationale |
