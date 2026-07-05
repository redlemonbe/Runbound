# Changelog

All notable changes to Runbound are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [0.9.0]

Consolidated baseline for the 0.9 line. Runbound is a drop-in Unbound-compatible DNS
server with an XDP kernel-bypass fast path, a live REST API and an embedded dashboard —
everything built in, single static binary, no plugins. This entry synthesises the current
feature set.

### Resolution
- Drop-in Unbound config parsing (`unbound.conf`-style syntax; exotic directives ignored gracefully).
- Forwarding resolver — DoT-capable upstreams, query racing, per-upstream health probes.
- Sovereign full recursion — iterative from the root, opt-in; no third-party resolver sees your queries.
- Split-horizon DNS (per-subnet answers).
- serve-stale (RFC 8767) — answer from expired cache while refreshing in the background.

### Security & DNSSEC
- DNSSEC validation under full recursion (Bogus → SERVFAIL, AD bit).
- Authoritative DNSSEC signing — online, zero-touch: per-zone KSK+ZSK (ECDSAP256), NSEC3 denial, DS surfaced via API.
- Encrypted DNS server — DoT (853), DoH (443, RFC 8484 GET+POST), DoQ (853); local downloadable CA or bring-your-own, live with no restart.
- Automatic TLS via built-in ACME / Let's Encrypt.
- DDoS abuse engine — per-client rate-limit + tarpit + bans, escalation gated to verified sources (anti-spoof); bans dropped at the XDP/kernel layer on both datapaths.
- RBAC API roles (read / dns / operator / admin).
- Privacy by default — client-IP redaction, configurable retention (GDPR).
- Tamper-evident audit log — HMAC-chained, actor-attributed, SIEM-ready JSON, searchable in the WebUI.
- Signed releases — minisign signatures + CycloneDX SBOM shipped with every release. Signing public key `RWR8qoSBp5QDO/+vJox3/sHX1RIp4y1ifIVWb5nSKD//Po+exCOWPZ0B` (see `docs/BUILD.md`).

### Performance — XDP fast path
- AF_XDP kernel-bypass, zero-syscall hot path (~9.85 M qps single-link, ~20.3 M qps dual-link on Intel X710).
- SIMD / ASM wire responder shared by the fast and slow paths.
- Multi-NIC with IRQ/CPU auto-pinning, governor control, ring auto-sizing.
- XDP ICMP echo responder (rate-limited, auto-ban).
- Static musl binary — no runtime dependencies.

### Management & operations
- Live REST API — add/block domains, zones and config with no restart.
- Embedded browser dashboard (no nginx needed).
- Block-list feed subscriptions managed via the API.
- Real-time stats — Prometheus `/metrics` (queries, cache, XDP, DDoS/abuse, upstreams) + SSE stream.
- Master/slave replication — REST relay (HMAC + TLS-pinned) and AXFR/IXFR (RFC 5936).
- Anycast deployment — BGP announcement via a supervised `exabgp` process, health-driven route withdrawal.
- Multi-user API with per-user zone isolation.
- Webhook notifications (Slack / Discord / ntfy).
- Hot backup / restore via the API.
- White-label UI branding — name, logo, accent colour, favicon via `branding.conf`.

> ⚠️ **Experimental** — under active development, not yet externally audited; not recommended for production deployments handling sensitive traffic.
