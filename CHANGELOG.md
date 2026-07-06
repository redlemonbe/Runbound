# Changelog

All notable changes to Runbound are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [0.9.1]

### Added
- **#228** — IPv6 bans are now enforced at the XDP fast path. A new `icmp_banned_v6`
  BPF map (16-byte key) plus gated lookups on the main and VLAN-tagged IPv6
  datapaths drop banned IPv6 sources at kernel-bypass speed, not just in the
  userspace slow path. The IPv4 ban path is unchanged.
- Unbound `include:` / `include-toplevel:` directives are now honoured (with glob
  support), so a split configuration — e.g. Debian's
  `include: "/etc/unbound/unbound.conf.d/*.conf"` — loads correctly instead of being
  silently dropped. Guard-railed: bounded nesting depth (8), file count (256) and
  cumulative size (16 MiB), glob only in the final path component, and refusal to
  escape the config file's directory.

### Fixed
- **#229** — "Top Domains" stayed empty at low QPS: per-domain counters sat in
  thread-local buffers because the only flush trigger was count-based (every 512
  calls), which never fires at residential/LAN rates. Added a time-based flush
  (≤ 1 s) so the dashboard converges at any QPS; the multi-MQPS path is unchanged.
- **#230** — The validating recursor had no infrastructure cache: every cache miss
  re-walked from the root, re-fetching zone-cut NS sets and the whole DNSSEC chain
  (root/TLD DNSKEY+DS) each time — ~70 % of miss traffic hit the root servers and
  each miss cost 325 ms–1.3 s. Added a TTL-honouring, bounded (LRU) zone-cut +
  validated-DNSKEY cache: repeated misses under the same parent now collapse from
  ~240 ms to ~55 ms. Fail-closed validation is preserved (DNSKEYs cached only after
  a Secure result, bounded by RRSIG expiry); reviewed by a two-model cross-audit.
- `PUT /api/policies/:name` returned 422 when the request body omitted `name`; it
  now takes the name from the path as documented (and a `POST` without a name gives
  a clear 400 "name is required" instead of a 422).
- The `fuzz`-feature library build was broken (`webhooks` referenced
  `crate::feeds::{SsrfSafeDnsResolver, is_private_ip}`, but `feeds` is not exposed to
  the cargo-fuzz lib). Extracted a standalone `src/ssrf.rs` — the single source of
  truth for the SSRF address filter and connection-time DNS guard — that
  `recursor_wire`, `feeds` and `webhooks` delegate to. Restores
  `cargo build --features fuzz` and the weekly fuzz workflow.
- `cargo audit` was not clean: bumped `anyhow` 1.0.102 → 1.0.103 (RUSTSEC-2026-0190),
  documented the two remaining `unmaintained` advisories (`paste`, `rustls-pemfile`)
  in `audit.toml`, and added a `cargo audit` CI job so the badge is verified on every
  push.
- Test harness: three `rbac_*` API tests were flaky-failing on some machines because
  they shared a fixed `BASE_DIR` (`/tmp/runbound-test`) that could be owned by another
  user, making `/api/dns` return 500. Each test process now uses its own writable temp
  dir. Full suite: 464 passing / 0 failing.

### Docs
- Documented `GET /api/dns/:id` and the `GET /api/alerts/rules` alias. `/api/help`
  now maps 1:1 to the router and every one of the 82 endpoints is covered by
  `docs/api.md`.
- Pre-publication accuracy pass: build prerequisites (clang/libbpf-dev/mold/musl-tools)
  in README + BUILD.md; fixed a dead audit-report link; version markers 0.9.0 → 0.9.1
  in the API/quick-start/internals/sync examples; the audit log is described as
  per-entry HMAC-SHA256 + periodic checkpoints (not a running chain); the sovereign
  recursor is config-gated (`resolution: full-recursion`), not feature-gated; and
  corrected stale source comments (`recursor_wire` build_query emits EDNS DO=1,
  `wire_bridge` notes hickory is a dev-only oracle). `include:` documented in
  `docs/unbound-migration.md`.

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
