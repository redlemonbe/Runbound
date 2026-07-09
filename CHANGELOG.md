# Changelog

All notable changes to Runbound are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.9.3] - 2026-07-09

Consolidated release of all post-0.9.2 work: VM/container CPU sizing, DNSSEC-validated
answer caching, parallel DNSSEC-chain recursion, forward-mode AD relay and DO=1 caching,
and observability.

### Added
- **DNSSEC verdict counters in OpenMetrics.** `GET /api/metrics` exports
  `runbound_dnssec_secure_total`, `runbound_dnssec_bogus_total` and
  `runbound_dnssec_insecure_total` (previously only in `GET /api/stats` and the WebUI).
- **Finer latency histogram above 1 s.** The fixed histogram gains 1.5 s / 2 s / 3 s bucket
  bounds (15 buckets total), sharpening p95/p99 for slow cache-miss recursions.

### Changed
- **DNSSEC-validated answers are cached (DO=1, full-recursion).** The shared wire cache
  previously stored only the RRSIG-free (DO=0) form, so DO=1 queries — the bulk of real
  traffic — re-recursed on every hit. A validating cache now holds the full validated answer
  keyed by `(qname, qtype)`; `Bogus` is never cached, and entry lifetime is bounded by both
  the smallest record/authority TTL and the nearest RRSIG expiration (fail-closed). Measured
  on the production master: validated hit rate ~7 % -> 35 %+, mean latency ~532 ms -> ~170 ms.
- **Recursor slow-path latency** (cache-miss). Three network-scheduling optimisations; DNSSEC
  validation semantics unchanged (same order, same fail-closed).
  - DNSSEC chain fetched in parallel: `trusted_keys_for` pre-fetches every level's DS/DNSKEY
    concurrently, then validates strictly in order. A cold ~5-RTT serial chain collapses toward
    ~1-2 RTT. Measured: -39 % median cold cache-miss latency.
  - Leaf answer + DNSKEY overlap (same servers, known from the referral).
  - Cold hedge: with no RTT history, `query_ns_set` fans out to 2 nameservers at once instead
    of waiting on a lone slow pick; hedge delay 300 ms -> 150 ms.
- **Forward mode relays the upstream AD (Authenticated Data) bit — safely.** A forwarder does
  not validate DNSSEC itself, so the upstream AD is propagated to the client only when BOTH
  hold: (a) the answer arrived over an authenticated DoT channel (`forward-tls-upstream`), and
  (b) the client asked for validation (AD or DO set). Cleartext UDP/TCP upstreams never
  propagate AD (anti-spoofing, RFC 6840 §5.7). The cache still stores the AD-less base form;
  AD is stamped only on the served copy.
- **Forward mode caches DO=1 (DNSSEC) answers locally** so repeat validated queries no longer
  re-forward to the upstream. Signed answers are cached with their RRSIGs and bounded by RRSIG
  expiration; unsigned (Insecure) answers are bounded by record TTL alone. Fail-closed: TTLs
  decay and are clamped to the entry lifetime, an already-expired RRSIG is never cached, the
  DO=0 fast path is unchanged, and AD is relayed under the same authenticated-channel gate.
  Measured on the production master (forward mode): hit rate ~13 % -> ~33 %.

### Fixed
- **CPU over-subscription on VMs / containers (self-inflicted latency).** `cpu::physical_cores()`
  read host-wide `/sys` CPU topology, which is NOT namespaced: a Proxmox VM with vCPU hotplug
  slots (or an LXC cpuset) advertises far more `cpuN` entries than the process may run on. On a
  2-vCPU VM Runbound spawned **64 tokio workers + 63 kernel-loop threads**, saturating the box
  (load ~14, ~193 % CPU at idle) and adding a **~200 ms scheduling stall to every slow-path UDP
  answer**. `physical_cores()` now intersects the sysfs topology with the CPU-affinity mask
  (`sched_getaffinity`), so worker/thread counts match the real budget. Physical-only selection
  is preserved (cores only dropped, never an SMT sibling added). No-op on bare-metal.
- **`cache_entries` reports the real cached-entry count.** `GET /api/stats` and
  `GET /api/cache/stats` exposed a per-miss counter that equalled `cache_misses`; they now
  report the live resolver-cache map length (`XDP_CACHE_FOR_API.len()`).
- **`GET /api/config` now reports `cache_min_ttl`** alongside `cache_max_ttl` (the TTL floor was
  applied at cache-insert time but omitted from the config dump).

## [0.9.2]

### Added
- **Live-editable DNS rate limit** — `rate-limit` / `rate-limit-burst` are changeable at runtime
  via `PATCH /api/config` and the WebUI Protection tab ("DNS Rate Limit" card): applied live to the
  XDP fast path + kernel slow path (no restart) and persisted to `runbound.conf`. `rate-limit-burst`
  is now honoured at `server:` level (it was silently ignored — the DNS burst was hard-coded to
  `rps*2`) and survives config regeneration; `GET /api/config` reports both live. Per-node (a local
  capacity policy, not replicated to slaves).
- QNAME minimisation (RFC 9156, #231) for the sovereign full-recursion resolver.
  Intermediate authoritative servers (root, TLD) are now probed with only the next
  label toward the target (as a QTYPE A query), so they never see the full query
  name; the complete name and type are sent only to the zone's own authoritative
  server. On by default under `resolution: full-recursion` (like Unbound), toggled
  with `qname-minimisation: yes|no`. Relaxed variant: any anomaly on a probe
  (NXDOMAIN on an empty non-terminal, an unexpected answer, or a mute server) falls
  back to the full name at that delegation point, so it never breaks an
  otherwise-resolvable name; deep flat names stop being probed label-by-label after
  10 labels. The two previously-duplicated descent loops (`resolve_once` /
  `resolve_message`) are unified into one engine. DNSSEC validation (incl. the
  DS-at-parent anchoring, #230) and the infrastructure cache are unaffected —
  verified live (Secure/Bogus/Insecure) and by packet capture showing the root
  receiving only the TLD.
- The WebUI header now shows the running version, between the name and the status dot.

### Security
- **Double-pass adversarial audit** (`docs/security-audit/AUDIT-2026-07-07`): `GET /api/audit/tail`
  is gated to admins (was readable by any authenticated key in multi-user); backup import writes
  secret files `0600`; the forward negative cache checks the authority SOA is in-bailiwick for the
  qname; `parse_nsec` slices the NSEC type bitmap at the bytes consumed, not the presentation length.
- **Auto-ban hardening on every path.** Loopback/unspecified can no longer be banned (a
  `PUT /blacklist/127.0.0.1` self-DoS that also persisted); relayed and manual bans are now permanent
  on **both** ban systems (XDP/kernel fast path *and* the slow-path/DoT/DoH/DoQ enforcer), fixing a
  silent 24h lapse on slaves; bot-defense bans also reach `icmp_stats` so they enforce on the
  kernel-UDP path under `xdp: no`; IPv6 bans propagate to the fast-path map; the in-memory ban and
  login-rate maps are capped.

### Fixed
- Alert rules with different windows now each count in their own sliding window; a single shared
  counter previously let a short-window rule reset the count a long-window rule needed, silently
  disabling it.
- `create_user` wrote a **duplicate** entry to `users.json`.
- `/api/metrics`: the `runbound_cache_hit_rate` HELP said "0.0 to 1.0" but the value is a percentage.
- Startup **fails fast** with an actionable message when the config base directory is not writable
  (was an obscure tokio "cannot drop a runtime" panic); the API/UI runtimes are leaked at creation to
  remove that async-drop panic class.
- **API documentation** (`docs/api.md`) resynced with the handlers across 21 endpoints — response
  schemas (`dns/lookup`, `cache/stats`, upstream probe), real OpenMetrics family names, the
  `PATCH /api/config` "is persisted" note, and 11 missing `/api/system` fields.
- WebUI idle auto-logout restored to **5 minutes** (it had drifted to 30).
- Backup restore/import now **applies live (hot-reload)** instead of asking for a service
  restart — Runbound never restarts. The restore re-reads the config, republishes local
  zones (resyncing the XDP cache), refreshes alert rules, and re-applies the resolution
  mode + QNAME-minimisation toggles; both restore paths share one `apply_config_hot_reload`
  helper (`restore_handler` previously discarded the reloaded config). Verified live: a
  restored zone reappears with no restart.
- Persisted-cache load hardened against an `Instant`-overflow panic on a corrupt cache
  file (checked add; PENT-1 from the offensive pentest — docs/security-audit/).
- Compact denial of existence (RFC 9824 / Cloudflare "black lies", #232): under
  `resolution: full-recursion` + `dnssec-validation: yes`, a non-existent name in a
  Cloudflare-hosted zone is now presented to the client as **NXDOMAIN** instead of
  NOERROR/NODATA. A validated NSEC that matches the qname and whose type bitmap carries
  the NXNAME pseudo-type (128) translates NOERROR → NXDOMAIN (fail-closed: only on a
  Secure verdict). Genuine NODATA and classic NXDOMAIN are unchanged. NSEC for now;
  NSEC3 compact denial to follow.
- IPv6 on the slow path (#233): with `xdp: no`, an IPv6 `interface:` failed to bind
  (`:::53` is invalid and the kernel-loop socket was hard-coded to IPv4), which took
  down ALL of DNS. Bind addresses are now bracketed (`[::]:53`), the socket domain
  follows the address (IPv6-only, so `[::]:53` coexists with an IPv4 wildcard bind and
  the ACL/rate-limiter sees the real source), and a secondary interface that cannot bind
  (e.g. a fixed IPv6 whose prefix went away) is skipped with a warning instead of
  failing the whole service — the primary DNS stays up.

### Changed
- A manual ban via `PUT /api/alerts/blocked/:ip` is now **permanent** on both ban systems (matching
  the documented "permanent, no expiry"). Ban/blacklist endpoints return `{blocked:false,reason}` /
  `{blacklisted:false,reason}` for a protected (loopback/unspecified) target instead of a false
  success.
- WebUI About page: removed the external Links section and the issue hyperlink; the
  community-contributor credit is now plain text (no link).

## [0.9.1]

### Added
- IPv6 bans are now enforced at the XDP fast path. A new `icmp_banned_v6`
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
- "Top Domains" stayed empty at low QPS: per-domain counters sat in
  thread-local buffers because the only flush trigger was count-based (every 512
  calls), which never fires at residential/LAN rates. Added a time-based flush
  (≤ 1 s) so the dashboard converges at any QPS; the multi-MQPS path is unchanged.
- The validating recursor had no infrastructure cache: every cache miss
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

### Security

- **M1** — the WebUI login always runs the argon2 verify, even when the username is
  wrong, so response time no longer leaks whether a username is valid.
- **M2** — the validating recursor reads UDP responses until one matches the query's
  transaction id *and* question; a single spoofed or stray datagram from the queried
  server no longer aborts resolution (still bounded by the query timeout).
- **M3** — the systemd unit now sets `MemoryDenyWriteExecute=true` (W^X). Verified
  compatible: AF_XDP UMEM is read/write only, eBPF loads via the `bpf()` syscall, and
  the crypto is pure-Rust.
- **M4** — the WebUI escapes the record id interpolated into the delete handlers.
- **M5** — `tls-cert-bundle` is Unbound's *outbound* CA bundle, not the DoT/DoH server
  certificate; it is now warned about and ignored instead of being loaded as the cert.
- Documented in `docs/xdp.md` that the XDP blacklist fast-block matches the raw QNAME
  case-sensitively — a case-varied (0x20) query falls through to the slow path, which
  still blocks it (no bypass).

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
- Signed releases — minisign signatures + CycloneDX SBOM shipped with every release. Signing public key `RWSBM9HzDiZpfCD82uTnkeP1Ui30LfWE96C8EtFyI4/WVyLAVxpLzYy/` (see `docs/BUILD.md`).

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

> Not yet audited by an external third party — see #170.
