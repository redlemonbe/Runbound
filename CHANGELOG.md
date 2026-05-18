# Changelog

All notable changes to Runbound are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.4.13] — 2026-05-18

### Fixed

- **XDP crash on UMEM allocation** (`XDP_UMEM_REG failed: No buffer space available`):
  the default locked-memory limit (~64 KB) is insufficient for AF_XDP UMEM rings.
  Runbound now raises `RLIMIT_MEMLOCK` to infinity before allocating UMEM sockets.
  `LimitMEMLOCK=infinity` added to `runbound.service` and `install.sh` as belt-and-suspenders.

- **XDP socket creation panic replaced by clean fallback**: the `expect()` at
  `worker.rs:74` was crashing the entire process instead of falling back to
  SO_REUSEPORT. Replaced with `map_err(...)` so XDP failure triggers the normal
  graceful degradation path.

---

## [0.4.12] — 2026-05-18

### Fixed

- **XDP eBPF verifier rejection — instruction 21** (`r3 += r4`): the BPF verifier
  prohibits adding a scalar variable to a packet pointer even with `CAP_BPF`.
  Fixed by assuming a standard IPv4 header (IHL = 20, no options); packets with
  IP options are passed to the kernel via `XDP_PASS`. The UDP offset is now a
  compile-time constant (14 + 20 = 34), statically provable by the verifier.
  Validated with `bpftool prog load` on kernel 6.12.

---

## [0.4.11] — 2026-05-18

### Fixed

- **XDP eBPF verifier rejection on kernel 6.x** — the BPF verifier rejected the previous
  `dns_xdp` program because of variable-offset pointer arithmetic passed through an
  inlined function (`data + udp_off`). Rewritten to use struct-relative arithmetic
  (`(void *)ip + ihl`, `(struct udphdr *)(ip6 + 1)`) which the verifier can track.
  Validated with `bpftool prog load` on kernel 6.12.

- **XDP error messages now categorized** — on startup failure, Runbound distinguishes
  between: verifier rejection, missing capabilities, `AF_XDP` not in `RestrictAddressFamilies`,
  and unsupported NIC/kernel.

---

## [0.4.10] — 2026-05-18

### Changed

- **All release binaries now built with `--features xdp`** — AF/XDP kernel-bypass fast path enabled in every published binary. Previously XDP was opt-in at build time only.

---

## [0.4.9] — 2026-05-18

### Changed

- **DNS socket workers use physical core count** (HT excluded) instead of `available_parallelism()`. Consistent with the tokio runtime pinning introduced in v0.4.8.

- **Cache size is now auto-sized from available RAM** and adjusts dynamically under memory pressure.
  At startup, Runbound allocates up to 10 % of `MemAvailable` (1 entry ≈ 512 B), clamped to [512, 65 536] entries and logged as `cache_size=N entries (auto-sized from MemAvailable)`.
  The memory guard (every 30 s) now operates in four bands:
  - **< 60 % used** — scale up: restore cache toward the current optimal size (5-minute cooldown between upscales).
  - **60–70 %** — stable, no action.
  - **70–80 %** — halve cache size (floor 512).
  - **≥ 80 %** — recalculate from current RAM, flush rate limiter.

---

## [0.4.8] — 2026-05-18

### Added

- **CPU affinity for tokio worker threads** (`cpu-affinity: yes/no`, default `yes`).
  Each tokio worker is pinned to a distinct physical core, HyperThreading siblings excluded.
  Reduces cache thrashing and improves tail latency consistency at high QPS.
  Startup log reports the number of pinned cores.
  Silent fallback when `/sys` is unavailable (containers, non-Linux).

---

## [0.4.7] — 2026-05-18

### Fixed

- **`rate-limit: 0` now disables rate limiting** (was: refuse every query).
  When `rate-limit` is set to `0` in `unbound.conf`, the token-bucket `check()`
  now returns `true` immediately without touching the bucket table. Previously,
  `rps = 0` produced `burst = 0`, the initial bucket had `tokens = 0`, the
  refill formula added `(0 × elapsed) / 1000 = 0` tokens, and every query was
  answered `REFUSED`.  
  Startup log now prints `rate limiting disabled (rate-limit: 0)` instead of
  `rps=0 burst=0`.

---

## [0.4.6] — 2026-05-18

### Changed — code quality & performance (senior Rust audit follow-up)

- **QUAL-05** (`src/main.rs`) — Decomposed 344-line `main()` into three private helpers:
  `handle_cli_flags()`, `init_runtime()`, `build_and_launch()`. `main()` is now a
  40-line dispatcher with clear separation of concerns.

- **QUAL-06** (`src/dns/server.rs`) — Extracted `handle_local_zone()` and
  `resolve_upstream()` from the 298-line `handle_request()`. Uses `Result<ResponseInfo, R>`
  to safely transfer `ResponseHandler` ownership without cloning. `handle_request()` is
  now a 40-line dispatcher; zero behavior change.

- **QUAL-07** (`src/api/mod.rs`) — Extracted `validate_dns_entry()` (all validation,
  RR construction, parse) and `persist_and_swap()` (mutex, store, ArcSwap) from
  `add_dns_handler()`. Handler body reduced to 3 lines.

- **QUAL-08** (`src/api/mod.rs`) — Extracted `fmt_counter()`, `fmt_gauge()`, and
  `render_prometheus_metrics()` from `metrics_handler()`. Handler body reduced to 2 lines.

- **PERF-02** (`src/dns/server.rs`) — Zero-alloc identity-probe check: static
  `OnceLock<[LowerName; 4]>` initialised once, compared by reference per query.
  Eliminates a `String` allocation on every DNS request.

- **PERF-03/QUAL-03** (`src/upstreams.rs`) — `BIND_V4` / `BIND_V6` are now `const
  SocketAddr` (Rust 1.82+), removing two `.parse().unwrap()` calls in the hot probe path.

- **QUAL-01** (`src/sync.rs`) — `.unwrap()` → `.expect("…")` on all Mutex locks for
  clearer panic diagnostics.

- **QUAL-02** (`src/upstreams.rs`) — `.unwrap()` → `.expect("…")` on all RwLock
  accesses in the health-loop task.

- **QUAL-04** (`src/api/mod.rs`) — Removed duplicate section comment before
  `POST /rotate-key`.

- **QUAL-09** (`src/config/parser.rs`) — Added intent comment above the
  `match key {}` block in `parse_server_directive`.

- **PERF-01 doc** (`docs/api.md`) — Added copy-on-write write-performance note
  under the DNS entries section explaining the `ArcSwap` clone-on-write zone store
  and its lock-free read behaviour.

- **docs** (`docs/code-audit.md`, `docs/security.md`) — Added full 23-finding senior
  Rust audit report (QUAL, PERF, BUILD, ARCH categories); linked from security.md.

---

## [0.4.5] — 2026-05-17

### Security — pentest v0.4.4 follow-up

- **NEW-HIGH — Timing oracle on Bearer token eliminated** (`src/api/mod.rs`)  
  The brute-force brake (`tokio::time::sleep(500 ms)` at ≥ 50 auth failures) was on the
  critical path *after* `constant_time_eq`, creating a measurable timing signal for keys
  that shared a long prefix with the valid key (observed: +183 ms vs. random key).  
  Fix: the sleep is now applied **before** `constant_time_eq`, uniformly to all requests
  when the failure counter is high, so it cannot reveal key content. Post-comparison side
  effects (audit event, periodic `warn!`) are moved to `tokio::spawn` — the 401 is
  returned immediately with no timing leakage.

- **SEC-02 MEDIUM — Domain length validation confirmed + HTTP integration tests** (`src/api/mod.rs`)  
  Pentest claimed "254-char name → HTTP 201". Investigation confirms this is the same false
  positive as the military audit: the test used a 253-char name + trailing FQDN dot (= 254
  bytes submitted), which is correctly accepted (trailing dot stripped before the 253-char
  check per RFC 1035 §2.3.4). Added three HTTP-level integration tests
  (`dns_name_254_chars_is_rejected`, `blacklist_name_254_chars_is_rejected`,
  `dns_name_253_chars_no_trailing_dot_passes_validation`) that prove the boundary
  end-to-end and will catch any regression.

- **SEC-04 LOW — JSON POST without `Content-Length` now returns 411** (`src/api/mod.rs`)  
  Chunked JSON bodies (no `Content-Length` header) bypassed the early 413 check in the
  security middleware and caused `DefaultBodyLimit` to drop the TCP connection for large
  bodies (observed for 512 KB and 5 MB payloads) instead of returning 413. Fix: JSON
  requests without `Content-Length` now receive **411 Length Required** before reaching
  rate limiting or auth. Non-JSON POST endpoints (`/reload`, `/feeds/update`, etc.)
  are unaffected. New integration tests confirm 411 behaviour.

- **NEW-LOW — UUID null byte TCP drop** (`docs/security-audit.md`)  
  A raw `\x00` in an HTTP path is rejected by hyper at the HTTP/1.1 parse layer before
  any application code runs. Documented as a known hyper limitation; not addressable at
  the application level.

---

## [0.4.4] — 2026-05-17

### Added — supply-chain security & HSM key storage

- **Supply-chain audit tooling** (`deny.toml`, `Makefile`, `docs/audit.md`)  
  Added `cargo-deny` configuration (`deny.toml`) with advisory blocking, license whitelist
  (MIT, Apache-2.0, BSD-2/3, ISC, Zlib, Unicode-3.0, CDLA-Permissive-2.0; AGPL-3.0-or-later
  for runbound itself), and dependency ban rules. New `Makefile` targets: `audit`
  (`cargo audit --deny warnings`), `deny` (`cargo deny check`), `sbom`
  (`cargo cyclonedx --format json`), `audit-full` (all three + `cargo outdated`).
  Full process documented in `docs/audit.md`.

- **HSM key storage via PKCS#11** (`src/hsm.rs`, `docs/hsm.md`)  
  Sensitive key material (REST API Bearer token, JSON store HMAC key) can now be loaded
  from a Hardware Security Module via PKCS#11 (`cryptoki 0.6`). Keys are extracted once at
  startup into `Zeroizing<T>` buffers (memory scrubbed on drop) and the HSM session is
  closed immediately after. Priority chain: HSM > `RUNBOUND_API_KEY`/`RUNBOUND_STORE_KEY`
  env vars > config file > auto-generated. Failure to load keys from a configured HSM is
  **fatal** — no silent fallback. Supported: SoftHSM2 (dev/CI), YubiHSM 2, Nitrokey HSM 2,
  AWS CloudHSM, Thales Luna (any PKCS#11-compliant `.so`). New config directives:
  `hsm-pkcs11-lib`, `hsm-slot`, `hsm-pin` (WARN if in config; prefer `HSM_PIN` env var),
  `hsm-api-key-label`, `hsm-store-key-label`. `/health` now reports `"hsm": true/false`;
  `/config` masks the PIN as `"***"`. Full setup guide in `docs/hsm.md`.

---

## [0.4.3] — 2026-05-17

### Fixed — second military audit follow-up (all findings closed)

- **SEC-02 INFO — Domain name length validation confirmed correct** (`src/api/mod.rs`)  
  Added six unit tests for `validate_dns_name()` to document and verify RFC 1035 §2.3.4
  compliance: 253-char names accepted, 254-char names rejected, trailing-dot stripping
  before length check, per-label 63-char enforcement. Audit finding was a false positive —
  the auditor counted the trailing dot as part of the name length; the existing `n.len() > 253`
  check (where `n` is the name with the trailing dot stripped) is correct per RFC.

- **SEC-03 LOW — Identity probes inconsistently blocked** (`src/dns/server.rs`)  
  The CHAOS class check (`u16::from(query_class()) == 3`) was in place but hickory
  normalises the CHAOS class to IN before invoking our handler for some query paths,
  causing `version.bind.` to return NOERROR and `hostname.bind.` to return NXDOMAIN
  instead of REFUSED/NOTIMP.  
  Added a defense-in-depth name-based check immediately after the class check: any query
  for `version.bind.`, `hostname.bind.`, `id.server.`, or `version.server.` — regardless
  of query class — now returns REFUSED.

- **DOC-01 INFO — README showed v0.3.4 binary names** (`README.md`)  
  Updated all hardcoded binary filename references from `v0.3.4` to `v0.4.3`.

- **DOC-02 INFO — Non-configurable runtime limits undocumented** (`docs/configuration.md`)  
  Added "Fixed runtime limits" section documenting all compiled-in constants:
  API max payload (64 KB), API rate limit (30 req/s, burst 60), sync ring buffer
  (1,000 events), memory purge thresholds (80 % → 50 %), and hard caps on DNS
  entries (10,000), blacklist entries (100,000), and feed subscriptions (100).

- **DOC-03 INFO — Slave DNS behaviour not documented** (`docs/ha.md`)  
  Added "Slave DNS behaviour" section documenting that replicated entries are served
  by the slave's DNS engine immediately after each sync cycle (fixed in v0.4.2), the
  behaviour on slave restart (zones rebuilt from disk before accepting queries), and
  what happens during a sync cycle (atomic zone-trie updates under mutex).

---

## [0.4.2] — 2026-05-17

### Fixed

- **MEDIUM — Replicated entries not served by DNS on slave nodes** (`src/sync.rs`, `src/main.rs`)  
  `SlaveClient::apply_event` was writing deltas to the on-disk store but never updating
  the in-memory `ArcSwap<LocalZoneSet>` that hickory uses to answer queries. The slave's
  `/dns` API showed the entry; DNS returned NXDOMAIN.  
  `POST /reload` was correctly blocked (`READ_ONLY`) on slaves, leaving no path to apply
  changes without a restart.

  Fix — `SlaveClient` now holds `Arc<ArcSwap<LocalZoneSet>>`, the shared `zones_mutex`,
  and the `UnboundConfig`. For each delta operation:
  - `AddDns` — injects the new record directly into the zone trie (same path as the API
    handler), under `zones_mutex` to prevent concurrent write races.
  - `DeleteDns` — saves the store then calls `build_zone_set()` for a full rebuild
    (deletion requires removing from the trie; incremental removal is not worth the complexity).
  - `AddBlacklist` — calls `override_zone()` on the current zone set (same as the API).
  - `DeleteBlacklist` — full rebuild via `build_zone_set()`.
  - `full_sync` — saves all three stores then rebuilds zones atomically under `zones_mutex`.

  `zones_mutex` is now hoisted before slave/AppState construction in `main.rs` so both
  share the same `Arc<Mutex<()>>` instance — zone mutations from the API and from sync
  are mutually exclusive.

---

## [0.4.1] — 2026-05-17

### Fixed — v0.4.0 audit follow-up (all findings closed)

- **BUG-01 BLOCKING — Sync HTTPS server panic** (`src/main.rs`)  
  rustls 0.23 panics when `ServerConfig::builder()` is called without a default
  `CryptoProvider` installed. Added `rustls::crypto::ring::default_provider().install_default().ok()`
  early in `main()`. Port 8082 now opens; HA master/slave sync is functional.

- **S-10 MEDIUM — CNAME/MX/NS/PTR/SRV target values not length-validated** (`src/api/mod.rs`)  
  `validate_dns_name()` was only applied to the DNS `name` field and blacklist `domain`.
  Target `value` fields for CNAME, MX, NS, PTR, SRV and the `replacement` field for
  NAPTR are now validated as domain names (max 253 chars, labels max 63 chars, RFC 1035
  character set). Rejects RFC-violating records with HTTP 400.

- **S-11 LOW — 1 MB body returned HTTP 429 instead of 413** (`src/api/mod.rs`)  
  `DefaultBodyLimit` fires at extraction time inside the handler, after the rate limiter.
  Added `Content-Length` header pre-check at the top of `security_middleware` — oversized
  requests are rejected with JSON HTTP 413 before the rate-limit token is consumed.

- **Q-01/Q-02/Q-03 LOW — JSON deserialization failures returned plain-text 422** (`src/api/mod.rs`)  
  axum's default `Json<T>` extractor returns a plain-text body on `JsonRejection`.
  Replaced with a custom `ApiJson<T>` extractor (`#[axum::async_trait] FromRequest`)
  that converts all `JsonRejection` variants to structured JSON:
  `{"error": "INVALID_REQUEST", "details": "..."}`. Applied to `POST /dns`,
  `POST /blacklist`, `POST /rotate-key`.

- **Q-04 LOW — GET /logs?page=-1 returned plain-text 400** (`src/api/mod.rs`)  
  `Query<LogsParams>` with `page: usize` would panic the extractor on negative input.
  Changed to `Result<Query<LogsParams>, QueryRejection>` — parse failure returns
  `{"error": "INVALID_PARAM", "details": "..."}` with HTTP 400.

### Documentation

- **`docs/security.md`** — Complete rewrite to reflect v0.4.0 architecture:
  HMAC store integrity, connection-layer SSRF resolver, mutual TLS for DoT,
  rustls 0.23 TLS stack, updated defensive-layers diagram, full audit table
  through v0.4.1.

---

## [0.4.0] — 2026-05-17

### Security — all open audit findings closed

- **HIGH-06 — HMAC-SHA256 store integrity** (`src/integrity.rs`, `src/store.rs`, `src/feeds/mod.rs`)  
  Set `RUNBOUND_STORE_KEY` (env var, hex 32+ bytes or UTF-8) to enable.  
  Every JSON write produces a sidecar `.mac` file (`HMAC-SHA256(content, key)`, hex).  
  On load: missing `.mac` with key set → WARN; HMAC mismatch → ERROR, load refused.  
  Domain caches are regeneratable: mismatch discards cache with WARN and triggers re-fetch.

- **HIGH-07 — hickory 0.24 → 0.26, rustls 0.21 → 0.23** (`Cargo.toml`, `src/dns/server.rs`, `src/sync.rs`)  
  Resolves six CVEs: RUSTSEC-2026-0119, -0037, -2025-0009, -2026-0104, -0098, -0099.  
  rustls 0.23 defaults to TLS 1.3 + approved cipher suites (BSI TR-02102 / NIST SP 800-52 Rev 2).  
  DoQ uses `builder_with_protocol_versions(&[&TLS13])` — Quinn enforces TLS 1.3 only.  
  All `audit.toml` ignores removed.

- **HIGH-08 — DoT mutual TLS** (`src/dns/server.rs`, `src/config/parser.rs`)  
  New `dot-client-auth-ca:` directive. When set, `WebPkiClientVerifier` requires clients  
  to present a certificate signed by the configured CA. DoH and DoQ unaffected.

- **MED-03 — SSRF at TCP connection layer** (`src/feeds/mod.rs`)  
  `SsrfSafeDnsResolver` implements `reqwest::dns::Resolve`.  
  Every hostname resolution by the feed HTTP client filters private/loopback addresses  
  before the TCP connection is established — independent of the system resolver.

- **MED-06 — qname log injection** (`src/dns/server.rs`)  
  `sanitize_dns_name()` replaces ASCII control chars (0x00–0x1F, 0x7F) and non-ASCII  
  bytes with `?` before any structured log emission. Prevents log injection via crafted  
  DNS names in JSON-mode logging (Elasticsearch, Splunk consumers).

- **LOW-03 — Config entry cap** (`src/config/parser.rs`)  
  `MAX_LOCAL_ZONES = MAX_LOCAL_DATA = 1_000_000`. Entries above the cap are dropped  
  with a WARN. Prevents startup OOM from pathological configs.

### Changed

- `hickory-server`, `hickory-resolver`, `hickory-proto` bumped to `0.26`.
- `rustls` bumped to `0.23`, `rustls-pemfile` to `2`, `tokio-rustls` to `0.26`.
- `TokioAsyncResolver` renamed to `TokioResolver` (hickory 0.26 API).
- `ServerFuture` renamed to `Server`; `register_listener` gains `response_buffer_size` arg.
- `MessageResponseBuilder` moved to `hickory_server::zone_handler`.
- `RequestHandler::handle_request` gains `T: Time` type parameter (hickory 0.26).
- `ResolverConfig::new()` → `from_parts(None, vec![], vec![])`.
- `record.name()` → `record.name` field access (hickory 0.26 public fields).
- `Record::new()` → `Record::from_rdata(name, ttl, rdata)`.
- rustls `Certificate`/`PrivateKey` → `pki_types::{CertificateDer, PrivateKeyDer}`.
- `ServerCertVerifier` → `rustls::client::danger::ServerCertVerifier`.
- `verify_server_cert` no longer takes `_scts`; uses `UnixTime` instead of `SystemTime`.

---

## [0.3.5] — 2026-05-17

### Fixed

- **`GET /config` missing `log_retention` / `log_client_ip`** — the two GDPR privacy
  directives added in v0.3.4 were not exposed in the config snapshot endpoint.
  Both fields now appear in the response alongside all other runtime parameters.
- **CHAOS class returning NOERROR** — confirmed that `version.bind CH TXT` and
  `hostname.bind CH TXT` correctly return `NOTIMP` (SEC-10). The finding was caused by
  the pentest tooling hitting the system Unbound on port 53 rather than Runbound.
  No code change required; this entry documents the root-cause analysis.

---

## [0.3.4] — 2026-05-17

### Added

- **AGPL-3.0 dual license** — Runbound switches from PolyForm Noncommercial to AGPL-3.0
  for open-source use. A commercial license remains available for organizations that
  cannot comply with the AGPL (see `COMMERCIAL_LICENSE.md`).
- **SPDX headers** — every `.rs` source file now carries `SPDX-License-Identifier: AGPL-3.0-or-later`.
- **`log-retention` config directive** — controls the size of the in-RAM query log ring
  buffer (default: 1000). Set to `0` to disable `/logs` entirely and hold no client IPs
  in memory (GDPR data minimisation).
- **`log-client-ip` config directive** — when set to `no`, client IPs are replaced with
  `[redacted]` before being stored in the ring buffer and the logfile. The audit log is
  unaffected (IPs are required for PCI-DSS / NIS2 traceability).
- **`DELETE /logs`** — authenticated endpoint that clears the in-memory query log ring
  buffer and records the action in the audit log (`event: "logs_clear"`). Allows operators
  to respond to GDPR right-to-erasure requests without restarting the server.
- **`docs/gdpr.md`** — GDPR compliance guide covering data inventory, operator
  responsibilities, and concrete configuration recipes.
- **`CLA.md` rewrite** — plain-language one-page CLA; grants the maintainer the right
  to redistribute contributions under any license (AGPL or commercial) with mandatory
  changelog attribution.

---

## [0.3.3] — 2026-05-17

### Fixed

- **Bug 1 — `POST /rotate-key` silent no-op** (`src/api/mod.rs`)  
  The handler was reading `RUNBOUND_API_KEY` from the process environment,
  which is frozen at startup — updating the systemd EnvironmentFile without
  a restart had no effect. New contract: caller sends `{"new_key":"<32+ chars>"}`
  in the JSON body. Validates minimum length (32 chars), rejects control characters,
  atomically swaps the in-memory key, and persists to `base_dir/api.key` (chmod 600).

- **Bug 2 — CHAOS class queries returned NOERROR** (`src/dns/server.rs`)  
  The `DNSClass::CH` enum comparison could fail when hickory parsed the class
  as `Unknown(3)` for some query variants, bypassing the filter. Fixed by
  comparing the numeric wire value directly (`u16::from(class) == 3`).
  Response changed from REFUSED to NOTIMP per RFC 5358 §4.

- **Bug 3 — Payloads ≥512 KB dropped TCP connection instead of HTTP 413** (`src/api/mod.rs`)  
  `tower_http::RequestBodyLimitLayer` drops the TCP connection for very large
  payloads instead of returning 413. Replaced with `axum::extract::DefaultBodyLimit::max()`
  which enforces the limit at the stream level and always sends a proper 413
  before reading the body into RAM, regardless of payload size.

- **Bug 4 — Negative TTL returned plain-text 422 instead of JSON** (`src/api/mod.rs`)  
  TTL field changed from `u32` to `i64` so serde accepts negative values
  without aborting deserialization. Explicit validation now returns
  `{"error":"INVALID_TTL","details":"TTL must be between 0 and 2147483647"}` HTTP 422.

### Security (audit)

- **[HIGH] Sync Bearer comparison was not constant-time** (`src/sync.rs`)  
  `auth != format!(...)` string comparison exits early on the first differing
  byte — a timing oracle for the sync-key length and content. Replaced with
  `subtle::ConstantTimeEq`.

- **[MEDIUM] Feed URLs with embedded credentials accepted** (`src/feeds/mod.rs`)  
  `https://user:pass@host/path` would strip credentials for the SSRF host check
  but store the URL with credentials in the config. Now explicitly rejected with
  a clear error message.

- **[MEDIUM] `rate-limit: 18446744073709551615` silently disabled rate limiting** (`src/config/parser.rs`)  
  Extreme values parsed as `u64::MAX` effectively disable the rate limiter.
  Capped at 1,000,000 rps.

- **[LOW] `unwrap()` on production RwLock/Mutex** (`src/api/mod.rs`, `src/store.rs`)  
  `upstreams.read().unwrap()`, `log_buffer.lock().unwrap()`, and two
  `path.parent().unwrap()` calls replaced with explicit error handling that
  returns HTTP 500 JSON or propagates `AppError::Internal`.

### Audit findings (acknowledged, not fixed — target v0.4.0)

Six CVEs in `hickory-proto 0.24` transitive dependencies require upgrading
to `hickory 0.26`. The migration breaks ~50 API sites across the codebase
(rustls 0.21→0.23, renamed types, restructured modules) and is tracked for
v0.4.0. See `audit.toml` for per-CVE exposure analysis and mitigations.

- RUSTSEC-2026-0119 — hickory-proto: O(n²) name compression (CPU exhaustion)
- RUSTSEC-2026-0037 — quinn-proto: DoS (CRITICAL — mitigate: firewall 853/UDP)
- RUSTSEC-2025-0009 — ring: AES panic with overflow checks (release builds unaffected)
- RUSTSEC-2026-0104/98/99 — rustls-webpki: CRL/name constraint issues (no exploitable path)

---

## [0.3.2] — 2026-05-17

### Added

- **`GET /metrics` — Prometheus/OpenMetrics exposition** (`src/api/mod.rs`)  
  All stats counters and gauges are now available in Prometheus text format
  (`text/plain; version=0.0.4`). Compatible with Prometheus, Grafana Agent,
  VictoriaMetrics, and OTEL Collector. Requires Bearer authentication.

  Exposed metrics: `runbound_queries_total`, `runbound_blocked_total`,
  `runbound_nxdomain_total`, `runbound_refused_total`, `runbound_servfail_total`,
  `runbound_forwarded_total`, `runbound_local_hits_total`, `runbound_uptime_seconds`,
  `runbound_qps{window}`, `runbound_latency_ms{quantile}`,
  `runbound_cache_hit_rate`, `runbound_cache_entries`,
  `runbound_dnssec_total{status}`.

- **`POST /rotate-key` — live API key rotation without restart** (`src/api/mod.rs`)  
  Atomically replaces the active Bearer token from the `RUNBOUND_API_KEY` environment
  variable. The old key is invalidated immediately. DNS service is uninterrupted.
  Designed for PCI-DSS and NIS2 periodic key rotation requirements. The rotation is
  recorded in the audit log as a `ConfigReload` event.

  The API key is now stored in an `ArcSwap<String>` (previously `OnceLock<String>`)
  to allow lock-free atomic swaps on every auth check with zero overhead.

### Fixed (documentation)

- **DoH not documented in `docs/tls.md`** — Added full DoH section: port 443,
  path `/dns-query`, `curl`/`kdig`/`doggo` test examples, browser and OS client
  configuration (Firefox, Chrome, Windows 11, Android). All three encrypted protocols
  (DoT, DoH, DoQ) now documented with a comparison table.

- **ACME timer ambiguity in `docs/configuration.md`** — Clarified that the "60 days"
  value is the cert file mtime threshold (not a configurable TTL). Let's Encrypt issues
  90-day certs; a 60-day mtime check triggers renewal with ≥ 30 days of validity
  remaining. Added a summary line: check interval = 6 h · threshold = 60 days ·
  minimum remaining validity = 30 days.

- **`/help` auth ambiguity** — `GET /help` requires Bearer authentication on all nodes.
  Documentation harmonised across `docs/api.md` with a security rationale note
  (fingerprinting prevention, consistent with AUDIT-HIGH-02).

- **`access-control` default not explicit** — The implicit `refuse` catch-all when no
  rule matches is now shown as a row in the action table with a bold label and a note
  that an empty `access-control` block blocks all clients.

- **`sync-cert.pem` path undocumented in `docs/ha.md`** — Added a file reference table
  documenting the exact paths for `sync-cert.pem`, `sync-key.pem`, and
  `sync-master.fingerprint`. Noted that all runtime files follow the config file
  directory (`base_dir`), with guidance for non-standard install paths and re-TOFU
  procedure.

---

## [0.3.1] — 2026-05-17

### Added

- **Immutable HMAC-SHA256 audit log** (`src/audit.rs`, `src/config/parser.rs`, `src/api/mod.rs`, `src/main.rs`)  
  Every security-relevant API operation is written to an append-only structured log
  (`audit.log` in the config directory) with a monotonic sequence number and an
  HMAC-SHA256 chain. Tampering with any line — or deleting lines — breaks the chain
  and is detectable by replaying `mac = HMAC-SHA256(key, seq || ts || event || fields)`.

  The log is driven by a dedicated tokio task over an unbounded channel — callers
  (API handlers) never block on the hot path. The HMAC key is auto-generated on first
  run (256-bit, chmod 600, `audit-hmac.key`). The monotonic sequence is persisted in
  `audit-seq.dat` (flushed every 100 events and on clean shutdown) so it survives restarts.

  **Events logged:** `startup`, `shutdown`, `dns_add`, `dns_delete`, `blacklist_add`,
  `blacklist_delete`, `feed_add`, `feed_delete`, `config_reload`, `auth_failure`.

  **New endpoint:** `GET /audit/tail?n=100` — returns the last N lines (max 1,000) as a
  JSON array. Useful for SIEM integration.

  **Config directives:**
  ```
  audit-log:          yes                      # default: no
  audit-log-path:     /var/log/runbound/audit.log  # default: <config_dir>/audit.log
  audit-log-hmac-key: "hex-or-raw-key"         # default: auto-generated
  ```

- **Automatic Let's Encrypt certificate provisioning via ACME** (`src/acme.rs`, `src/config/parser.rs`, `src/main.rs`)  
  Runbound can now request, obtain, and renew TLS certificates from Let's Encrypt
  automatically — no certbot, no manual renewal scripts.

  Uses ACME HTTP-01 challenge: a temporary HTTP listener on port 80 is started only
  during the challenge phase, then shut down. The cert is written atomically via
  temp-file → rename. A background task checks every 6 hours and renews when
  ≤ 30 days remain (Let's Encrypt certs are valid 90 days).

  Transport: `instant-acme 0.8.5` (ring backend) with a custom `reqwest`-based HTTP
  client, avoiding the `rustls 0.21 / 0.23` version conflict with hickory-server.

  **Config directives:**
  ```
  acme-email:          admin@example.com    # Let's Encrypt account contact
  acme-domain:         dns.example.com      # SANs (repeat for multiple)
  acme-cache-dir:      /etc/runbound/acme   # account credentials + temp files
  acme-staging:        no                   # yes = use LE Staging API (testing)
  acme-challenge-port: 80                   # HTTP-01 challenge port (default: 80)
  ```

  The cert and key paths come from `tls-service-pem` / `tls-service-key` (or fall back
  to `cert.pem` / `key.pem` in the config directory). Once obtained, DoT/DoH/DoQ are
  active with a publicly trusted certificate.

- **DNSSEC full local validation stats** (`src/stats.rs`, `src/dns/server.rs`, `src/api/mod.rs`)  
  New config directive `dnssec-log-bogus: yes` (default: no) triggers WARN logs for
  every DNSSEC-bogus query. Bogus queries (`RrsigsNotPresent`) return SERVFAIL and
  increment `dnssec.bogus`. Secure responses (RRSIG present) increment `dnssec.secure`;
  unsigned queries increment `dnssec.insecure`. All counters are `AtomicU64`.  
  Exposed in `GET /stats` as:
  ```json
  "dnssec": {"secure": 1204, "bogus": 3, "insecure": 8821}
  ```

- **Runtime files relative to config directory** (`src/runtime.rs`)  
  All runtime files (`api.key`, `dns_entries.json`, `blacklist.json`, `feeds.json`,
  `sync-cert.pem`, `audit.log`, …) are now stored in the **same directory as the config
  file** — not hardcoded under `/etc/runbound/`. This allows a master and slave to run
  on the same machine using separate config directories without any path collisions.

### Fixed

- All pre-existing `cargo clippy -- -D warnings` failures resolved:
  `clippy::upper_case_acronyms` on `DnsType` variants; `trim_split_whitespace`;
  `is_multiple_of`; redundant `into_iter()`; `map_err` → `inspect_err` in XDP socket;
  `last()` on `DoubleEndedIterator`; manual prefix stripping; double-`Ok` + `?`;
  `unwrap()` after `is_some()`.

---

## [0.3.0] — 2026-05-17

### Added

- **`GET /stats` — 9 new fields** (`src/stats.rs`, `src/api/mod.rs`)  
  The stats endpoint now reports QPS sliding window (`qps_1m`, `qps_5m`, all-time `qps_peak`),
  latency percentiles (`latency_p50_ms`, `latency_p95_ms`, `latency_p99_ms`), cache metrics
  (`cache_hit_rate`, `cache_entries`), and local zone resolution count (`local_hits`).  
  Implementation: fixed 10-bucket latency histogram (zero allocation per query via `partition_point`);
  300-slot QPS ring buffer (`AtomicU64` × 300, updated by a 1-second background task);
  cache hit detection via timing heuristic (< 2 ms = hickory in-process cache hit).
  All hot-path counters are `AtomicU64` — no mutex, no allocation on the DNS query path.

- **`GET /stats/stream` — Server-Sent Events live stats** (`src/api/mod.rs`)  
  Streams a JSON stats snapshot every second using SSE (`text/event-stream`).
  Implementation uses `futures_util::stream::unfold` — no background task or channel leak.
  When the client disconnects, axum drops the SSE stream and cancels the in-flight sleep.
  `X-Accel-Buffering: no` header ensures nginx proxies events immediately.

- **`GET /upstreams` — upstream DNS health check** (`src/upstreams.rs`, `src/api/mod.rs`)  
  Reports reachability and latency for each configured `forward-addr`.
  Probed every 30 seconds via a minimal RFC 1035 UDP DNS query (17-byte hardcoded packet for `. IN A`).
  2-second per-probe timeout. WARN log on failure. Response includes `healthy` / `total` counts.

- **`GET /logs` — ring buffer query log** (`src/logbuffer.rs`, `src/dns/server.rs`, `src/api/mod.rs`)  
  Captures up to 10,000 recent DNS queries in a fixed-size pre-allocated ring buffer.
  Each `LogEntry` is a fixed-size struct (no heap pointers) — zero allocation after startup.
  Fields: timestamp (RFC 3339 UTC), DNS name, client IP, qtype, action, elapsed ms.  
  Actions: `forwarded`, `cached`, `local`, `blocked`, `nxdomain`, `refused`, `servfail`.  
  Query params: `limit` (default 100, max 1,000), `page` (0-based), `action`, `client` (IP), `since` (Unix timestamp).
  Invalid params return `400 Bad Request`; `limit > 1000` returns `422 Unprocessable Entity`.

- **Slave/master replication** (`src/sync.rs`, `src/config/parser.rs`, `src/api/mod.rs`, `src/main.rs`)  
  Runbound now supports a master/slave topology for high-availability DNS. A master node
  records every write operation (DNS entries, blacklist, feeds) in a delta journal and serves
  it over a dedicated HTTPS sync port. Slave nodes poll the master, apply deltas, and
  rebuild their local zone set on change — with zero API downtime.

  **Architecture:**
  - `SyncJournal` — ring buffer of 1,000 `SyncEvent`s (`VecDeque<SyncEvent>`, monotonic `AtomicU64` seq).
    When a slave falls more than 1,000 events behind, it performs a full config snapshot instead.
  - **Sync endpoints** (master, HTTPS on `sync-port`, separate from REST API):
    - `GET /sync/cert` — returns the master's SHA-256 cert fingerprint (public, no auth required, for TOFU bootstrap).
    - `GET /sync/state` — current journal sequence number.
    - `GET /sync/config` — full state snapshot (DNS + blacklist + feeds + seq). Used on first sync or after 410.
    - `GET /sync/delta?since=N` — events with seq ≥ N. Returns 410 Gone when N is too old.
  - **TOFU TLS** — master auto-generates a self-signed certificate via rcgen (`/etc/runbound/sync-cert.pem`).
    On first slave connect, the cert fingerprint is downloaded from `/sync/cert` and cross-verified
    against the TLS handshake, then saved to `/etc/runbound/sync-master.fingerprint` with a WARN log.
    All subsequent connections use rustls pinned cert verification (SHA-256 of DER). No CA or PKI needed.
  - **Slave read-only** — when `mode: slave`, all non-GET API requests return `503 READ_ONLY`.
    The slave applies changes exclusively via the replication protocol.
  - **Slave feed updates** — on `UpdateFeed` events, the slave re-downloads the same URL stored
    in its local feeds config, without requiring the master to forward feed content.
  - **Exponential backoff** — on network errors, retry delay doubles (5 s → 10 → 20 → … cap 300 s).
    On 410 Gone, a full sync is triggered immediately without waiting for the backoff interval.

  **Configuration (master):**
  ```
  server:
      mode:      master        # default — may be omitted
      sync-port: 8082          # enables HTTPS sync server on 0.0.0.0:8082
      sync-key:  <shared-secret>
  ```

  **Configuration (slave):**
  ```
  server:
      mode:          slave
      sync-master:   192.168.1.10:8082    # master ip:port
      sync-key:      <same-shared-secret>
      sync-interval: 30                   # poll interval in seconds (default: 30)
  ```

### Changed

- **`blocked_percent` — now a float** (`src/api/mod.rs`)  
  Previously rounded to `u64`, now `f64` with one decimal place (e.g. `4.7` instead of `5`).

- **`GET /help` — updated endpoint list** to include `/stats/stream`, `/upstreams`, `/logs`.

---

## [0.2.5] — 2026-05-17

### Security

- **SEC-HIGH-02 — `/help` endpoint now requires Bearer authentication** (`src/api/mod.rs`)  
  `/help` was previously public, exposing the endpoint list and RFCs to unauthenticated callers.
  Fingerprinting a running Runbound instance and cross-referencing with known CVEs is now blocked.
  All endpoints — including `/help` — now require a valid Bearer token.

- **SEC-MED-05 — Global auth-failure counter with automated lockout** (`src/api/mod.rs`)  
  Repeated authentication failures now increment a global `AUTH_FAILURES` AtomicU64 counter.
  Every 10th failure emits a `WARN`-level log. After 50 consecutive failures a 500 ms delay is
  injected before the 401 response, slowing automated guessing without blocking legitimate retries.
  The counter resets on every successful authentication.

- **SEC-HIGH-05 — Rate limiter bucket exhaustion mitigation** (`src/dns/ratelimit.rs`)  
  When the bucket table reaches `MAX_RATE_LIMIT_BUCKETS = 65,536`, the old code silently refused
  all new source IPs — enabling a targeted DoS by flooding from 65 k distinct IPs to fill the table.
  On exhaustion, buckets idle for more than 10 s are now aggressively evicted before dropping the
  new IP. Under a real flood (all buckets active) the drop still fires; under a spoofed exhaustion
  attack with stale buckets, legitimate IPs are admitted after eviction.

- **PENTEST-01 — HTTP feed URLs upgraded from warn to hard reject** (`src/feeds/mod.rs`)  
  SEC-08 (v0.2.0) added a `WARN`-level log for `http://` feed subscriptions but still accepted
  and fetched them. A pentest confirmed that a man-in-the-middle between Runbound and the feed
  server could inject arbitrary block-list entries with no cryptographic protection.
  `validate_feed_url()` now returns `400 Bad Request` for any non-HTTPS URL. HTTP feeds are
  completely blocked at the API layer; the downstream `reqwest` call is never reached.

- **PENTEST-02 — Feed update did not rebuild zone set; blocked stats undercounted** (`src/api/mod.rs`)  
  `POST /feeds/update` and `POST /feeds/:id/update` fetched and cached feed data but never
  called `build_zone_set()`. Feed domains were never added to the active `ArcSwap<LocalZoneSet>`,
  so they were not resolved as blocked and the `/stats` blocked counter was understated.
  Both handlers now call `build_zone_set()` and atomically swap the zone pointer after a
  successful fetch. Feed blocks are effective immediately without a manual `/reload`.

- **PENTEST-03 — CRLF injection in DNS entry text fields** (`src/api/mod.rs`)  
  DNS record fields that are embedded verbatim into zone-file-style RR strings (`value`,
  `tag`, `description`, `fingerprint`, `cert_data`, `services`, `regexp`, `replacement`,
  `flags_naptr`) and the blacklist `description` field accepted arbitrary bytes, including
  `\r` and `\n`. A crafted entry could inject additional resource records into the in-memory
  zone when the RR string was parsed downstream.
  A new `validate_no_control_chars()` helper rejects any byte below `0x20` or equal to
  `0x7f` (DEL) across all affected fields, returning `400 Bad Request`.

- **PENTEST-04 — TTL exceeding RFC 2181 §8 maximum accepted silently** (`src/api/mod.rs`)  
  RFC 2181 §8 defines the maximum DNS TTL as 2,147,483,647 (signed 32-bit maximum).
  `POST /dns` accepted any `u32` TTL (up to ~4.29 billion) and silently capped it at 86,400 s.
  An out-of-range TTL now returns `400 Bad Request` with `INVALID_TTL` before the entry is
  validated further, matching RFC-compliant resolver behaviour.

- **PENTEST-05 — version.bind CHAOS query disclosed server identity** (`src/dns/server.rs`)  
  `dig CHAOS TXT version.bind @<host>` returned identifying information from the underlying
  hickory-server resolver. CHAOS class (`DNSClass::CH`) is now intercepted at the start of
  `handle_request()`, before any zone lookup, and answered with REFUSED.
  The check precedes the existing ANY-query block so it cannot be bypassed by query type.

### Fixed

- **TCP / DoT / DoH / DoQ idle timeout 5 s → 30 s** (`src/dns/server.rs`)  
  The 5-second TCP idle timeout was too aggressive for DNSSEC responses (large RRSIG/DNSKEY
  payloads can take several round-trips). All TCP listeners now use a 30-second timeout.

- **Hand-rolled UTC timestamp replaced with humantime** (`src/feeds/mod.rs`)  
  `utc_now_rfc3339()` implemented a custom date/time calculation (including leap-year arithmetic)
  that had no fuzz coverage and could have edge-case bugs around year boundaries.
  Replaced with `humantime::format_rfc3339(SystemTime::now())` — a well-tested library already
  in the dependency graph.

### Added

- **`GET /health` endpoint** (`src/api/mod.rs`)  
  Liveness probe — returns `{"status":"ok","uptime_secs":…,"queries":…}`.
  Useful for load balancers and monitoring systems. Previously returned HTTP 404.

- **`GET /stats` endpoint** (`src/api/mod.rs`)  
  Query statistics: total, blocked, forwarded, NXDOMAIN, REFUSED, SERVFAIL,
  `blocked_percent`, and `uptime_secs`. Counters are maintained as `AtomicU64` in the
  DNS handler hot path; reads from `/stats` never contend with query processing.
  Previously returned HTTP 404.

- **`GET /config` endpoint** (`src/api/mod.rs`)  
  Dumps the active configuration (sanitised — `api-key` is intentionally omitted).
  Previously returned HTTP 404.

- **`POST /reload` endpoint** (`src/api/mod.rs`)  
  Hot-reload equivalent: re-parses `runbound.conf` and rebuilds all in-memory DNS data
  atomically via ArcSwap. Equivalent to `systemctl reload runbound` (SIGHUP).
  Previously returned HTTP 404.

- **`dnssec-validation` config directive** (`src/config/parser.rs`, `src/dns/server.rs`)  
  Mirrors Unbound's `dnssec-validation` directive. When set to `yes`, hickory-resolver
  performs local DNSSEC re-validation. Default remains `no` (forwarder mode — trust upstream
  AD bit) because forwarders strip RRSIGs and local re-validation would SERVFAIL every
  signed domain. Enable only for full recursive deployments with complete RRSIG chains.

- **`src/stats.rs`** — `Stats` / `StatsSnapshot` types with per-outcome AtomicU64 counters,
  shared between `RunboundHandler` and `AppState` via `Arc<Stats>`.

---

## [0.2.4] — 2026-05-16

### Security

- **SEC-CRIT-03 — IPv6 ULA / link-local addresses bypassed SSRF guard** (`src/feeds/mod.rs`)  
  `is_private_ip()` only covered `::1` and `::`. ULA (`fc00::/7`), link-local (`fe80::/10`),
  IPv4-mapped (`::ffff:0:0/96`), and NAT64 well-known (`100::/64`) ranges were not blocked.
  A feed hostname resolving to `fd00::1` or `fe80::1` bypassed the SSRF check entirely.
  All IPv6 private/internal ranges are now covered.

- **SEC-CRIT-04 — SSRF redirect policy only inspected literal IP destinations** (`src/feeds/mod.rs`)  
  A feed server could redirect to `http://internal.corp/data` and the redirect would be
  followed without any hostname validation. The redirect policy now blocks redirects to
  well-known internal hostnames (`.local`, `.internal`, `.corp`, `.lan`, `localhost`,
  `169.254.169.254`, `metadata.google.internal`).

- **SEC-HIGH-01 — No feed subscription count limit** (`src/api/mod.rs`)  
  An authenticated client could add unlimited feeds. Since each feed can download up to
  100 MiB, this enabled an authenticated DoS via memory/disk exhaustion.
  Hard cap `MAX_FEEDS = 100` is now enforced on `POST /feeds`.

- **SEC-HIGH-03 — Silent fallback to Cloudflare when no forward-zone configured** (`src/dns/server.rs`)  
  Misconfigured or stripped config files caused all queries to be silently routed to
  Cloudflare. A `WARN`-level log is now emitted to alert operators.

- **SEC-MED-04 — XDP frame_mut() had no bounds assertion** (`src/dns/xdp/umem.rs`)  
  A malformed XDP ring descriptor could produce an out-of-bounds write in the XDP fast path.
  `debug_assert!` bounds checks added to `frame_mut()` and `frame()`.

- **SEC-MED-07 — api-key in config file accepted silently** (`src/config/parser.rs`)  
  Using `api-key:` in `runbound.conf` stores the token in cleartext. A `WARN`-level log
  is now emitted directing operators to use `RUNBOUND_API_KEY` in the env file instead.

### Fixed

- **API docs: ghost endpoints removed** (`docs/api.md`)  
  `GET /health`, `GET /stats`, `GET /config`, and `POST /reload` were documented as
  implemented but returned HTTP 404. The docs now accurately reflect the implemented
  endpoints and note the missing ones as open work items.

- **API docs: path parameters corrected** (`docs/api.md`)  
  `DELETE /dns/{name}` and `DELETE /feeds/{name}` used name-based paths in the docs
  but the actual implementation uses UUID (`DELETE /dns/:id`, `DELETE /feeds/:id`).
  `POST /feeds/{name}/refresh` → `POST /feeds/:id/update`. All corrected.

- **systemd.md: SIGHUP table: ACL is NOT reloaded** (`docs/systemd.md`)  
  The hot-reload table incorrectly stated that `access-control` rules are reloaded on
  SIGHUP. The `Arc<Acl>` is built once at startup; only local zones, DNS entries,
  blacklist, and feed entries are reloaded. ACL changes require a full restart.

### Added

- **`docs/security-audit.md`** — Full white-box security audit (23 findings, CRIT→LOW).

---

## [0.2.3] — 2026-05-16

### Fixed

- **`/etc/guestdns/` → `/etc/runbound/`** (`src/feeds/mod.rs`, `src/main.rs`)  
  Feed subscriptions and cache were stored in `/etc/guestdns/feeds.json` and
  `/etc/guestdns/feed_cache/` — a leftover path from the project's internal predecessor.
  All paths are now under `/etc/runbound/`, consistent with every other Runbound data file.
  The `--help` text is also corrected.

- **SIGHUP now hot-reloads zones instead of killing the process** (`src/main.rs`)  
  `systemctl reload runbound` previously terminated the DNS server because SIGHUP had no
  handler and the OS default action (terminate) fired. A `tokio::signal::unix` handler is
  now installed at startup: on SIGHUP, the config file is re-parsed and all local zones,
  persisted DNS entries, blacklist, and feed entries are rebuilt atomically via ArcSwap.
  In-flight DNS queries are not interrupted. `ExecReload=/bin/kill -HUP $MAINPID` in the
  systemd unit file now works correctly.

- **OISD Full preset URL returned HTTP 410 Gone** (`src/feeds/mod.rs`)  
  `https://dbl.oisd.nl/` was deprecated upstream. Updated to `https://big.oisd.nl/`
  (domains format). OISD Basic updated from `https://dbl.oisd.nl/basic/` to
  `https://small.oisd.nl/` (domains format).

- **Local CNAME chain not followed** (`src/dns/server.rs`)  
  A query for `alias.local A` where `alias.local CNAME tardis.local` and
  `tardis.local A 192.168.1.1` were both local-data entries returned an empty answer.
  RFC 1034 §3.6.2 requires the resolver to follow the chain and include all records.
  `follow_local_cname()` now walks up to 8 hops within local zones and returns the
  full CNAME chain + final A/AAAA records in one response.

- **Download URLs in docs were unversioned** (`README.md`, `docs/unbound-migration.md`)  
  Links pointed to `runbound-x86_64-linux-musl` but release assets are named
  `runbound-vX.Y.Z-x86_64-linux-musl`. Following the doc URL caused a 404.
  All references now include the version prefix and note to check the releases page.

- **`/health` documented as public — actually requires Bearer token** (`docs/api.md`)  
  The API reference incorrectly stated "No authentication required" for `GET /health`.
  The endpoint enforces the same auth as all others. Doc corrected.

- **`install.sh` required a local Rust build** (`install.sh`)  
  The installer checked for `./target/release/runbound` and failed for users without
  a Rust toolchain. Rewritten to auto-detect architecture, fetch the versioned binary
  from the GitHub release, verify it with `--version`, and write the systemd unit inline.
  Supports `--version <tag>` for pinned installs. `--uninstall` still works.

---

## [0.2.2] — 2026-05-16

### Added

- **`api-port` directive** (`src/config/parser.rs`, `src/main.rs`)  
  The REST API port is now configurable via the config file (`api-port: 9090`).
  Defaults to `8081` when absent. Removes the hardcoded `API_PORT` constant.

- **`cache-max-ttl` directive** (`src/config/parser.rs`, `src/dns/server.rs`)  
  Maximum TTL cap for cached records is now configurable (`cache-max-ttl: 3600`).
  Defaults to `86400` (24 h) when absent. Removes the hardcoded `MAX_TTL_CAP` constant.
  Mirrors Unbound's `cache-max-ttl` directive.

- **`private-address` directive — DNS rebinding protection** (`src/config/parser.rs`, `src/dns/acl.rs`, `src/dns/server.rs`)  
  CIDR ranges configured with `private-address` are now enforced: if any A or AAAA record
  returned by an upstream resolver falls within a configured private range, the query is
  answered with SERVFAIL instead of forwarding the private IP to the client.
  Mirrors Unbound's `private-address` directive. A new `PrivateAddressSet` type in
  `acl.rs` provides zero-extra-crate CIDR matching using the same bit-shift/mask logic
  as the ACL engine. `CidrBlock` is factored out to avoid code duplication.

- **`forward-tls-upstream` directive — DNS-over-TLS to upstream** (`src/config/parser.rs`, `src/dns/server.rs`)  
  Adding `forward-tls-upstream: yes` to a `forward-zone:` block now sends queries to
  upstream resolvers over an encrypted TLS connection (port 853 by default, overridable
  with `addr@port` syntax). Without the directive, plain UDP+TCP is used (existing behaviour).
  Mirrors Unbound's `forward-tls-upstream` directive.

---

## [0.2.1] — 2026-05-16

### Performance

- **OPT-01 — Eliminate `Name::from(qname.clone())` on every DNS query** (`src/dns/local.rs`, `src/dns/server.rs`)
  `LocalZoneSet::find()`, `local_records()`, and `name_has_records()` now accept `&LowerName`
  directly instead of `&Name`. Previously, every incoming query paid two heap allocations
  (clone `LowerName` + `Name::from`) before the first zone lookup. The hot path now uses
  `LowerName: Borrow<Name>` to perform the `HashMap` lookup with zero allocation.
  The walk-up hierarchy path (`find()` parent-zone traversal) uses `LowerName::base_name()`
  end-to-end, avoiding an additional `Name` clone per label trimmed.
  The XDP fast path benefits from the same change with no callsite modification.

### Fixed

- **`*response_code` in resolver error path** (`src/dns/server.rs`)
  `ResolveErrorKind::NoRecordsFound::response_code` binds as `&ResponseCode` under match
  ergonomics. The dereference was correct but the compiler's error reporting was misleading
  when other errors were present in the same compilation unit. Confirmed and preserved as-is.

---

## [0.2.0] — 2026-05-16

### Security

- **SEC-01 — Race condition on concurrent API writes** (`src/api/mod.rs`)  
  `store::load` / `store::save` are now performed inside the `zones_mutex` critical section, making the entire read→validate→write→swap sequence atomic. Previously two concurrent `POST /dns` requests could both read the same snapshot and one silently overwrite the other.

- **SEC-02 — XDP fast-path bypassed ACL entirely** (`src/dns/xdp/worker.rs`)  
  The AF_XDP worker answered DNS queries without consulting the ACL. An attacker on a refused subnet could bypass the access-control policy by sending raw UDP on an XDP-attached interface. ACL is now checked in `answer_dns()` before any zone lookup; `Deny` → silent drop, `Refuse` → crafts a REFUSED DNS frame.

- **SEC-03 — IPv4-mapped IPv6 addresses skipped ACL rules** (`src/dns/acl.rs`)  
  A client connecting over IPv6 with address `::ffff:10.0.0.1` would not match the IPv4 `10.0.0.0/8` allow entry and would fall through to the default `Refuse`. Address normalisation now maps `::ffff:a.b.c.d` → `a.b.c.d` before matching, ensuring consistent ACL behaviour across transports.

- **SEC-04 — SSRF via HTTP redirect** (`src/feeds/mod.rs`)  
  `reqwest` follows redirects by default. A malicious feed server could redirect to `http://169.254.169.254/` (cloud metadata) or any private IP. A custom redirect `Policy` now blocks HTTPS→HTTP downgrades and redirects whose destination resolves to a private or loopback address.

- **SEC-05 — TOCTOU on feed URL validation** (`src/feeds/mod.rs`)  
  Feed URLs were validated once at subscription time; subsequent `update_feed()` calls reused the stored URL without re-checking. A race between subscribe and first fetch, or a compromised feed record, could bypass validation. `update_feed()` now re-validates the URL on every invocation.

- **SEC-06 — Unbounded data-store growth** (`src/api/mod.rs`)  
  No limit was enforced on the number of DNS entries or blacklist entries. An authenticated client could fill disk / exhaust memory. Limits are now enforced: `MAX_DNS_ENTRIES = 10 000`, `MAX_BLACKLIST_ENTRIES = 100 000`; `POST` requests beyond the limit return `422 Unprocessable Entity`.

- **SEC-07 — Feed data files world-readable** (`src/feeds/mod.rs`)  
  Serialised feed files were created with the process umask (typically `0644`). Feeds may contain sensitive block-list intelligence. A `chmod 640` is now applied after each atomic rename so files are readable only by owner and group.

- **SEC-08 — Plaintext HTTP feeds** (`src/feeds/mod.rs`)  
  HTTP feed URLs were silently accepted. A `WARN`-level log is now emitted for any `http://` feed URL, flagging the man-in-the-middle injection risk.

### Changed

- ACL logic extracted into a dedicated `src/dns/acl.rs` module with a public `Acl` / `AclAction` API, shared by both the hickory-server path and the XDP worker.
- `run_dns_server()` and `start_xdp()` now accept an `Arc<Acl>` built once in `main()` and shared across all paths.
- Version bumped to `0.2.0` in `Cargo.toml`.

### Added

- `examples/home.conf` — Home / Pi-hole replacement configuration.
- `examples/office.conf` — SMB office split-horizon DNS configuration.
- `examples/server.conf` — Public/shared recursive resolver configuration.
- `examples/secure.conf` — High-security / air-gapped / military-grade configuration.
- `README.md` — Comprehensive GitHub documentation: installation, configuration reference, full REST API reference, performance benchmarks, security architecture, systemd setup, XDP fast-path guide, Unbound compatibility table, and sysadmin-oriented comparison.
- `.gitignore` — Comprehensive ignore rules covering build artefacts, PGO data, TLS secrets, editor files, and test artefacts.

---

## [0.1.0] — 2026-04-01

### Added

- High-performance DNS server written in Rust, drop-in replacement for Unbound.
- Unbound-compatible configuration file parser (`server:`, `forward-zone:`, `local-zone:`, `local-data:`, `access-control:` directives).
- UDP + TCP DNS on port 53; DNS-over-TLS on port 853.
- REST API on port 8081 with Bearer-token authentication (`subtle::ConstantTimeEq` timing-safe comparison).
- AF_XDP kernel-bypass fast path for high-throughput deployments (`--features xdp`).
- Token-bucket rate limiter (`DashMap<IpAddr, IpBucket>` with `ahash`) shared between hickory and XDP paths.
- Inflight-request semaphore (`MAX_INFLIGHT_REQUESTS = 4096`) providing a hard OOM backstop under flood conditions.
- Lock-free `ArcSwap<LocalZoneSet>` for zero-contention zone data reads on the hot path.
- `SO_REUSEPORT` with 32 UDP sockets per CPU for parallel UDP handling.
- REST API endpoints:
  - `GET  /health` — liveness probe
  - `GET  /dns`   — list all local DNS entries
  - `POST /dns`   — add a local DNS entry
  - `DELETE /dns/{name}` — remove a local DNS entry
  - `GET  /blacklist` — list blacklisted domains
  - `POST /blacklist` — add a domain to the blacklist
  - `DELETE /blacklist/{domain}` — remove a domain from the blacklist
  - `GET  /feeds` — list configured feed subscriptions
  - `POST /feeds` — subscribe to a remote block-list feed
  - `DELETE /feeds/{name}` — remove a feed subscription
  - `POST /feeds/{name}/refresh` — force immediate feed refresh
  - `GET  /stats` — query statistics (total, blocked, forwarded, NXDOMAIN)
  - `GET  /config` — dump active configuration (sanitised — no secrets)
  - `POST /reload` — hot-reload configuration without restart
- Persistent JSON store for DNS entries, blacklist, and feed subscriptions; atomic file writes via rename.
- Feed auto-refresh scheduler with configurable interval.
- Systemd service file template.

---

[0.3.1]: https://github.com/redlemonbe/Runbound/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/redlemonbe/Runbound/compare/v0.2.5...v0.3.0
[0.2.5]: https://github.com/redlemonbe/Runbound/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/redlemonbe/Runbound/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/redlemonbe/Runbound/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/redlemonbe/Runbound/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/redlemonbe/Runbound/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/redlemonbe/Runbound/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/redlemonbe/Runbound/releases/tag/v0.1.0
