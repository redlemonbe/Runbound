# Runbound — Security Audit Report

**Version audited:** 0.2.3 (initial audit) — findings tracked through v0.4.16 live pentest  
**Last updated:** 2026-05-19  
**Scope:** Full source review — DNS engine, REST API, feed subsystem, ACL, rate limiter, XDP fast-path, persistence layer, TLS, configuration parser, HSM integration  
**Methodology:** Manual white-box source code review of all Rust modules + external penetration test (v0.4.4)

---

## Executive Summary

**57 findings across 7 audit cycles — 55 resolved, 2 open (targeted v0.4.17).**

| Cycle | Target | Findings | Status |
|---|---|---|---|
| Live pentest | v0.4.16 | 2 bugs + 13 PASS + 2 observations | ⚠️ 2 bugs open → v0.4.17 |
| Pre-release white-box | v0.4.16 | 5 (2 Medium, 3 Low) | ✅ All fixed v0.4.16 |
| Initial white-box | v0.2.3 | 20 (4 Critical, 8 High, 5 Medium, 3 Low) | ✅ All fixed v0.2.4–v0.4.0 |
| Second white-box | v0.3.3 | 9 (1 High, 6 Medium, 2 Low) | ✅ All fixed v0.3.3–v0.3.5 |
| Third white-box | v0.4.0 | 8 (1 Blocking, 2 Medium, 5 Low) | ✅ All fixed v0.4.1 |
| IA audit | v0.4.1 | 9 (3 Low, 3 Info, 2 Doc, 1 false positive) | ✅ All closed v0.4.3 |
| External pentest | v0.4.4 | 4 (1 High, 1 Medium/false positive, 1 Low, 1 Info) | ✅ All closed v0.4.5 |

Runbound's core DNS path is well-engineered: memory-safe Rust, lock-free hot path
via ArcSwap, per-IP token-bucket rate limiting with aggressive eviction, RFC 8482
ANY-query blocking, IPv4-mapped IPv6 normalisation in the ACL, HMAC-SHA256 audit
chain, and constant-time Bearer comparison (timing oracle fixed in v0.4.0 and
re-hardened in v0.4.5 by moving the brute-force brake to before the comparison).

The four original critical findings (ghost API endpoints, DNSSEC unconditionally
disabled, IPv6 SSRF bypass, SSRF hostname-redirect bypass) and all high-severity
findings from the initial audit have been resolved across v0.2.4, v0.2.5, and v0.3.x.
A second audit cycle targeting v0.3.3 identified eight additional findings (SEC-09
through SEC-16), all fixed in v0.3.3.

**All HIGH and MEDIUM findings are closed. 2 LOW bugs from the v0.4.16 live pentest are open and targeted for v0.4.17 (VUL-3.2 rate limit not wired, VUL-6.2 cap not enforced on non-loopback).**

- JSON store HMAC-SHA256 integrity (HIGH-06) — `RUNBOUND_STORE_KEY` env var, sidecar `.mac` files.
- TLS cipher suite hardening (HIGH-07) — hickory 0.26 + rustls 0.23, TLS 1.3 default.
- DoT mutual TLS (HIGH-08) — `dot-client-auth-ca` directive + `WebPkiClientVerifier`.
- SSRF at connection layer (MED-03) — custom `reqwest::dns::Resolve` filtering private IPs.
- qname log injection (MED-06) — `sanitize_dns_name()` strips control chars before structured logging.
- Config entry cap (LOW-03) — 1,000,000 limit on `local-zone` / `local-data`.

---

## Severity Classification

| Rating | Criteria |
|---|---|
| **CRITICAL** | Exploitable without authentication, or completely breaks a documented security guarantee |
| **HIGH** | Exploitable with authentication, or silently breaks operational correctness |
| **MEDIUM** | Reduces defence-in-depth; exploitable under specific conditions |
| **LOW** | Best-practice gap; no direct exploitability |
| **INFO** | Architectural note for hardened deployments |

---

## Initial Audit Cycle — v0.2.3

### Critical Findings

#### AUDIT-CRIT-01 — Ghost API endpoints (404 in production)

**File:** `src/api/mod.rs`, `docs/api.md`  
**Status:** ✅ Fixed in v0.2.5 — all four endpoints implemented

The following endpoints appeared in the documentation but had no handler in the
actual router: `GET /health`, `GET /stats`, `GET /config`, `POST /reload`.
All returned HTTP 404, breaking monitoring probes, Prometheus scrapers, and the
documented REST reload path. Path parameter mismatches (`{name}` vs `:id`) caused
all DELETE operations to return 404.

All four endpoints implemented in v0.2.5. Path parameters corrected in documentation.

---

#### AUDIT-CRIT-02 — DNSSEC validation unconditionally disabled

**File:** `src/dns/server.rs`  
**Status:** ✅ Mitigated in v0.2.5 — `dnssec-validation` directive added

```rust
// v0.2.3 — hardcoded
opts.validate = false;
```

Runbound trusted the AD bit set by upstream resolvers without local re-validation.
A compromised upstream could serve forged responses with AD=1.

`dnssec-validation: yes` now sets `opts.validate = true` and the DNSSEC stats
counters (`secure`, `bogus`, `insecure`) are tracked per-query. Operators running
a DNSSEC-validating recursive resolver upstream (Unbound, BIND) and enabling this
directive get local chain verification. Default remains `no` for compatibility with
enterprise forwarders that strip DNSSEC records.

---

#### AUDIT-CRIT-03 — IPv6 ULA/link-local addresses bypass SSRF guard

**File:** `src/feeds/mod.rs`  
**Status:** ✅ Fixed in v0.2.4

`is_private_ip()` only checked `::1` (loopback) and `::` (unspecified). The
following IPv6 ranges were not blocked: `fc00::/7` (ULA, `fd00::x` common in
enterprise networks), `fe80::/10` (link-local), `::ffff:0:0/96` (IPv4-mapped).

Current implementation (v0.3.5):

```rust
std::net::IpAddr::V6(v6) => {
    let s = v6.segments();
    v6.is_loopback() || v6.is_unspecified()
    || (s[0] & 0xfe00) == 0xfc00   // ULA fc00::/7
    || (s[0] & 0xffc0) == 0xfe80   // link-local fe80::/10
    || (s[0] == 0x2001 && s[1] == 0x0db8)  // documentation
}
```

---

#### AUDIT-CRIT-04 — SSRF redirect guard only checked literal IPs, not hostnames

**File:** `src/feeds/mod.rs`  
**Status:** ✅ Fixed in v0.2.4

The redirect policy only called `is_private_ip()` when the redirect destination
parsed as a literal `IpAddr`. A redirect to `http://internal.corp/data` passed
`host.parse::<IpAddr>()` fails, so `attempt.follow()` was called unconditionally.

Fix: the reqwest redirect policy now resolves hostname destinations before following.
TOCTOU re-validation (SEC-05) also added — URL is re-validated on every fetch, not
just at subscription time.

---

### High Findings

#### AUDIT-HIGH-01 — No feed subscription count limit (authenticated DoS)

**File:** `src/api/mod.rs`, `src/feeds/mod.rs`  
**Status:** ✅ Fixed in v0.2.4 (`MAX_FEEDS = 100`)

No upper bound on feed subscriptions — each feed could download up to 100 MiB,
enabling an authenticated client to trigger unbounded network I/O. Cap of 100
subscriptions enforced in v0.2.4.

---

#### AUDIT-HIGH-02 — `/help` endpoint information disclosure (unauthenticated)

**File:** `src/api/mod.rs`  
**Status:** ✅ Fixed in v0.2.5 — Bearer authentication required

Previously returned exact version string, endpoint list, RFC claims, and author
identity without authentication, enabling version fingerprinting for targeted
exploitation. All endpoints now require Bearer token.

---

#### AUDIT-HIGH-03 — Silent fallback to Cloudflare when no `forward-zone` configured

**File:** `src/dns/server.rs`  
**Status:** ✅ Mitigated in v0.2.4 — loud WARN log emitted

If the config has no `forward-zone:` block, all DNS queries fall back to Cloudflare
(1.1.1.1/1.0.0.1) over plain UDP. For classified deployments this is a data exfiltration
risk. A startup WARN is now logged. Operators should always configure explicit
`forward-zone:` blocks.

---

#### AUDIT-HIGH-04 — ACL not reloaded on SIGHUP (documentation wrong)

**File:** `src/main.rs`, `docs/systemd.md`  
**Status:** ✅ Fixed in v0.2.5 — documentation corrected

The SIGHUP handler reloads DNS zones but the `Arc<Acl>` is built once at startup.
The `systemd.md` hot-reload table erroneously stated that `access-control` rules
are reloaded on SIGHUP. Table corrected — ACL change requires restart.

---

#### AUDIT-HIGH-05 — Rate limiter bucket exhaustion under UDP source IP spoofing

**File:** `src/dns/ratelimit.rs`  
**Status:** ✅ Mitigated — aggressive eviction on bucket table full

UDP source IP spoofing can fill the bucket table (65,536 entries). Original
implementation refused new IPs when full, including legitimate clients.

Current implementation evicts idle entries (last seen > 10 s) before refusing.
If still full after eviction, the flood is active and the drop is intentional.
Network-layer controls (BCP38 ingress filtering) remain the correct primary
defence.

---

#### AUDIT-HIGH-06 — JSON data stores have no integrity protection

**File:** `src/store.rs`, `src/feeds/mod.rs`, `src/integrity.rs`  
**Status:** ✅ Fixed in v0.4.0 — HMAC-SHA256 sidecar `.mac` files

`dns_entries.json`, `blacklist.json`, and `feeds.json` are stored as cleartext JSON
(mode 0640). An attacker with filesystem write access can inject arbitrary DNS
records without touching the API, bypassing authentication, rate limiting, and entry
count limits.

**Fix:** Set `RUNBOUND_STORE_KEY` (hex-encoded 32+ bytes or any UTF-8 string). On every
write, `src/integrity.rs` computes `HMAC-SHA256(content, key)` and writes it to a
sidecar `.mac` file (e.g. `dns_entries.mac`). On every load, the HMAC is verified
before deserialization:
- `.mac` missing, key set → WARN, load proceeds (backwards compatibility).
- `.mac` present, mismatch → ERROR, load refused, server exits.
- `.mac` present, key unset → WARN, load proceeds (cannot verify).

Domain cache files (per-feed `.json`) are regeneratable from the internet; HMAC mismatch
discards the cache (WARN) and triggers a re-fetch on next update cycle.

---

#### AUDIT-HIGH-07 — TLS cipher suites inherit rustls 0.21 defaults

**File:** `Cargo.toml`, `src/dns/server.rs`  
**Status:** ✅ Fixed in v0.4.0 — hickory 0.26 + rustls 0.23, TLS 1.3 default

`rustls 0.21` (pulled by hickory-server 0.24) enabled TLS 1.2 + cipher suites
below BSI TR-02102 / NIST SP 800-52 Rev 2. Upgraded to hickory-server 0.26 + rustls 0.23.
DoQ uses `ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])` —
Quinn rejects configs that permit TLS 1.2. DoT and DoH use the rustls 0.23 default
which offers TLS 1.3 by preference. Six hickory-proto CVEs (RUSTSEC-2026-0119,
RUSTSEC-2026-0037, RUSTSEC-2025-0009, RUSTSEC-2026-0104, RUSTSEC-2026-0098,
RUSTSEC-2026-0099) resolved. All ignores removed from `audit.toml`.

---

#### AUDIT-HIGH-08 — No mTLS for DoT client authentication

**File:** `src/dns/server.rs`, `src/config/parser.rs`  
**Status:** ✅ Fixed in v0.4.0 — `dot-client-auth-ca` + `WebPkiClientVerifier`

DoT uses server-only TLS by default. Mutual TLS is now enabled with:

```
server:
    dot-client-auth-ca: "/etc/runbound/client-ca.pem"
```

`build_tls_config()` detects the CA path and builds a `WebPkiClientVerifier` via
`rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build()?`.
The DoT `ServerConfig` is then constructed with `with_client_cert_verifier(verifier)`.
DoH and DoQ are unaffected (they authenticate via application-layer tokens).
When `dot-client-auth-ca` is absent, DoT falls back to server-only authentication.

---

### Medium Findings

#### AUDIT-MED-01 — Feed parser accepts underscore labels

**File:** `src/feeds/mod.rs`  
**Status:** ✅ Accepted — intentional RFC relaxation, documented

`is_valid_domain()` requires at least one dot but allows underscore labels
(`_dmarc.example.com`). RFC 1035 §2.3.1 disallows underscores in host labels, but
service labels use them by convention (RFC 2782/6763). Blocklist pragmatism takes
precedence. No action required.

---

#### AUDIT-MED-02 — TOCTOU window in feed URL validation

**File:** `src/feeds/mod.rs`  
**Status:** ✅ Mitigated — SEC-05 (v0.2.0) + re-validation on every fetch (v0.3.0)

`validate_feed_url()` resolves the hostname then reqwest re-resolves for the actual
TCP connection. DNS rebinding with TTL=0 could switch the A record in that window
(< 10 ms). URL is now re-validated on every fetch, not just at subscription time,
closing the window for pre-subscribed records. Residual risk requires attacker
control of both the feed's DNS zone and precise millisecond timing.

---

#### AUDIT-MED-03 — SSRF hostname resolution uses system resolver

**File:** `src/feeds/mod.rs`  
**Status:** ✅ Fixed in v0.4.0 — `SsrfSafeDnsResolver` implements `reqwest::dns::Resolve`

`validate_feed_url()` uses `tokio::net::lookup_host()` which resolves via
`/etc/resolv.conf`. On a Runbound host that is its own resolver, this creates a
loop, and the system resolver is not guaranteed to give accurate SSRF-blocking
results.

**Fix:** `SsrfSafeDnsResolver` implements `reqwest::dns::Resolve` and is installed
via `Client::builder().dns_resolver(Arc::new(SsrfSafeDnsResolver))`. On every TCP
connection, the resolver calls `tokio::net::lookup_host`, filters all returned
`SocketAddr`s through `is_private_ip()`, and returns an error if no public address
remains. This operates at the network layer — independent of `validate_feed_url()`
and active on every redirect followed by the client.

---

#### AUDIT-MED-04 — XDP `frame_mut()` had no bounds enforcement

**File:** `src/dns/xdp/umem.rs`  
**Status:** ✅ Fixed in v0.2.4 — `debug_assert!` bounds checks added

```rust
debug_assert!(
    (offset as usize) + len <= self.area_len,
    "XDP frame_mut: offset {offset} + len {len} exceeds UMEM size {}",
    ...
);
```

---

#### AUDIT-MED-05 — No authentication failure rate limiting

**File:** `src/api/mod.rs`  
**Status:** ✅ Fixed in v0.2.5 — 500 ms async delay after each failure

`AUTH_FAILURES` global counter increments on every failed authentication.
A 500 ms `tokio::time::sleep` is injected after each failed attempt, reducing
brute-force throughput from 30 req/s to 2 req/s. Counter resets on successful
authentication.

---

#### AUDIT-MED-06 — Log injection via structured DNS query names

**File:** `src/dns/server.rs`  
**Status:** ✅ Fixed in v0.4.0 — `sanitize_dns_name()` strips control characters

DNS query names are emitted verbatim as structured log fields. With JSON output
(`RUST_LOG=json`), a crafted name containing `"` or `}` could break downstream
log consumers (Elasticsearch, Splunk).

**Fix:** `sanitize_dns_name(name: &LowerName) -> String` replaces any ASCII control
character (0x00–0x1F, 0x7F) with `?` before the name is used in any `tracing` macro.
Non-ASCII bytes are also replaced with `?`. The function is called on every query before
the structured log event is emitted, ensuring the logged field is always printable ASCII.

---

#### AUDIT-MED-07 — `api-key` stored cleartext in `runbound.conf`

**File:** `src/config/parser.rs`  
**Status:** ✅ Mitigated in v0.2.4 — WARN log when `api-key:` is used in config

Production deployments should set `RUNBOUND_API_KEY` via environment variable (systemd
`EnvironmentFile`, Docker secret) rather than the config file. A WARN is logged at
startup when the config-file `api-key:` directive is used.

---

### Low Findings

#### AUDIT-LOW-01 — Hand-rolled UTC timestamp in `feeds/mod.rs`

**File:** `src/feeds/mod.rs`  
**Status:** ✅ Fixed in v0.2.5 — replaced with `humantime::format_rfc3339`

30-line custom Gregorian calendar implementation replaced by `humantime` (already a
dependency), eliminating leap year edge case risk.

---

#### AUDIT-LOW-02 — `/help` exposes author identity and repository URL (unauthenticated)

**File:** `src/api/mod.rs`  
**Status:** ✅ Fixed in v0.2.5 — endpoint requires Bearer authentication

See AUDIT-HIGH-02.

---

#### AUDIT-LOW-03 — No cap on `local-zone` / `local-data` entries in config

**File:** `src/config/parser.rs`  
**Status:** ✅ Fixed in v0.4.0 — `MAX_LOCAL_ZONES = MAX_LOCAL_DATA = 1_000_000`

The config parser now enforces a 1,000,000 entry limit for both `local-zone:` and
`local-data:` directives. When the limit is reached, subsequent entries are silently
dropped and a WARN is emitted: `local-zone limit (1000000) reached — entry ignored`.
This prevents accidental OOM from pathological configs while supporting any realistic
deployment size (1M entries ≈ 200 MiB of zone data at 200 bytes average).

---

#### AUDIT-LOW-04 — TCP idle timeout too short for high-latency DoT

**File:** `src/dns/server.rs`  
**Status:** ✅ Fixed in v0.2.5 — TCP timeout raised to 30 s (RFC 7858 §3.5)

---

---

## Second Audit Cycle — v0.3.3

The following eight findings were identified during the v0.3.3 audit and all fixed
in the same release. They are cross-referenced as SEC-09 through SEC-16 in
[`docs/security.md`](security.md).

---

### SEC-09 (High) — `POST /rotate-key` was a silent no-op

**File:** `src/api/mod.rs`  
**Status:** ✅ Fixed in v0.3.3

The handler read `RUNBOUND_API_KEY` from `std::env::var()`, which is frozen at
process startup. Updating the systemd `EnvironmentFile` and calling `POST /rotate-key`
appeared to succeed (HTTP 200) but the in-memory key was never updated. The new key
was unreachable until restart.

**Fix:** `POST /rotate-key` now accepts `{"new_key": "<32+ chars>"}` in the request
body and atomically swaps the live key via `ArcSwap<String>`. The old key remains
valid until the swap completes (zero downtime). The new key is written to
`/etc/runbound/api.key` with `chmod 600`.

---

### SEC-10 (Medium) — CHAOS class queries returned NOERROR

**File:** `src/dns/server.rs`  
**Status:** ✅ Fixed in v0.3.3 — confirmed correct in v0.3.5 pentest re-test

CHAOS class queries (`version.bind CH TXT`, `hostname.bind CH TXT`) expose server
identity and are used for DNS fingerprinting. RFC 5358 §4 specifies that resolvers
which do not implement CHAOS SHOULD return NOTIMP.

The check was added in v0.3.3:

```rust
if u16::from(request.query().query_class()) == 3 {
    return send_error(request, response_handle, ResponseCode::NotImp).await;
}
```

**Pentest note (v0.3.5):** A subsequent pentest reported NOERROR for
`version.bind CH TXT`. Root-cause analysis confirmed the test tool was querying the
system Unbound daemon on port 53, not Runbound on port 5353. Direct test against
Runbound confirms `status: NOTIMP`.

---

### SEC-11 (Medium) — Body limit dropped TCP instead of returning HTTP 413

**File:** `src/api/mod.rs`  
**Status:** ✅ Fixed in v0.3.3

Payloads above axum's default `DefaultBodyLimit` caused the middleware to drop the
TCP connection without sending a response. Clients (including `curl`) reported
"connection reset" rather than a structured error.

**Fix:** Explicit `DefaultBodyLimit::max(65_536)` (64 KiB). axum returns HTTP 413
`Content Too Large` with a JSON body before reading oversized payloads into RAM.

---

### SEC-12 (Medium) — Negative TTL caused `unwrap()` panic

**File:** `src/api/mod.rs`  
**Status:** ✅ Fixed in v0.3.3

`POST /dns` with `{"ttl": -1}` caused a `u32::try_from` failure that propagated
as an `unwrap()` panic, crashing the handler task. Clients received a 500 with no
JSON body.

**Fix:** TTL is validated in range 0–2,147,483,647 (RFC 2181 §8) before conversion.
Out-of-range values return HTTP 422 `INVALID_TTL`.

---

### SEC-13 (Medium) — Production `unwrap()` / `expect()` in request handlers

**File:** `src/api/mod.rs`, `src/feeds/mod.rs`  
**Status:** ✅ Fixed in v0.3.3

Several request-path functions used `unwrap()` and `expect()` on fallible operations
(lock acquisition, JSON serialisation, store reads). A poisoned mutex or corrupt
store would crash the handler task, and in some paths the entire process via
`Mutex::lock().unwrap()`.

**Fix:** All `unwrap()` / `expect()` in handler paths replaced with `?` or explicit
match arms that return HTTP 500 or 503 with structured JSON error responses.

---

### SEC-14 (Medium) — Sync Bearer comparison was timing-vulnerable

**File:** `src/api/mod.rs`  
**Status:** ✅ Fixed in v0.3.3

The authentication middleware compared Bearer tokens with a synchronous string
equality check that short-circuits on the first differing byte. With sufficiently
precise timing measurements, an attacker could determine the number of correct prefix
characters.

**Fix:** Comparison replaced with `subtle::ConstantTimeEq` (constant-time byte-by-byte
comparison, no early exit). The `subtle` crate is designed specifically to prevent
timing side-channels.

---

### SEC-15 (Low) — Feed URLs with embedded credentials not rejected

**File:** `src/feeds/mod.rs`  
**Status:** ✅ Fixed in v0.3.3

Feed URLs containing `user:pass@host` were accepted and stored in `feeds.json` at
rest. The credentials were sent in the `Authorization` header on every fetch and
could be logged by the upstream feed server.

**Fix:** `validate_feed_url()` rejects URLs containing `@` in the host component
(userinfo present) with HTTP 400 before any network request.

---

### SEC-16 (Low) — `rate-limit: u64::MAX` silently disabled rate limiting

**File:** `src/config/parser.rs`, `src/dns/ratelimit.rs`  
**Status:** ✅ Fixed in v0.3.3

Setting `rate-limit:` to `u64::MAX` or any value that overflowed `u64` when
doubled (for burst calculation) silently disabled the rate limiter without warning.

**Fix:** Values above 10,000,000 (10M qps) are capped at 10M and a WARN is logged.
`rate-limit: 0` explicitly disables the limiter with an explicit WARN at startup.

---

---

## v0.3.5 Fix

### GET /config missing `log_retention` / `log_client_ip`

**File:** `src/api/mod.rs`  
**Status:** ✅ Fixed in v0.3.5

The two GDPR privacy directives added in v0.3.4 (`log-retention`, `log-client-ip`)
were not exposed in the `GET /config` snapshot endpoint. All other runtime parameters
are visible; the omission was an incomplete rebuild (binary pre-dated the source
change). Both fields appear in the config response from v0.3.5 onward:

```json
"log_client_ip": true,
"log_retention": 1000
```

---

---

## Informational Notes

### AUDIT-INFO-01 — Single shared API key, no roles

There is one API key shared by all operators. No per-operator keys, no read-only
vs. read-write separation, no per-key audit attribution. For multi-operator
deployments, individual operator keys with per-key audit logs are required.

### AUDIT-INFO-02 — No OCSP stapling for DoT certificates

The TLS configuration does not implement OCSP stapling. DoT clients performing
certificate revocation checks incur additional round-trip latency. For production
DoT, use Let's Encrypt certificates with OCSP stapling enabled in the TLS stack.

### AUDIT-INFO-03 — Memory pressure guard requires `/proc/meminfo`

The 30-second memory check reads `/proc/meminfo` (Linux-only). On systems or
containers without `/proc/meminfo`, the guard silently skips — DNS service continues
normally. A WARN is logged on the first missed check.

### AUDIT-INFO-04 — XDP fast path is safe-by-design for query forwarding

The AF_XDP worker correctly falls through to the kernel (hickory-server) for
recursive queries, ANY queries, and malformed frames. ACL-denied sources receive a
crafted REFUSED frame in-kernel. There is no data exfiltration risk from the XDP path.

---

## Finding Summary

### Initial Audit (v0.2.3) — status as of v0.4.0

| ID | Severity | Component | Status |
|---|---|---|---|
| CRIT-01 | CRITICAL | API | ✅ Fixed v0.2.5 |
| CRIT-02 | CRITICAL | DNSSEC | ✅ Mitigated v0.2.5 — `dnssec-validation` directive |
| CRIT-03 | CRITICAL | SSRF/IPv6 | ✅ Fixed v0.2.4 |
| CRIT-04 | CRITICAL | SSRF/redirect | ✅ Fixed v0.2.4 |
| HIGH-01 | HIGH | Feeds | ✅ Fixed v0.2.4 — MAX_FEEDS = 100 |
| HIGH-02 | HIGH | API | ✅ Fixed v0.2.5 — /help requires Bearer |
| HIGH-03 | HIGH | DNS | ✅ Mitigated v0.2.4 — startup WARN |
| HIGH-04 | HIGH | Reload | ✅ Fixed v0.2.5 — docs corrected |
| HIGH-05 | HIGH | RateLimit | ✅ Mitigated — aggressive eviction on flood |
| HIGH-06 | HIGH | Storage | ✅ Fixed v0.4.0 — HMAC-SHA256 sidecar `.mac` files |
| HIGH-07 | HIGH | TLS | ✅ Fixed v0.4.0 — hickory 0.26 + rustls 0.23, TLS 1.3 |
| HIGH-08 | HIGH | TLS/DoT | ✅ Fixed v0.4.0 — `dot-client-auth-ca` mTLS |
| MED-01 | MEDIUM | Feeds | ✅ Accepted — intentional RFC relaxation |
| MED-02 | MEDIUM | SSRF/TOCTOU | ✅ Mitigated — re-validation on every fetch |
| MED-03 | MEDIUM | SSRF | ✅ Fixed v0.4.0 — `SsrfSafeDnsResolver` at connect time |
| MED-04 | MEDIUM | XDP | ✅ Fixed v0.2.4 — debug_assert bounds |
| MED-05 | MEDIUM | API auth | ✅ Fixed v0.2.5 — 500 ms lockout per failure |
| MED-06 | MEDIUM | Logging | ✅ Fixed v0.4.0 — `sanitize_dns_name()` |
| MED-07 | MEDIUM | Config | ✅ Mitigated v0.2.4 — WARN on api-key in config |
| LOW-01 | LOW | Feeds | ✅ Fixed v0.2.5 — humantime::format_rfc3339 |
| LOW-02 | LOW | API | ✅ Fixed v0.2.5 — /help requires Bearer |
| LOW-03 | LOW | Config | ✅ Fixed v0.4.0 — 1,000,000 entry cap |
| LOW-04 | LOW | DNS/TLS | ✅ Fixed v0.2.5 — TCP timeout 30 s |

### Second Audit Cycle (v0.3.x) — status as of v0.3.5

| ID | Severity | Component | Status |
|---|---|---|---|
| SEC-09 | HIGH | API | ✅ Fixed v0.3.3 — /rotate-key JSON body + ArcSwap |
| SEC-10 | MEDIUM | DNS | ✅ Fixed v0.3.3 — CHAOS → NOTIMP (confirmed v0.3.5) |
| SEC-11 | MEDIUM | API | ✅ Fixed v0.3.3 — DefaultBodyLimit → HTTP 413 |
| SEC-12 | MEDIUM | API | ✅ Fixed v0.3.3 — negative TTL → HTTP 422 |
| SEC-13 | MEDIUM | API | ✅ Fixed v0.3.3 — unwrap() → structured errors |
| SEC-14 | MEDIUM | API auth | ✅ Fixed v0.3.3 — subtle::ConstantTimeEq |
| SEC-15 | LOW | Feeds | ✅ Fixed v0.3.3 — credential URL rejected |
| SEC-16 | LOW | RateLimit | ✅ Fixed v0.3.3 — u64::MAX capped at 10M |

### v0.3.5 Fix

| ID | Severity | Component | Status |
|---|---|---|---|
| CONF-01 | LOW | API | ✅ Fixed v0.3.5 — /config exposes log_retention + log_client_ip |

---

### v0.4.1 Audit Findings (IA audit on v0.4.0)

| ID | Severity | Component | Status |
|---|---|---|---|
| BUG-01 | BLOCKING | Sync/TLS | ✅ Fixed v0.4.1 — CryptoProvider install in main() |
| S-10 | MEDIUM | API/DNS | ✅ Fixed v0.4.1 — validate_dns_name on CNAME/MX/NS/PTR/SRV values |
| S-11 | LOW | API | ✅ Fixed v0.4.1 — Content-Length check before rate limit (413 not 429) |
| Q-01 | LOW | API | ✅ Fixed v0.4.1 — ApiJson extractor: JSON body on POST /dns rejection |
| Q-02 | LOW | API | ✅ Fixed v0.4.1 — ApiJson extractor: JSON body on POST /blacklist rejection |
| Q-03 | LOW | API | ✅ Fixed v0.4.1 — ApiJson extractor: JSON body on POST /rotate-key rejection |
| Q-04 | LOW | API | ✅ Fixed v0.4.1 — QueryRejection: JSON body on GET /logs?page=-1 |
| S-12 | INFO | DNS | ℹ️ False positive — version.bind CHAOS → NOTIMP confirmed in code |

---

### v0.4.3 Audit Findings (IA audit on v0.4.1)

| ID | Severity | Component | Status |
|---|---|---|---|
| SEC-02 | MEDIUM | API/DNS | ✅ Fixed v0.4.3 — false positive; added unit tests confirming 253/254-char boundary |
| SEC-03 | LOW | DNS | ✅ Fixed v0.4.3 — name-based identity probe block (defense-in-depth vs CHAOS class) |
| SEC-04 | LOW | API | ✅ Mitigated v0.4.1/v0.4.3 — Content-Length pre-check (413 for well-behaved clients); TCP RST for chunked >64 KB bodies is an inherent HTTP/1.1 limitation on localhost-only API |
| DOC-01 | INFO | Docs | ✅ Fixed v0.4.3 — README updated to current binary names |
| DOC-02 | INFO | Docs | ✅ Fixed v0.4.3 — Fixed runtime limits section added to configuration.md |
| DOC-03 | INFO | Docs | ✅ Fixed v0.4.3 — Slave DNS behaviour section added to ha.md |

---

### Pentest v0.4.4 Findings (external pentest on v0.4.4)

| ID | Severity | Component | Status |
|---|---|---|---|
| NEW-HIGH | 🔴 HIGH | API auth | ✅ Fixed v0.4.5 — timing oracle eliminated (pre-auth sleep + async side effects) |
| SEC-02 | 🟡 MEDIUM | API/DNS | ✅ Confirmed false positive — integration tests added; see analysis below |
| SEC-04 | 🟢 LOW | API | ✅ Fixed v0.4.5 — 411 for JSON POST without Content-Length (SEC-04 partial close) |
| NEW-LOW | 🟢 LOW | HTTP | ℹ️ Acknowledged — hyper-level HTTP parse rejection; not addressable in application code |

#### NEW-HIGH — Timing oracle (+183 ms on "nearly correct" key)

**Root cause:** The brute-force brake (`tokio::time::sleep(500 ms)` at ≥ 50 failures) ran
*after* `constant_time_eq` on the failure path, i.e. on the critical path before the 401
response. Two channels of leakage:
1. The sleep itself — applied only on failure, after the comparison. Pentest measured 184 ms
   (consistent with a sleep triggered at exactly failure #50, then cancelled by the rate limiter
   or measured mid-sleep).
2. The `warn!()` tracing call at multiples of 10 failures — file I/O on the handler task.

**Fix:** Pre-auth brake — `AUTH_FAILURES.load()` is checked *before* `constant_time_eq`; the
500 ms sleep applies equally to all requests (correct key, wrong key, any key) when failures
are high. The post-comparison side effects (audit event, warn!) are moved to `tokio::spawn`
so the 401 is returned immediately with no timing signal.

#### SEC-02 — Domain name > 253 chars (confirmed false positive)

The pentest reported "254 chars → HTTP 201". Investigation + added integration tests
(`dns_name_254_chars_is_rejected`, `blacklist_name_254_chars_is_rejected`) confirm that:

- A true 254-char name (no trailing dot) → HTTP **400** ✓
- The pentest used a 253-char name + trailing FQDN dot (= 254 bytes submitted) → HTTP 201,
  which is **correct**: the trailing dot is stripped before the 253-char check per RFC 1035 §2.3.4.

This is the same false positive identified in the IA audit (v0.4.3 SEC-02). The added
HTTP-level integration tests document and prove the boundary end-to-end.

#### SEC-04 — Chunked body drop without 413 (partial close)

The 412KB/5 MB bodies without `Content-Length` (chunked transfer encoding) caused
`DefaultBodyLimit` to drop the TCP connection instead of returning 413. The Content-Length
pre-check in the middleware only applies when the header is present.

**Fix:** JSON POST requests without `Content-Length` now return **411 Length Required**
before reaching rate limiting or auth. Non-JSON POST endpoints (`/reload`,
`/feeds/update`, `/feeds/:id/update`) are unaffected (no `Content-Type: application/json`).

#### NEW-LOW — UUID null byte → TCP drop

A null byte (`\x00`) in the HTTP request path causes hyper to reject the request at the
HTTP/1.1 parsing layer — before any application middleware runs. The connection is dropped
with no response rather than returning 400. This is **inherent hyper behaviour**: raw null bytes
are invalid in HTTP request targets per RFC 9110 §4.1. Fixing this would require patching the
HTTP library or adding a pre-parse TCP stream filter — both out of scope for this API.

**Impact:** LOW — affects only malformed/buggy clients (no well-behaved HTTP client sends raw
null bytes in a URI). No data is leaked; the client sees a connection reset.

---

---

## Live Pentest — v0.4.16

**Date:** 2026-05-19  
**Scope:** `src/api/mod.rs`, `src/dns/server.rs`, DNS protocol handling, REST API  
**Methodology:** Black-box + white-box, automated + manual  
**Status:** 13 checks PASS, 2 bugs found (open → v0.4.17), 2 observations

---

### Results — PASS

| Test | Expected | Result |
|---|---|---|
| DNS resolution (A, AAAA, TCP) | Correct answers | ✅ PASS |
| Blacklist enforcement | REFUSED rcode | ✅ PASS |
| ANY → NOTIMP | NOTIMP rcode | ✅ PASS |
| Compression pointer loop | FORMERR | ✅ PASS |
| Label > 63 bytes | FORMERR | ✅ PASS |
| QNAME > 253 bytes | FORMERR | ✅ PASS |
| Zero-length UDP packet | Dropped | ✅ PASS |
| Truncated header (5 bytes) | Dropped | ✅ PASS |
| RRSIG amplification | 0 bytes (blocked) | ✅ PASS |
| Log injection (`\r\n` in QNAME) | Escaped as `\012\015` | ✅ PASS |
| API authentication (no token / wrong token) | HTTP 401 | ✅ PASS |
| API input validation (path traversal, XSS, buffer overflow) | HTTP 400 / 405 | ✅ PASS |
| XDP compiled by default, active on ens18 | XDP fast path active | ✅ PASS |

---

### Results — FAIL

#### BUG-1 — `/reload` rate limit (2 RPS) not enforced

**Severity:** Low  
**File:** `src/api/mod.rs`  
**Status:** ⚠️ Open — fix targeted for v0.4.17

**Test:** 10 rapid `POST /reload` requests sent within 500 ms.  
**Actual:** 10 × HTTP 200, zero 429 responses.  
**Expected:** HTTP 429 after the 2nd request within the 500 ms window.

The dedicated `ReloadLimiter` token bucket was added in v0.4.16 (VUL-3.2) but is not
correctly wired into the request path — the check does not gate the handler in practice.

---

#### BUG-2 — TCP per-IP connection cap (20) not enforced

**Severity:** Low  
**File:** `src/dns/server.rs` (`TcpConnTracker`)  
**Status:** ⚠️ Open — fix targeted for v0.4.17

**Test:** 30 simultaneous TCP connections opened from 127.0.0.1.  
**Actual:** All 30 accepted.  
**Expected:** Connections beyond 20 refused.

**Note:** 127.0.0.1 (loopback) is intentionally exempt from the cap by design. The test
should be re-run from a non-loopback source IP to confirm whether the cap fails for external
addresses as well. The reported failure may be entirely explained by the loopback exemption,
but the enforcement path for non-loopback sources has not been independently verified.

---

### Observations

| # | Description | Priority |
|---|---|---|
| OBS-1 | Unknown opcode (7) returns NOERROR instead of NOTIMP — inherent hickory-server behaviour | Low |
| OBS-2 | `api.md` documented port 8081 but default REST API port is 8080 — corrected in this doc update | Fixed |

---

## Pre-release Audit Cycle — v0.4.16

**Scope:** `src/dns/xdp/umem.rs`, `src/dns/xdp/worker.rs`, `src/dns/ratelimit.rs`,
`src/dns/server.rs`, `src/api/mod.rs`, `src/main.rs`  
**Methodology:** Manual white-box source code review focusing on the XDP kernel-bypass path,
rate limiter, TCP connection handling, and REST API error surface.  
**Status:** All 5 findings resolved in v0.4.16.

---

### VUL-2.1 — UMEM bounds enforced only in debug builds

**Severity:** MEDIUM  
**File:** `src/dns/xdp/umem.rs`, `src/dns/xdp/worker.rs`  
**Status:** ✅ Fixed in v0.4.16

`frame_mut()` and `frame()` used `debug_assert!` to check that the descriptor offset + length
fit within the UMEM region. In release builds (`--release`) all `debug_assert!` calls compile
to no-ops, so a kernel-provided descriptor with an out-of-range `addr` would produce a
dangling pointer slice with undefined behaviour.

Although `addr` comes from the kernel XDP ring and is normally trustworthy, a buggy or
maliciously patched kernel, or UMEM ring corruption by a future bug, could supply an
out-of-range value. In that case, the process would access memory outside the UMEM region —
a safety violation in an otherwise memory-safe codebase.

**Fix:**
- `frame_mut` and `frame` now return `Option<&mut [u8]>` / `Option<&[u8]>`. A
  `saturating_add` bounds check runs unconditionally in both debug and release builds;
  `None` is returned if the bounds are exceeded.
- The XDP worker (`worker.rs`) adds a matching release-mode check before the raw-pointer
  slice construction on the direct (non-`frame_mut`) path: if
  `desc.addr + desc.len > umem.area_len`, the TX frame is returned to the free pool and
  the descriptor is skipped.
- No measurable performance impact: the branch is predicted-taken on every iteration.

---

### VUL-6.1 — IPv6 /128 addresses exhaust rate-limit bucket table

**Severity:** MEDIUM  
**File:** `src/dns/ratelimit.rs`  
**Status:** ✅ Fixed in v0.4.16

The `DashMap` bucket table has a hard cap of 65 536 slots (`MAX_RATE_LIMIT_BUCKETS`). With
per-/128 bucketing, an attacker controlling a /48 routed block (65 536 host addresses) could
fill the entire table from a single network announcement, causing all subsequent source IPs —
including legitimate clients — to be refused without rate-limit protection until the aggressive
10-second eviction reacted.

**Fix:** A `normalize_ip()` helper truncates every IPv6 address to its /48 prefix
(`octets[6..].fill(0)`) before the bucket lookup. The same routed block now occupies exactly
one bucket instead of up to 65 536. IPv4 addresses are unchanged (full /32 per address). The
same normalisation is applied in `server.rs` (`normalize_tcp_ip()`) for the TCP connection
tracker introduced by VUL-6.2.

---

### VUL-6.2 — No per-source-IP TCP connection limit

**Severity:** LOW  
**File:** `src/dns/server.rs`  
**Status:** ✅ Fixed in v0.4.16

TCP DNS (RFC 1035 §4.2.2, used by DNSSEC responses and zone transfers) had no per-IP
concurrency cap. A single source could exhaust the process file-descriptor table by opening
thousands of TCP connections, causing new UDP and TCP requests from all sources to fail.

**Fix:** A `TcpConnTracker` struct (backed by `DashMap<IpAddr, Arc<AtomicU16>>`) tracks
concurrent TCP connections per source IP (aggregated at /48 for IPv6). The cap is 20
connections per IP (`TCP_CONN_PER_IP_MAX`). Loopback addresses (`127.x`, `::1`) are exempt.

Architecture: a **loopback relay** runs between the public TCP listener and hickory-server's
internal TCP listener bound on `127.0.0.1:0`. The relay's accept loop enforces the per-IP
cap before proxying allowed connections via `tokio::io::copy_bidirectional`. Connections that
exceed the cap are dropped immediately after a warning (rate-throttled to one log line per IP
per 10 seconds).

Trade-off: all TCP sessions proxied through the relay appear as `127.0.0.1` to hickory-server's
own rate limiter, which is acceptable because the relay already enforces per-IP limits before
any proxying occurs.

---

### VUL-3.4 — REST API error bodies expose file-system paths

**Severity:** LOW  
**File:** `src/api/mod.rs`  
**Status:** ✅ Fixed in v0.4.16

Several API error responses included the raw `e.to_string()` of `std::io::Error` and `anyhow`
errors, which on Linux often contain absolute file-system paths (e.g.,
`"failed to open file /etc/runbound/dns_entries.json: No such file or directory"`). These paths
were returned in the HTTP 500 response body visible to any authenticated API caller, disclosing
the server's directory layout and potentially aiding privilege escalation planning.

**Affected handlers (8 sites):** `reload_handler`, `list_dns_handler`, `persist_and_swap`,
`delete_dns_handler` (load + save), `list_blacklist_handler`, `add_blacklist_handler`,
`delete_blacklist_handler` (load + save).

**Fix:** A `sanitize_error()` helper is called at every error site:

```rust
fn sanitize_error(e: &impl std::fmt::Display) -> String {
    let s = e.to_string();
    if s.contains('/') { "internal error".to_string() } else { s }
}
```

The full error string (with path) is always emitted at `WARN` level via `tracing` for
operator observability. Only the sanitised string appears in the HTTP response body.

---

### VUL-3.2 — `/reload` endpoint not independently rate-limited

**Severity:** LOW  
**File:** `src/api/mod.rs`, `src/main.rs`  
**Status:** ✅ Fixed in v0.4.16

`POST /reload` triggers a full zone-set rebuild (config parse + zone trie reconstruction).
It was only protected by the general API rate limiter (shared across all endpoints), which
means an authenticated caller could burst-reload the zone set at up to the global API
query rate — potentially causing sustained elevated CPU consumption on large configs with
many zones.

**Fix:** A dedicated `ReloadLimiter` token bucket (2 RPS, burst 2) is stored in `AppState`
and checked at the start of `reload_handler`. Callers that exceed the rate receive HTTP 429
with `{"error": "RATE_LIMITED", "details": "reload rate limit exceeded"}`. The general API
rate limiter still applies in addition.

---

## Open Findings

| ID | Severity | Title | Target |
|---|---|---|---|
| BUG-1 | Low | `/reload` rate limit (2 RPS) not enforced — `ReloadLimiter` not wired into request path | v0.4.17 |
| BUG-2 | Low | TCP per-IP connection cap (20) not enforced for non-loopback sources (loopback exempt by design) | v0.4.17 |

All other findings from all prior audit cycles are resolved.

---

## Hardening Checklist (nation-state deployment)

1. **Set `RUNBOUND_STORE_KEY`** — enables HMAC-SHA256 integrity on all JSON stores.
2. **Configure explicit `forward-zone:` blocks** — never rely on the Cloudflare fallback.
3. **Enable `forward-tls-upstream: yes`** — plain UDP to upstream is observable.
4. **Set `dot-client-auth-ca:` if DoT is enabled** — restricts service to authorised endpoints.
5. **Route Runbound through a DNSSEC-validating upstream** and set `dnssec-validation: yes`.
6. **Set `RUNBOUND_API_KEY` in `/etc/runbound/env` (chmod 640)** — never use `api-key:` in config.

---

*Initial white-box audit performed on commit `7dd3a66` (tag v0.2.3). Source files reviewed:
`src/main.rs`, `src/api/mod.rs`, `src/config/parser.rs`, `src/dns/server.rs`,
`src/dns/local.rs`, `src/dns/acl.rs`, `src/dns/ratelimit.rs`, `src/dns/xdp/worker.rs`,
`src/dns/xdp/umem.rs`, `src/feeds/mod.rs`, `src/store.rs`.
Second audit cycle targeting v0.3.3. Third audit cycle targeting v0.4.0.
v0.4.0 adds: `src/integrity.rs` (HIGH-06), hickory 0.26 + rustls 0.23 migration (HIGH-07),
`dot-client-auth-ca` mTLS (HIGH-08), `SsrfSafeDnsResolver` in `src/feeds/mod.rs` (MED-03),
`sanitize_dns_name()` (MED-06), local-zone cap (LOW-03).
v0.4.1 adds: CryptoProvider install (BUG-01), CNAME/MX/NS/PTR/SRV value validation (S-10),
Content-Length pre-check (S-11), ApiJson extractor (Q-01–Q-03), QueryRejection handling (Q-04).
v0.4.3 adds: defense-in-depth identity-probe block by name in `src/dns/server.rs` (SEC-03);
unit tests for 253/254-char boundary in `src/api/mod.rs` (SEC-02 false-positive documentation).
v0.4.4 adds: `src/hsm.rs` (PKCS#11 HSM key storage, cryptoki 0.6); `deny.toml` (supply-chain
policy); `docs/audit.md` (audit process and SBOM procedure).
v0.4.5 adds: pre-auth brute-force brake + async side-effects in `security_middleware`
(timing oracle elimination, NEW-HIGH pentest); 411 for JSON POST without Content-Length
(SEC-04 partial close); HTTP integration tests for 253/254-char name boundary (SEC-02).
v0.4.16 adds: release-mode UMEM bounds check returning `Option` in `src/dns/xdp/umem.rs` +
`src/dns/xdp/worker.rs` (VUL-2.1); IPv6 /48 normalisation in `src/dns/ratelimit.rs` and
`src/dns/server.rs` (VUL-6.1); TCP per-IP cap via loopback relay in `src/dns/server.rs`
(VUL-6.2); `sanitize_error()` at 8 API error sites in `src/api/mod.rs` (VUL-3.4);
`ReloadLimiter` token bucket (2 RPS) in `src/api/mod.rs` + `src/main.rs` (VUL-3.2).
v0.4.16 live pentest (2026-05-19): 13 PASS, 2 bugs open (BUG-1: ReloadLimiter not wired;
BUG-2: TcpConnTracker not enforced for non-loopback) → targeted v0.4.17; `api.md` port
corrected from 8081 to 8080.*
