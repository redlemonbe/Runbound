# Runbound — Security Audit Report

**Version audited:** 0.2.3 (initial audit) — findings tracked through v0.4.1  
**Last updated:** 2026-05-17  
**Scope:** Full source review — DNS engine, REST API, feed subsystem, ACL, rate limiter, XDP fast-path, persistence layer, TLS, configuration parser  
**Methodology:** Manual white-box source code review of all Rust modules

---

## Executive Summary

Runbound's core DNS path is well-engineered: memory-safe Rust, lock-free hot path
via ArcSwap, per-IP token-bucket rate limiting with aggressive eviction, RFC 8482
ANY-query blocking, IPv4-mapped IPv6 normalisation in the ACL, HMAC-SHA256 audit
chain, and constant-time Bearer comparison.

The four original critical findings (ghost API endpoints, DNSSEC unconditionally
disabled, IPv6 SSRF bypass, SSRF hostname-redirect bypass) and all high-severity
findings from the initial audit have been resolved across v0.2.4, v0.2.5, and v0.3.x.
A second audit cycle targeting v0.3.3 identified eight additional findings (SEC-09
through SEC-16), all fixed in v0.3.3.

**All HIGH and MEDIUM open findings are closed as of v0.4.0:**

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

### v0.4.1 Audit Findings (military audit on v0.4.0)

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

## Open Findings

All findings from all audit cycles are resolved as of v0.4.1.
No open findings remain.

---

## Hardening Checklist (nation-state deployment)

1. **Set `RUNBOUND_STORE_KEY`** — enables HMAC-SHA256 integrity on all JSON stores.
2. **Configure explicit `forward-zone:` blocks** — never rely on the Cloudflare fallback.
3. **Enable `forward-tls-upstream: yes`** — plain UDP to upstream is observable.
4. **Set `dot-client-auth-ca:` if DoT is enabled** — restricts service to authorised endpoints.
5. **Route Runbound through a DNSSEC-validating upstream** and set `dnssec-validation: yes`.
6. **Set `RUNBOUND_API_KEY` in `/etc/runbound/env` (chmod 640)** — never use `api-key:` in config.

---

*Initial audit performed on commit `7dd3a66` (tag v0.2.3). All source files reviewed:
`src/main.rs`, `src/api/mod.rs`, `src/config/parser.rs`, `src/dns/server.rs`,
`src/dns/local.rs`, `src/dns/acl.rs`, `src/dns/ratelimit.rs`, `src/dns/xdp/worker.rs`,
`src/dns/xdp/umem.rs`, `src/feeds/mod.rs`, `src/store.rs`.
Second audit cycle targeting v0.3.3. Third audit cycle targeting v0.4.0.
v0.4.0 adds: `src/integrity.rs` (HIGH-06), hickory 0.26 + rustls 0.23 migration (HIGH-07),
`dot-client-auth-ca` mTLS (HIGH-08), `SsrfSafeDnsResolver` (MED-03),
`sanitize_dns_name()` (MED-06), local-zone cap (LOW-03).
v0.4.1 adds: CryptoProvider install (BUG-01), CNAME/MX/NS/PTR/SRV value validation (S-10),
Content-Length pre-check (S-11), ApiJson extractor (Q-01–Q-03), QueryRejection handling (Q-04).*
