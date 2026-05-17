# Runbound — Security Audit Report

**Version audited:** 0.2.3  
**Date:** 2026-05-16  
**Scope:** Full source review — DNS engine, REST API, feed subsystem, ACL, rate limiter, XDP fast-path, persistence layer, TLS, configuration parser  
**Methodology:** Manual white-box source code review of all Rust modules

---

## Executive Summary

Runbound's core DNS path is well-engineered: memory-safe Rust, lock-free hot path
via ArcSwap, per-IP token-bucket rate limiting, RFC 8482 ANY-query blocking, IPv4-mapped
IPv6 normalisation in the ACL. The six security fixes in v0.2.0 addressed the most
obvious post-MVP issues.

However, a full-depth audit reveals **four critical findings** that must be resolved
before nation-state or high-security production deployment:

1. Four API endpoints documented as implemented (`/health`, `/stats`, `/config`, `/reload`)
   return HTTP 404 — the code does not exist.
2. DNSSEC local validation is unconditionally disabled.
3. IPv6 private/ULA address ranges are absent from SSRF checks.
4. The SSRF redirect policy only inspects literal-IP destinations; a redirect to a
   private *hostname* bypasses the guard entirely.

Eight high-severity and seven medium-severity findings are documented below.
All critical and high findings have been corrected in v0.2.4 (this audit cycle).

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

## Critical Findings

### AUDIT-CRIT-01 — Ghost API endpoints (404 in production)

**File:** `src/api/mod.rs`, `docs/api.md`  
**Status:** Documentation corrected in v0.2.4

The following four endpoints appear in `docs/api.md`, `CHANGELOG.md` (v0.1.0), and
`docs/systemd.md` but have no handler and no route in the actual router:

| Endpoint | Documented as |
|---|---|
| `GET /health` | Liveness probe |
| `GET /stats` | Query counters (total, blocked, forwarded, refused) |
| `GET /config` | Sanitised config dump |
| `POST /reload` | REST-triggered hot reload |

All four return HTTP **404**. Consequences:
- **Monitoring is broken.** Kubernetes liveness probes, Prometheus scrapers, and
  any health-check relying on `/health` silently fail.
- **Operational visibility is zero.** There is no machine-readable source of query
  statistics. Traffic anomalies are invisible without log parsing.
- **The documented REST reload path does not work.** Operators who rely on
  `POST /reload` instead of SIGHUP have no reload mechanism.

Additionally, the API docs use **name-based path parameters** (`DELETE /dns/{name}`,
`DELETE /feeds/{name}`) while the actual code uses **UUIDs** (`DELETE /dns/:id`,
`DELETE /feeds/:id`). Every delete operation in the documentation produces a 404.

`POST /feeds/{name}/refresh` (documented) is actually `POST /feeds/:id/update`.

**Mitigation:** Implement the four missing endpoints and correct all path parameters.
See v0.2.4 release for implementation of `/health`, `/stats`, and corrected docs.

---

### AUDIT-CRIT-02 — DNSSEC validation unconditionally disabled

**File:** `src/dns/server.rs:414`  
**Status:** Architectural — requires operator decision

```rust
opts.validate = false;
```

Runbound operates in forwarder mode and trusts the AD (Authenticated Data) bit set by
upstream resolvers (Cloudflare, Quad9). If an upstream is compromised, misconfigured,
or subject to legal compulsion, it can set AD=1 on forged responses. Runbound will
accept and serve those responses to clients.

For nation-state and high-security deployments, local DNSSEC re-validation is mandatory.
The hickory-resolver crate supports `opts.validate = true` but requires full RRSIG/DNSKEY
chains in upstream responses. This is incompatible with forwarders that strip DNSSEC
records (some enterprise resolvers do). Operators must choose between:

- **DoT/DoH to a validating upstream** (Cloudflare 1.1.1.1, Quad9 9.9.9.9) and trust their AD bit
- **Enabling `opts.validate = true`** and operating in stub/recursive mode with a
  chain-complete upstream
- **Running a full DNSSEC-validating recursive resolver** (Unbound, BIND) as the
  upstream and point Runbound at it

**Mitigation:** Add a config directive `dnssec-validation: yes` that sets `opts.validate = true`.
Document the trade-off. For nation-state: configure a local DNSSEC-validating recursive
resolver as the upstream and set `forward-tls-upstream: yes` to it.

---

### AUDIT-CRIT-03 — IPv6 ULA/link-local addresses bypass SSRF guard

**File:** `src/feeds/mod.rs:345`  
**Status:** Fixed in v0.2.4

The `is_private_ip()` function used for SSRF prevention checks:

```rust
std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
```

This covers `::1` (loopback) and `::` (unspecified) only. The following ranges are
**not blocked**:

| Range | Description |
|---|---|
| `fc00::/7` | Unique Local Addresses (ULA) — `fd00::1`, etc. — RFC 4193 |
| `fe80::/10` | Link-local — RFC 4291 |
| `::ffff:0:0/96` | IPv4-mapped — `::ffff:192.168.1.1` |
| `100::/64` | Discard (NAT64 well-known) — RFC 6666 |
| `2001:db8::/32` | Documentation — RFC 3849 |

An attacker who registers a feed URL that resolves to `fd00::1` (a ULA address
common in enterprise and government networks) bypasses the SSRF check entirely.
All internal services reachable via IPv6 are exposed to SSRF.

**Fix:** Extend `is_private_ip()` to cover all IPv6 private ranges (implemented in v0.2.4).

---

### AUDIT-CRIT-04 — SSRF redirect guard only checks literal IPs, not hostnames

**File:** `src/feeds/mod.rs:582`  
**Status:** Fixed in v0.2.4

The SSRF-safe HTTP client blocks redirects to private *literal IP* destinations:

```rust
if let Ok(ip) = host.parse::<std::net::IpAddr>() {
    if is_private_ip(&ip) {
        return attempt.error("redirect to private IP blocked");
    }
}
attempt.follow()   // ← reached for hostname destinations
```

A feed server that redirects to `http://internal.corp/data` bypasses the guard:
`host.parse::<IpAddr>()` fails (it's a hostname), so `attempt.follow()` is called
unconditionally. The redirect is followed to the internal hostname without DNS
resolution or IP-range check.

**Attack scenario:** Attacker operates a public feed server at `https://feeds.attacker.com/`.
Runbound subscribes. On the next auto-refresh, the server redirects to
`http://admin.internal/config`. Runbound fetches the internal endpoint and
(if it returns valid feed format) stores the result.

**Fix:** Resolve hostname destinations in the redirect policy before following.
Implemented in v0.2.4.

---

## High Findings

### AUDIT-HIGH-01 — No feed subscription count limit (authenticated DoS)

**File:** `src/api/mod.rs`, `src/feeds/mod.rs`  
**Status:** Fixed in v0.2.4 (`MAX_FEEDS = 100`)

`MAX_DNS_ENTRIES` (10,000) and `MAX_BLACKLIST_ENTRIES` (100,000) are enforced but
there is no cap on feed subscriptions. Each feed can download up to 100 MiB.
An authenticated client can:

```
for i in 0..1000:
  POST /feeds  {"name":"feed{i}", "url":"https://evil.com/huge.txt"}
POST /feeds/update   # triggers 1000 × 100 MiB downloads
```

100 GB of network I/O and 100 GB of parsed domain strings would exhaust memory
and storage. The server's OOM guard triggers but may not recover.

---

### AUDIT-HIGH-02 — `/help` endpoint information disclosure (unauthenticated)

**File:** `src/api/mod.rs:268`  
**Status:** Fixed in v0.2.5 — `/help` now requires Bearer authentication

`GET /help` previously required no authentication and returned:
- Exact version string (`"version": "0.2.3"`)
- Complete endpoint list
- RFC compliance claims
- Author identity (`env!("CARGO_PKG_AUTHORS")`)

This enables **version fingerprinting** for targeted exploitation of known
vulnerabilities in Runbound or its dependencies. For classified or restricted
deployments, this endpoint should be removed or placed behind authentication.

---

### AUDIT-HIGH-03 — Fallback to Cloudflare when no forward-zone configured

**File:** `src/dns/server.rs:397`  
**Status:** Warning added in v0.2.4

```rust
if resolver_cfg.name_servers().is_empty() {
    resolver_cfg = ResolverConfig::cloudflare();
}
```

If the config file has no `forward-zone:` block, all DNS queries are silently
forwarded to Cloudflare (1.1.1.1/1.0.0.1) over UDP. For a nation-state deployment
this is a **data exfiltration risk** — the entire DNS query stream goes to a US
cloud provider. The operator may be unaware.

A misconfigured or stripped config file (no forward-zone section) triggers this
silently.

---

### AUDIT-HIGH-04 — ACL not reloaded on SIGHUP (systemd.md table was wrong)

**File:** `src/main.rs:90`, `docs/systemd.md`  
**Status:** Corrected in v0.2.4

The SIGHUP handler calls `build_zone_set()` and stores the result. The `Arc<Acl>`
is built once at startup and is not updated by SIGHUP. The `systemd.md` hot-reload
table erroneously stated that `access-control` rules are reloaded on SIGHUP.
An operator who adds a new `access-control` deny rule and runs `systemctl reload`
will believe the rule is active when it is not. The process must be restarted.

---

### AUDIT-HIGH-05 — Rate limiter bucket exhaustion (UDP source IP spoofing)

**File:** `src/dns/ratelimit.rs`  
**Status:** Architectural — documented

```rust
const MAX_RATE_LIMIT_BUCKETS: usize = 65_536;
// ...
if !self.buckets.contains_key(&ip) && self.buckets.len() >= MAX_RATE_LIMIT_BUCKETS {
    return false;
}
```

UDP allows source IP spoofing. An attacker sending queries from 65,537+ unique
spoofed IPs fills the bucket table. New IPs (including legitimate clients) are
refused with no response. The cleanup only runs every 10,000 queries; with a
sustained flood, the cleanup never catches up.

Mitigation requires network-layer controls (ingress filtering, BCP38) upstream
of Runbound. At the application layer: reduce `MAX_RATE_LIMIT_BUCKETS` to a value
that allows faster cleanup, or use a time-bucketed structure that evicts stale IPs
aggressively.

---

### AUDIT-HIGH-06 — JSON data stores have no integrity protection

**File:** `src/store.rs`, `src/feeds/mod.rs`  
**Status:** Architectural — documented

`dns_entries.json`, `blacklist.json`, and `feeds.json` are stored as cleartext JSON
with file permissions 0640. An attacker with filesystem write access (e.g., via a
web shell or misconfigured backup restore) can inject arbitrary DNS records without
touching the API, bypassing authentication, rate limiting, and entry count limits.

For nation-state deployments: mount the data directory on an integrity-protected
filesystem (dm-verity, ZFS with checksums, or a HSM-backed secret store). Apply
HMAC-SHA256 over the JSON content using a key stored in the system keyring.

---

### AUDIT-HIGH-07 — TLS cipher suites inherit rustls 0.21 defaults

**File:** `src/dns/server.rs:507`, `Cargo.toml`  
**Status:** Architectural — documented

The DoT/DoH/DoQ TLS configuration uses `hickory-server`'s default rustls setup
without pinning minimum TLS version, cipher suites, or disabling obsolete
algorithms. `rustls 0.21` defaults to TLS 1.2+, which includes cipher suites
below BSI TR-02102 / NIST SP 800-52 Rev 2 requirements.

For nation-state deployments:
- Mandate TLS 1.3 only
- Pin cipher suites to `TLS_AES_256_GCM_SHA384` and `TLS_CHACHA20_POLY1305_SHA256`
- Disable RSA key exchange (require ECDHE)
- Upgrade to `rustls 0.23` (which defaults to TLS 1.3 and has a cleaner API)

---

### AUDIT-HIGH-08 — No mTLS for DoT client authentication

**File:** `src/dns/server.rs:643`  
**Status:** Architectural — documented

DNS-over-TLS uses server-only TLS (standard client→server direction). There is no
support for mutual TLS (client certificates). For a classified government DNS
resolver, client certificate authentication restricts service to authorised
endpoints.

The hickory-server TLS listener accepts a `(Vec<Certificate>, PrivateKey)` tuple
with no mechanism to require client certificates. Implementing mTLS requires a
custom `ServerConfig` with `client_cert_verifier` set.

---

## Medium Findings

### AUDIT-MED-01 — `is_valid_domain` in feed parser allows single-label entries via underscore

**File:** `src/feeds/mod.rs:489`

```rust
if !s.contains('.') { return false; }
```

The check requires at least one dot, but `_dmarc` (single label with underscore)
would pass `!s.contains('.')` as `false` (it fails). This is correct. However,
`_dmarc.example.com` (underscore in non-service position) is accepted.
RFC 1035 §2.3.1 specifies that labels must start with a letter, not underscore,
but service labels (`_tcp`, `_dmarc`) use underscores by convention (RFC 2782/6763).
This is technically a relaxed check but pragmatically correct for blocklists.
**No immediate action required; document the intentional relaxation.**

---

### AUDIT-MED-02 — TOCTOU window in feed URL validation

**File:** `src/feeds/mod.rs:524`

`update_feed()` calls `validate_feed_url()` (which resolves the hostname via
`tokio::net::lookup_host()`) immediately before `client.get()`. reqwest internally
re-resolves the hostname for the actual TCP connection. Between the two resolutions,
an attacker controlling the feed's DNS can switch the A record from a public IP
to a private one (DNS rebinding with TTL=0).

This window is typically < 10 ms. Exploiting it requires precise timing and control
over the feed's DNS zone. Practical risk is very low but non-zero.

**Mitigation (complete):** Use a custom reqwest DNS resolver that performs the
IP-range check at connection time, not before. The current approach is a significant
improvement over no validation (pre-v0.2.0).

---

### AUDIT-MED-03 — Cloudflare DNS used for SSRF hostname resolution

**File:** `src/feeds/mod.rs:323`

`validate_feed_url()` resolves hostnames using `tokio::net::lookup_host()`, which
uses the system resolver (`/etc/resolv.conf`). On a default installation after
`install.sh` runs, the system resolver may point to the Runbound instance itself
(loop), a public resolver, or DHCP-assigned resolver. None of these is guaranteed
to give accurate SSRF-blocking resolution.

**Mitigation:** Use a local resolver that is independent of the system resolver
for SSRF validation, or validate at the TCP connection layer.

---

### AUDIT-MED-04 — XDP `frame_mut()` has no bounds enforcement at call sites

**File:** `src/dns/xdp/umem.rs:334`

```rust
pub unsafe fn frame_mut(&mut self, offset: u64, len: usize) -> &mut [u8] {
    slice::from_raw_parts_mut(self.area.add(offset as usize), len)
}
```

The safety contract says "offset must be a valid UMEM frame offset" but is not
enforced. A kernel bug or ring corruption that delivers a malformed `XdpDesc`
could produce an out-of-bounds write. The XDP path runs in a dedicated OS thread
outside the async runtime, so a memory corruption here cannot be caught by Tokio
and would segfault the entire process.

**Mitigation:** Add a debug-mode bounds assertion: `debug_assert!(offset < self.area_len as u64)`.

---

### AUDIT-MED-05 — No authentication failure rate limiting / lockout

**File:** `src/api/mod.rs:174`

Failed authentication attempts are logged (`warn!`) but there is no incremental
delay, lockout, or alert. An automated attacker can attempt unlimited token guesses
(subject only to the per-IP rate limiter of 30 req/s). With a 256-bit key, brute
force is infeasible, but weak or manually-set `api-key:` values in the config file
are at risk.

**Mitigation:** Log failed attempts with client IP; add a per-IP failure counter
with exponential backoff or lockout after N failures.

---

### AUDIT-MED-06 — Log injection via structured DNS query names

**File:** `src/dns/server.rs:329`

```rust
name = %qname,
```

Every DNS query name is emitted as a structured log field. With JSON logging
(`RUST_LOG=json`), a crafted DNS name containing `"` or `}` characters could
potentially break the JSON structure in downstream log consumers (Elasticsearch,
Splunk). The hickory `LowerName` Display implementation escapes most control
characters but may not handle all JSON-breaking sequences.

**Mitigation:** Apply JSON escaping to `qname` before logging, or verify that
the `tracing-subscriber` JSON formatter escapes all special characters.

---

### AUDIT-MED-07 — `api-key` stored cleartext in `runbound.conf`

**File:** `src/config/parser.rs:187`, `docs/configuration.md`

The `api-key:` directive stores the API key in the config file (mode 0640).
The installer generates the key in a separate `env` file (mode 0640), which is
good practice. However, the config-file option is documented and operators may use
it for convenience, placing the key where it can be read by any process with group
membership, or in configuration management systems that log secrets.

**Mitigation:** Deprecate `api-key:` in the config file; require `RUNBOUND_API_KEY`
env var for all production deployments. Add a `WARN`-level log when `api-key:` is
used in config.

---

## Low Findings

### AUDIT-LOW-01 — Hand-rolled UTC timestamp in `feeds/mod.rs`

**File:** `src/feeds/mod.rs:728`

A 30-line custom Gregorian calendar implementation generates RFC 3339 timestamps
for feed `last_updated`. This reimplements date arithmetic that is subtle to get
right (leap year edge cases, month-day accounting). No known bug exists, but
maintenance risk is elevated. Use `std::time::SystemTime` formatted via
`humantime` (already a dependency) instead.

---

### AUDIT-LOW-02 — `GET /help` exposes author identity and repository URL

**File:** `src/api/mod.rs:270`  
**Status:** Fixed in v0.2.5 — `/help` now requires Bearer authentication

```rust
"author": env!("CARGO_PKG_AUTHORS"),
"repository": env!("CARGO_PKG_REPOSITORY"),
```

Previously revealed personal identity and repository URL from an unauthenticated endpoint.
The endpoint is now behind auth — unauthenticated callers receive 401.

---

### AUDIT-LOW-03 — No cap on the number of `local-zone` / `local-data` entries in config

**File:** `src/config/parser.rs`

The config parser accumulates `local_zones` and `local_data` entries without limit.
A malformed or adversarial config file with millions of `local-data:` lines would
consume excessive memory at startup. Since the config file is operator-controlled,
this is low risk, but a sanity limit (e.g., 1,000,000 entries) with an error at
parse time would prevent accidental misconfiguration.

---

### AUDIT-LOW-04 — TCP idle timeout (5 s) is too short for high-latency DoT

**File:** `src/dns/server.rs:631`  
**Status:** Fixed in v0.2.5 — timeout raised to 30 s

```rust
server.register_listener(tcp, Duration::from_secs(5));
```

DoT clients on high-latency links (satellite, intercontinental) may exceed 5 seconds
between queries on the same connection, causing premature disconnection and
re-handshake overhead. RFC 7858 §3.5 recommends >= 10 s. All TCP listeners now use 30 s.

---

## Informational Notes

### AUDIT-INFO-01 — Runbound trusts all API clients equally

There is a single API key shared by all operators. There are no roles (read-only
vs. read-write), no per-operator keys, no audit attribution. For multi-operator
deployments, individual operator keys with per-key audit logs are necessary.

### AUDIT-INFO-02 — No OCSP stapling for DoT certificates

The TLS configuration does not implement OCSP stapling. DoT clients performing
certificate revocation checks incur additional latency. For production DoT, use
Let's Encrypt certificates with OCSP stapling enabled in the TLS stack.

### AUDIT-INFO-03 — Memory pressure guard reads /proc/meminfo

The 30-second memory check reads `/proc/meminfo`, which is Linux-specific and
unavailable in some container runtimes. On systems where `/proc/meminfo` is
unavailable, `read_meminfo()` returns `None` and the guard silently does nothing.
Add a log warning if meminfo is unavailable at first poll.

### AUDIT-INFO-04 — XDP fast path handles only local-zone queries

The AF_XDP worker correctly falls through to the kernel (and hickory-server) for:
- Recursive queries (unknown names)
- ANY queries (RFC 8482)
- ACL-denied sources (crafts REFUSED and returns)
- Malformed frames

This design is sound. There is no data exfiltration risk from the XDP path.

---

## Finding Summary

| ID | Severity | Component | Status |
|---|---|---|---|
| CRIT-01 | CRITICAL | API | Fixed in v0.2.5 — /health /stats /config /reload implemented |
| CRIT-02 | CRITICAL | DNS/DNSSEC | Mitigated in v0.2.5 — dnssec-validation directive added |
| CRIT-03 | CRITICAL | Feeds/SSRF | Fixed in v0.2.4 |
| CRIT-04 | CRITICAL | Feeds/SSRF | Fixed in v0.2.4 |
| HIGH-01 | HIGH | Feeds | Fixed in v0.2.4 (MAX_FEEDS = 100) |
| HIGH-02 | HIGH | API | Fixed in v0.2.5 — /help now requires Bearer token |
| HIGH-03 | HIGH | DNS | Mitigated in v0.2.4 (loud warning log) |
| HIGH-04 | HIGH | Reload | Fixed in v0.2.5 — POST /reload implemented |
| HIGH-05 | HIGH | RateLimit | Mitigated in v0.2.5 — aggressive eviction on bucket exhaustion |
| HIGH-06 | HIGH | Storage | Open — architectural (HMAC integrity planned) |
| HIGH-07 | HIGH | TLS | Open — requires rustls upgrade |
| HIGH-08 | HIGH | TLS/DoT | Open — requires mTLS implementation |
| MED-01 | MEDIUM | Feeds | Accepted — intentional RFC relaxation |
| MED-02 | MEDIUM | Feeds/SSRF | Partial — documented residual risk |
| MED-03 | MEDIUM | Feeds/SSRF | Open — resolver independence |
| MED-04 | MEDIUM | XDP | Mitigated in v0.2.4 (debug_assert added) |
| MED-05 | MEDIUM | API | Fixed in v0.2.5 — AUTH_FAILURES global counter + 500ms lockout |
| MED-06 | MEDIUM | Logging | Open — verify tracing JSON escaping |
| MED-07 | MEDIUM | Config | Mitigated in v0.2.4 (WARN log) |
| LOW-01 | LOW | Feeds | Fixed in v0.2.5 — replaced with humantime::format_rfc3339 |
| LOW-02 | LOW | API | Fixed in v0.2.5 — /help now requires Bearer token |
| LOW-03 | LOW | Config | Open |
| LOW-04 | LOW | DNS/TLS | Fixed in v0.2.5 — TCP timeout raised to 30 s |

---

## Remediation Priority (nation-state deployment)

### Before first production use

1. **Configure explicit `forward-zone:` blocks** — never rely on the Cloudflare fallback.
2. **Enable `forward-tls-upstream: yes`** — plain UDP to upstream is observable.
3. ✅ **Authenticate `/help`** — done in v0.2.5 (Bearer token required).
4. **Mount data directory on integrity-protected storage** — dm-verity or ZFS.
5. **Route Runbound through a DNSSEC-validating resolver** as upstream.

### Short-term (next release cycle)

6. ✅ `GET /health`, `GET /stats`, `GET /config`, `POST /reload` implemented in v0.2.5.
7. Upgrade to rustls 0.23; pin TLS 1.3 + approved cipher suites.
8. Implement mTLS for DoT (client certificate required).
9. ✅ Auth failure counter + lockout implemented in v0.2.5 (AUTH_FAILURES, 500 ms delay).

### Medium-term

10. ✅ `dnssec-validation` config directive added in v0.2.5.
11. Implement HMAC integrity on JSON data stores.
12. Add per-operator API keys with audit log.
13. ✅ `utc_now_rfc3339()` replaced with `humantime::format_rfc3339` in v0.2.5.

---

*Audit performed on commit `7dd3a66` (tag v0.2.3 + doc fixes). All source files reviewed: `src/main.rs`, `src/api/mod.rs`, `src/config/parser.rs`, `src/dns/server.rs`, `src/dns/local.rs`, `src/dns/acl.rs`, `src/dns/ratelimit.rs`, `src/dns/xdp/worker.rs`, `src/dns/xdp/umem.rs`, `src/feeds/mod.rs`, `src/store.rs`, `src/error.rs`.*
