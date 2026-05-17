# Security Architecture

This document covers the security model, defensive layers, and all audit findings
fixed across Runbound releases through v0.4.1.

---

## Defensive layers

```
Internet / LAN
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  DoT / DoH / DoQ (TLS 1.2+, TLS 1.3 for DoQ)       │  ← rustls 0.23 + ring backend
│  Optional mTLS client auth (dot-client-auth-ca)     │  ← mutual TLS for DoT
├─────────────────────────────────────────────────────┤
│  ACL check (allow / deny / refuse)                  │  ← per-subnet rules, IPv4+IPv6
│  Rate limiter (token bucket)                        │  ← per-source-IP, DashMap+ahash
│  Inflight semaphore (max 4096)                      │  ← hard OOM backstop
├─────────────────────────────────────────────────────┤
│  XDP fast path (optional)                           │  ← same ACL + rate limit enforced
├─────────────────────────────────────────────────────┤
│  DNS engine (hickory-server 0.26)                   │
│  Zone lookup / forwarding                           │
└─────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  REST API (port 8081, localhost only)               │
│  Body size check before rate limit (Content-Length) │  ← 413 before 429
│  Bearer token (timing-safe cmp)                     │  ← subtle::ConstantTimeEq
│  Entry limits (10k DNS, 100k BL)                   │
│  zones_mutex (atomic write+swap)                    │
│  HMAC-SHA256 store integrity (.mac sidecars)        │  ← RUNBOUND_STORE_KEY
└─────────────────────────────────────────────────────┘
```

---

## ACL (Access Control List)

Rules are evaluated in order; first match wins. Default if no rule matches: **REFUSE**.

```
access-control: 127.0.0.0/8    allow
access-control: 10.0.0.0/8     allow
access-control: 0.0.0.0/0      refuse   ← secure default
```

**IPv4-mapped IPv6 normalisation (SEC-03):** Clients connecting via IPv6 as
`::ffff:10.0.0.1` are normalised to `10.0.0.1` before ACL matching, ensuring
IPv4 rules apply correctly regardless of transport.

---

## Rate limiting

Token-bucket rate limiter, one bucket per source IP.

```
rate-limit: 500    # max queries per second per IP
```

- Implemented with `DashMap<IpAddr, IpBucket>` and `ahash` for low-contention
  concurrent access.
- Excess queries receive a REFUSED response — no amplification possible.
- Shared between the standard path and the XDP fast path.
- Disable with `rate-limit: 0` (not recommended for public-facing resolvers).

---

## Anti-OOM memory protection

Runbound has two independent, always-active defences against memory exhaustion:

### 1. Inflight concurrency semaphore

Hard cap of **4,096 concurrent in-flight requests**. When the semaphore is exhausted,
new requests receive REFUSED immediately without allocating any additional memory.

### 2. Memory pressure guard

A background task reads `/proc/meminfo` every **30 seconds**. When system RAM usage
reaches **80 %**, two caches are purged atomically:

- **Rate-limiter DashMap** — all token buckets cleared.
- **hickory-resolver cache** — rebuilt and atomically swapped via ArcSwap.

After the purge, the new usage level is logged. If usage is still above 50 %, a
second warning is emitted.

On non-Linux systems or containers without `/proc/meminfo`, the guard silently
skips its check.

```
WARN Memory pressure — purging DNS caches  used_pct=82.3%  avail_mb=312  total_mb=1753
WARN DNS resolver cache flushed and rate limiter cleared  freed_buckets=8241
WARN Memory after purge  used_pct=44.1%  status="below 50% target"
```

**The memory guard is always active — no configuration required.**

---

## TLS (DoT / DoH / DoQ)

Runbound supports three encrypted DNS transports:

| Transport | Port | Standard |
|---|---|---|
| DNS-over-TLS (DoT) | 853 | RFC 7858 |
| DNS-over-HTTPS (DoH) | 443 | RFC 8484 |
| DNS-over-QUIC (DoQ) | 853/UDP | RFC 9250 |

TLS is provided by **rustls 0.23** with the **ring** cryptographic backend. DoQ
requires TLS 1.3 (`ServerConfig::builder_with_protocol_versions(&[&TLS13])`).

### Mutual TLS for DoT (mTLS)

Optionally require clients to present a certificate signed by a trusted CA:

```
dot-client-auth-ca: /etc/runbound/client-ca.pem
```

When set, unauthenticated DoT connections are rejected at the TLS handshake
before any DNS message is parsed. See [configuration.md](configuration.md) for
the full setup guide including client certificate generation.

### Certificate management

Runbound supports automatic certificate provisioning via **Let's Encrypt ACME**
(HTTP-01 challenge) and includes a `--gen-cert` utility for development
self-signed certificates.

```bash
# Generate self-signed certificate for testing
runbound --gen-cert dns.example.com

# Use Let's Encrypt in production (add to unbound.conf)
acme-email: ops@example.com
acme-domain: dns.example.com
```

---

## REST API security

**Authentication:** Bearer token via `Authorization` header. Compared using
`subtle::ConstantTimeEq` — not vulnerable to timing attacks.

**API key management:**
```bash
# Set via environment variable — never write in config files
export RUNBOUND_API_KEY="$(openssl rand -hex 32)"
```

**Body size enforcement:** `Content-Length` is checked before the rate limiter
so oversized requests return HTTP 413 (not 429). The `DefaultBodyLimit` at
64 KiB prevents OOM via large payloads.

**Entry limits:** Enforced server-side to prevent authenticated DoS:
- DNS entries: max 10,000
- Blacklist entries: max 100,000
- Feed subscriptions: max 100

**Concurrent write safety:** The entire load → validate → write → ArcSwap
sequence is performed inside `zones_mutex`. Two concurrent API writes cannot
overwrite each other.

**Input validation:**
- DNS `name` and domain-type `value` fields (CNAME, MX, NS, PTR, SRV targets)
  are validated against RFC 1035 rules: max 253 chars, labels max 63 chars,
  valid label characters only, no control characters.
- TTL must be in [0, 2147483647] (RFC 2181 §8).
- All JSON deserialization failures return structured JSON error bodies with
  `{"error": "INVALID_REQUEST", "details": "..."}`.

---

## Store integrity (HMAC)

Runbound optionally protects its JSON data stores against offline tampering using
HMAC-SHA256 sidecar files.

```bash
# 64-byte hex key (minimum)
export RUNBOUND_STORE_KEY="$(openssl rand -hex 32)"
```

Protected files:
- `dns_entries.json` → `dns_entries.json.mac`
- `blacklist.json` → `blacklist.json.mac`
- `feeds.json` → `feeds.json.mac`
- `feed_domains_<id>.txt` → `feed_domains_<id>.txt.mac`

| Key set | MAC file exists | Behaviour |
|---|---|---|
| No | No | OK — HMAC disabled |
| No | Yes | WARN — orphaned sidecar, load continues |
| Yes | No | WARN — file was written without MAC, load continues |
| Yes | Yes | Verify — mismatch → ERROR, load aborted |

A HMAC mismatch on startup returns an error and refuses to load the tampered file.
Startup continues with an empty store rather than serving poisoned data.

See [configuration.md](configuration.md) for the full 4-case behaviour table.

---

## Feed security

**SSRF protection — two independent layers:**

1. **Redirect policy:** HTTP→HTTPS downgrades and redirects to private/loopback
   addresses are blocked at the reqwest level before any HTTP request is issued.

2. **Connection-layer resolver (MED-03, v0.4.0):** A custom `reqwest` DNS
   resolver (`SsrfSafeDnsResolver`) filters private, loopback, and link-local
   addresses from DNS responses *before* a TCP connection is opened. This closes
   the gap where a feed URL resolves to a public IP at subscription time but a
   later DNS update returns a private IP (DNS rebinding).

**TOCTOU re-validation:** Feed URLs are re-validated on every fetch, not just
at subscription time.

**HTTPS enforcement:** HTTP feed URLs are rejected with 400 Bad Request —
only `https://` URLs are accepted.

**Credential stripping (v0.3.3):** Feed URLs with embedded credentials
(`user:pass@host`) are rejected before any network request.

**File permissions:** Serialised feed files are written with `chmod 640` —
owner and group readable only, with HMAC sidecar integrity verification.

---

## XDP path security

**ACL enforcement in XDP (SEC-02):** The AF/XDP fast path applies the full ACL
before answering any query. `Deny` → silent drop; `Refuse` → REFUSED frame
crafted directly in the XDP worker.

---

## HA master/slave sync

The sync HTTPS server (port 8082) uses **rustls 0.23** with a TOFU
(Trust-On-First-Use) certificate pinning strategy:

- Master generates a self-signed sync certificate on first start and pins its
  SHA-256 fingerprint.
- Slave connects only to a master whose certificate matches the configured
  fingerprint.
- Sync bearer token compared with `subtle::ConstantTimeEq`.
- All write operations are blocked on slave nodes (HTTP 503 `READ_ONLY`).

---

## File permissions reference

| File | Permissions | Notes |
|---|---|---|
| `/etc/runbound/runbound.conf` | `640` | Contains no secrets when using env vars |
| `/etc/runbound/api.key` | `600` | Auto-generated API key backup |
| `/etc/runbound/key.pem` | `600` | TLS private key — never world-readable |
| `/etc/runbound/cert.pem` | `644` | TLS certificate |
| `<base_dir>/dns_entries.json` | `640` | DNS store (auto-set by Runbound) |
| `<base_dir>/blacklist.json` | `640` | Blacklist store (auto-set by Runbound) |
| `<base_dir>/feeds.json` | `640` | Feed subscriptions |
| `<base_dir>/*.mac` | `640` | HMAC sidecar files |

---

## Systemd hardening

The provided unit file applies:
- `NoNewPrivileges=yes`
- `PrivateTmp=yes`
- `ProtectSystem=strict`
- `ProtectHome=yes`
- `ProtectKernelTunables=yes`
- `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` (port 53 only — no root)

See [systemd.md](systemd.md) for the full unit file.

---

## Audit findings

### v0.2.0 – v0.3.x

| ID | Severity | Title | Fixed in |
|---|---|---|---|
| SEC-01 | High | Race condition on concurrent API writes | v0.2.0 |
| SEC-02 | High | XDP fast path bypassed ACL entirely | v0.2.0 |
| SEC-03 | Medium | IPv4-mapped IPv6 skipped ACL rules | v0.2.0 |
| SEC-04 | Medium | SSRF via HTTP redirect in feed fetcher | v0.2.0 |
| SEC-05 | Medium | TOCTOU on feed URL validation | v0.2.0 |
| SEC-06 | Medium | Unbounded data-store growth | v0.2.0 |
| SEC-07 | Low | Feed data files world-readable | v0.2.0 |
| SEC-08 | Low | Plaintext HTTP feeds accepted silently | v0.2.0 |
| SEC-09 | High | `POST /rotate-key` was a silent no-op | v0.3.3 |
| SEC-10 | Medium | CHAOS class queries returned NOERROR instead of NOTIMP | v0.3.3 |
| SEC-11 | Medium | Body limit dropped TCP instead of returning HTTP 413 | v0.3.3 |
| SEC-12 | Medium | Negative TTL caused panic instead of HTTP 422 | v0.3.3 |
| SEC-13 | Medium | Production `unwrap()` / `expect()` could crash the process | v0.3.3 |
| SEC-14 | Medium | Sync Bearer comparison was timing-vulnerable | v0.3.3 |
| SEC-15 | Low | Feed URLs with embedded credentials were not rejected | v0.3.3 |
| SEC-16 | Low | `rate-limit: u64::MAX` silently disabled rate limiting | v0.3.3 |

### v0.4.0

| ID | Severity | Title | Fixed in |
|---|---|---|---|
| HIGH-01 | High | Auth bypass — 7 attack vectors accepted unauthenticated | v0.4.0 |
| HIGH-02 | High | Timing oracle on API key comparison | v0.4.0 |
| HIGH-03 | High | DNS injection via unvalidated name/value fields | v0.4.0 |
| HIGH-04 | High | ANY amplification not blocked | v0.4.0 |
| HIGH-05 | High | AXFR zone transfer not refused | v0.4.0 |
| HIGH-06 | High | No integrity protection on data stores | v0.4.0 |
| MED-01 | Medium | Per-IP rate limit on API missing | v0.4.0 |
| MED-02 | Medium | `local-zone` / `local-data` count unbounded in config | v0.4.0 |
| MED-03 | Medium | SSRF via DNS rebinding not blocked at connection layer | v0.4.0 |
| MED-04 | Medium | Audit log HMAC not enforced | v0.4.0 |
| MED-05 | Medium | DoT/DoH TLS upgrade to rustls 0.23 (CVE exposure) | v0.4.0 |
| LOW-01 | Low | Client IP logged for all queries (privacy) | v0.4.0 |
| LOW-02 | Low | Log buffer unbounded growth | v0.4.0 |
| LOW-03 | Low | Config cap on local-zone / local-data directives missing | v0.4.0 |
| LOW-04 | Low | Sync certificate not pinned (TOFU gap) | v0.4.0 |
| LOW-05 | Low | Control characters in log fields not sanitised | v0.4.0 |

### v0.4.1

| ID | Severity | Title | Fixed in |
|---|---|---|---|
| BUG-01 | Blocking | Sync HTTPS server panic (CryptoProvider not installed) | v0.4.1 |
| S-10 | Medium | CNAME/MX/NS/PTR/SRV target values accepted beyond 253 chars | v0.4.1 |
| S-11 | Low | 1 MB body returned 429 instead of 413 (rate limit fired first) | v0.4.1 |
| Q-01 | Low | POST /dns invalid type → HTTP 422 non-JSON body | v0.4.1 |
| Q-02 | Low | POST /blacklist invalid action → HTTP 422 non-JSON body | v0.4.1 |
| Q-03 | Low | POST /rotate-key non-string type → HTTP 422 non-JSON body | v0.4.1 |
| Q-04 | Low | GET /logs?page=-1 → HTTP 400 non-JSON body | v0.4.1 |

See [security-audit.md](security-audit.md) for the full white-box audit report.

---

## HSM key storage (PKCS#11)

Runbound supports loading the REST API key and the JSON store HMAC key from a
Hardware Security Module via PKCS#11. When active, keys are physically non-extractable
from the hardware and never written to disk in plaintext.

**Key priority chain (highest to lowest):**

| Source | API key | Store key |
|---|:---:|:---:|
| HSM (`hsm-api-key-label`) | ✅ | ✅ |
| Env var (`RUNBOUND_API_KEY` / `RUNBOUND_STORE_KEY`) | ✅ | ✅ |
| Config file (`api-key:`) | ✅ | — |
| Auto-generated (CSPRNG) | ✅ | — |

When `hsm-pkcs11-lib` is set and key loading fails, Runbound exits immediately —
no silent fallback to env vars.

The HSM session is opened at startup, keys are extracted into `Zeroizing<T>` buffers
(memory is scrubbed on drop), and the session is closed. The HSM does not need to
remain connected during normal operation.

**Tested devices:** SoftHSM2 (dev), YubiHSM 2 (recommended, FIPS 140-2 L3), Nitrokey
HSM 2, AWS CloudHSM, Thales Luna.

→ Full setup guide: [docs/hsm.md](hsm.md)

---

## Supply chain & audit

Runbound enforces supply-chain security at three levels:

**1. CVE scanning (`cargo audit`)**  
Every dependency is checked against the [RustSec advisory database](https://rustsec.org/)
at each release. The gate is `--deny warnings`: any known vulnerability blocks the
release, with no exceptions.

**2. Licence and ban policy (`cargo deny`)**  
`deny.toml` enforces the licence whitelist (MIT / Apache-2.0 / BSD / ISC / Zlib)
and blocks GPL-2.0 and LGPL-without-exception, which are incompatible with
Runbound's AGPL-3.0 / commercial dual-licence model and with Rust static linking.
Wildcard version requirements are banned; only crates.io sources are allowed.

**3. SBOM (Software Bill of Materials)**  
A `sbom.cdx.json` file (CycloneDX 1.4 format) listing all transitive dependencies
with version, hash, and licence is attached to every GitHub release. Enterprise
customers and security auditors can use it to verify the full dependency tree
without rebuilding.

```bash
make audit       # cargo audit --deny warnings
make deny        # cargo deny check (licence + advisory + ban policy)
make sbom        # generate sbom.cdx.json
make audit-full  # all three + cargo outdated
```

→ Full audit process, release procedure, and manual review areas: [docs/audit.md](audit.md)

---

## Reporting a vulnerability

Send a report to **redlemonbe@codix.be** with subject line `[SECURITY] Runbound`.
Please include a description of the vulnerability, reproduction steps, and
your assessment of its impact. We aim to respond within 48 hours.

Do not open a public GitHub issue for security vulnerabilities.
