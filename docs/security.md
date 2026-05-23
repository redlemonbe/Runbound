# Security Architecture

This document covers the security model, defensive layers, and all audit findings
fixed across Runbound releases through v0.6.8.

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
│  Rate limiter (token bucket, /48 for IPv6)          │  ← per-source-IP, DashMap+ahash
│  TCP per-IP connection cap (20, /48 for IPv6)       │  ← pre-accept filter, loopback relay
│  Inflight semaphore (max 4096)                      │  ← hard OOM backstop
├─────────────────────────────────────────────────────┤
│  AF/XDP fast path (default on)                      │  ← local-zone answered in user   │
│    ACL + rate limit enforced before any reply       │    space, XDP_PASS for recursive  │
├─────────────────────────────────────────────────────┤
│  DNS engine (hickory-server 0.26)                   │
│  Zone lookup / forwarding                           │
│  CPU-pinned workers (physical cores, HT excluded)   │  ← per-core tokio + DNS workers
└─────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  REST API (port 8080, localhost only)               │
│  Body size check before rate limit (Content-Length) │  ← 413 before 429
│  Bearer token (timing-safe cmp)                     │  ← subtle::ConstantTimeEq
│  /reload independent rate limit (2 RPS)             │  ← dedicated token bucket
│  Entry limits (10k DNS, 100k BL)                   │
│  Error bodies sanitised (no FS paths)               │  ← sanitize_error()
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
- Setting `rate-limit: 0` **disables** rate limiting entirely — every query is passed without
  a bucket check. On public-facing resolvers, this is not recommended.

**IPv6 /48 prefix aggregation (v0.4.16, VUL-6.1):** IPv6 source addresses are truncated to
their /48 prefix before bucket lookup. A flood from a single routed /48 block (up to 65 536
host addresses) fills at most one bucket instead of exhausting all 65 536 table slots.
IPv4 addresses use the full /32. This prevents a bucket-exhaustion attack where an attacker
fills the table from one network block, causing all subsequent IPs to bypass rate limiting.

---

## TCP connection cap (v0.4.16, VUL-6.2)

A pre-accept filter limits the number of concurrent TCP DNS connections per source IP to
**20 connections** (`TCP_CONN_PER_IP_MAX`). Connections that exceed the cap are dropped
immediately after a rate-throttled warning log.

**Architecture — loopback relay:** A relay listener sits between the public TCP port and
hickory-server's internal TCP listener (bound on `127.0.0.1:0`). The relay's accept loop:
1. Checks the per-IP counter in a `DashMap<IpAddr, Arc<AtomicU16>>` (with `/48` aggregation
   for IPv6).
2. If the cap is reached, drops the connection.
3. Otherwise increments the counter, opens a connection to hickory's loopback listener, proxies
   the session via `tokio::io::copy_bidirectional`, then decrements the counter on close.

Loopback addresses (`127.x.x.x`, `::1`) are exempt from the cap.

This prevents FD exhaustion attacks where a single source opens thousands of TCP connections to
exhaust the process file-descriptor limit and deny service to all clients.

---

## Anti-OOM memory protection

Runbound has two independent, always-active defences against memory exhaustion:

### 1. Inflight concurrency semaphore

Hard cap of **4,096 concurrent in-flight requests**. When the semaphore is exhausted,
new requests receive REFUSED immediately without allocating any additional memory.

### 2. Memory pressure guard

A background task reads `/proc/meminfo` every **30 seconds** and operates in four
bands based on `used = 1 − MemAvailable / MemTotal`:

| Band | Action |
|---|---|
| **< 60 %** | Scale up: restore cache toward optimal size (5-minute cooldown between upscales) |
| **60 – 70 %** | Stable — no action |
| **70 – 80 %** | Moderate pressure: halve cache size (floor 512 entries) |
| **≥ 80 %** | High pressure: recalculate cache from current RAM + flush rate-limiter buckets |

Cache changes take effect by rebuilding the hickory resolver and atomically swapping
it via **ArcSwap**. In-flight queries keep their `Arc` reference until completion —
no query is dropped mid-flight.

**Auto-sized cache at startup:** cache capacity is computed from `MemAvailable`
at launch (10 % of available RAM ÷ 512 B per entry), clamped to **[512, 65 536]**
entries. Falls back to 8 192 when `/proc/meminfo` is unavailable.

On non-Linux systems or containers without `/proc/meminfo`, the guard silently
skips its check.

```
WARN memory pressure — cache halved  used_pct=74.2%  cache_from=8192  cache_to=4096
WARN memory pressure high — cache flushed, resized, rate limiter cleared
     used_pct=82.3%  cache_from=4096  cache_to=2048  freed_buckets=8241
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

**`/reload` rate limit (v0.4.16, VUL-3.2):** `POST /reload` has a dedicated token bucket
(2 RPS, burst 2) separate from the general API limiter. This prevents an authenticated caller
from sustaining a burst of expensive zone-set rebuilds. Callers that exceed the rate receive
HTTP 429 `{"error": "RATE_LIMITED"}`.

**Error body sanitisation (v0.4.16, VUL-3.4):** HTTP 500 error bodies pass through
`sanitize_error()`, which replaces any error string containing `/` with `"internal error"`.
This prevents file-system paths (e.g.,
`failed to open file /etc/runbound/dns_entries.json: No such file or directory`) from
leaking to authenticated API callers. The full error is always logged at `WARN` level.

**Input validation:**
- DNS `name` and domain-type `value` fields (CNAME, MX, NS, PTR, SRV targets)
  are validated against RFC 1035 rules: max 253 chars, labels max 63 chars,
  valid label characters only, no control characters.
  A trailing FQDN dot (`example.com.`) is stripped before the 253-char check —
  submitting a 253-char domain with a trailing dot (= 254 bytes) is therefore
  accepted, because the actual domain length is 253 chars. A true 254-char name
  without a trailing dot is rejected. Integration tests `dns_name_254_chars_is_rejected`
  and `blacklist_name_254_chars_is_rejected` prove this boundary end-to-end.
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

## CPU affinity

Runbound pins each worker thread to a distinct **physical CPU core**, with
HyperThreading siblings excluded. This applies to both:

- **Tokio async workers** — the runtime thread pool is sized to the physical
  core count and each thread is pinned via `sched_setaffinity(2)`.
- **DNS socket workers** — one `SO_REUSEPORT` UDP socket per physical core.

Core topology is read from
`/sys/devices/system/cpu/cpuN/topology/core_id`. When `/sys` is unavailable
(containers, non-Linux), the affinity step is silently skipped and the process
continues with OS-scheduled threads.

CPU affinity can be disabled in `unbound.conf`:

```
cpu-affinity: no   # default: yes
```

---

## XDP path security

**Default-on since v0.4.14.** The AF/XDP fast path intercepts UDP port-53 packets
at the NIC driver level via an eBPF XDP program, answers **local-zone queries
entirely in user space**, and returns `XDP_PASS` for everything else (recursive
queries, AAAA on an A-only name, ANY, etc.) so they continue up through the normal
hickory-server path.

**ACL and rate-limit enforcement in XDP:** Both checks run inside the XDP worker
before any DNS response is constructed.
- `Deny` ACL rule → silent drop (`XDP_DROP`).
- `Refuse` ACL rule → REFUSED frame crafted and sent directly from the worker.
- Rate-limit exceeded → REFUSED frame, same as the kernel path.

**UMEM descriptor bounds (v0.4.16, VUL-2.1):** `frame_mut()` and `frame()` in
`src/dns/xdp/umem.rs` now return `Option<&mut [u8]>` / `Option<&[u8]>` with a hard
release-mode bounds check (`saturating_add`) instead of the previous `debug_assert!` which
compiled to a no-op in release builds. The XDP worker also adds an explicit bounds check
before raw-pointer UMEM slice construction. Malformed or kernel-corrupt descriptors are
silently skipped instead of producing undefined behaviour.

**Systemd requirements:** `LimitMEMLOCK=infinity` is required in the service file
for AF/XDP UMEM allocation. The provided `runbound.service` sets this automatically.
`install.sh` detects Intel XDP-native NICs (ixgbe/i40e/ice/igc) and configures
the appropriate capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`, `CAP_BPF`).

**Fallback:** If XDP initialisation fails (missing capabilities, unsupported NIC,
kernel < 5.10), Runbound logs a descriptive `WARN` with an actionable hint and
continues on the `SO_REUSEPORT` kernel path. The process does not panic.

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
| `/etc/runbound/unbound.conf` (or `runbound.conf`) | `640` | Contains no secrets when using env vars |
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

### v0.4.2

| ID | Severity | Title | Fixed in |
|---|---|---|---|
| BUG-01b | Blocking | Replicated DNS entries returned NXDOMAIN on slave nodes | v0.4.2 |

### v0.4.3

| ID | Severity | Title | Fixed in |
|---|---|---|---|
| AUDIT-SEC-02 | Info | Domain name 253-char boundary (false positive — confirmed with unit tests) | v0.4.3 |
| AUDIT-SEC-03 | Low | `version.bind` CHAOS class → NOERROR (hickory class normalisation) | v0.4.3 |
| AUDIT-SEC-04 | Low | 5 MB payload → connection drop without 413 (Content-Length check added) | v0.4.3 |
| AUDIT-DOC-01 | Info | README referenced v0.3.4 binary names | v0.4.3 |
| AUDIT-DOC-02 | Info | 4 runtime constants undocumented (body limit, rate limit, sync ring, purge %) | v0.4.3 |
| AUDIT-DOC-03 | Info | ha.md missing slave DNS behaviour section | v0.4.3 |

### v0.4.4

| ID | Severity | Title | Fixed in |
|---|---|---|---|
| FEAT-HSM | — | HSM key storage via PKCS#11 (API key + store HMAC key, `cryptoki 0.6`) | v0.4.4 |
| FEAT-AUDIT | — | Supply-chain audit tooling: `cargo-deny`, SBOM, `audit-full` Makefile target | v0.4.4 |

### v0.4.5

| ID | Severity | Title | Fixed in |
|---|---|---|---|
| PENTEST-HIGH | High | Timing oracle on Bearer token — pre-auth sleep + async side effects | v0.4.5 |
| PENTEST-SEC02 | Info | Domain 253-char boundary (confirmed false positive + HTTP integration tests) | v0.4.5 |
| PENTEST-SEC04 | Low | JSON POST without `Content-Length` → 411 (eliminates chunked TCP drop) | v0.4.5 |
| PENTEST-LOW | Low | Null byte in URL path → TCP drop (hyper parse layer, documented) | v0.4.5 |

### v0.4.6

| ID | Severity | Title | Fixed in |
|---|---|---|---|
| QUAL-05 | — | `main()` decomposed: 344-line function split into `handle_cli_flags()`, `init_runtime()`, `build_and_launch()` | v0.4.6 |
| QUAL-06 | — | `handle_request()` split into `handle_local_zone()` + `resolve_upstream()`, Result-based handler ownership | v0.4.6 |
| QUAL-07 | — | `add_dns_handler()` split: `validate_dns_entry()` + `persist_and_swap()` extracted | v0.4.6 |
| QUAL-08 | — | `metrics_handler()` split: `fmt_counter()`, `fmt_gauge()`, `render_prometheus_metrics()` extracted | v0.4.6 |
| PERF-02 | — | Zero-alloc identity-probe: `OnceLock<[LowerName; 4]>` eliminates a `String` allocation per DNS request | v0.4.6 |
| PERF-03 | — | `BIND_V4`/`BIND_V6` now `const SocketAddr`, removing `.parse().unwrap()` in hot probe path | v0.4.6 |

### v0.4.7

| ID | Severity | Title | Fixed in |
|---|---|---|---|
| BUG-RATELIMIT | Medium | `rate-limit: 0` refused every query instead of disabling rate limiting | v0.4.7 |

### v0.4.8

| ID | Severity | Title | Fixed in |
|---|---|---|---|
| FEAT-AFFINITY | — | CPU affinity for tokio workers and DNS socket workers — physical cores, HT excluded | v0.4.8 |

### v0.4.9

| ID | Severity | Title | Fixed in |
|---|---|---|---|
| FEAT-CACHE-AUTO | — | Cache auto-sized from `MemAvailable` at startup (10 %, clamped [512, 65 536]) | v0.4.9 |
| FEAT-MEMGUARD | — | Memory guard upgraded to 4-band system (< 60 / 60–70 / 70–80 / ≥ 80 %) | v0.4.9 |
| FEAT-WORKERS | — | DNS socket workers use physical core count (consistent with tokio affinity) | v0.4.9 |

### v0.4.14

| ID | Severity | Title | Fixed in |
|---|---|---|---|
| FEAT-XDP | — | AF/XDP kernel-bypass fast path — local-zone queries answered in user space at NIC driver level | v0.4.14 |
| FIX-XDP-VERIFIER | — | eBPF program rewritten with constant IHL=20 — eliminates BPF verifier rejection on variable pointer arithmetic | v0.4.14 |
| FIX-XDP-UMEM | — | `LimitMEMLOCK=infinity` added to `runbound.service` — fixes UMEM allocation failure under systemd sandboxing | v0.4.14 |
| FIX-XDP-FALLBACK | — | XDP init failure now logs actionable `WARN` and falls back to SO_REUSEPORT — process no longer panics | v0.4.14 |

### v0.4.16

| ID | Severity | Title | Fixed in |
|---|---|---|---|
| VUL-2.1 | Medium | UMEM bounds enforced only in debug builds — `debug_assert!` → release-mode `Option` return | v0.4.16 |
| VUL-6.1 | Medium | IPv6 /128 buckets exhaust rate-limit table — per-/48 normalisation added | v0.4.16 |
| VUL-6.2 | Low | No per-source-IP TCP connection cap — `TcpConnTracker` added (20 connections, loopback relay) | v0.4.16 |
| VUL-3.4 | Low | API error bodies exposed file-system paths — `sanitize_error()` added at 8 sites | v0.4.16 |
| VUL-3.2 | Low | `/reload` endpoint not independently rate-limited — dedicated 2 RPS token bucket added | v0.4.16 |

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

→ Full Rust code audit (quality, performance, architecture): [docs/code-audit.md](code-audit.md)

---

## Known limitations

### TCP rate limiting — loopback proxy (VUL-NEW-02)

**Status:** Accepted design trade-off — not a vulnerability, documented for transparency.

The TCP relay architecture (public TcpListener → loopback relay → hickory-server) causes
hickory to see `127.0.0.1` as the source for all relayed TCP connections. The per-IP DNS
rate limiter therefore uses a shared loopback bucket for all TCP clients rather than
individual per-client buckets.

**Impact:** A client sending many queries over DNS/TCP, DoT, or DoH can consume the shared
loopback rate-limit bucket, potentially affecting the measured rate for other TCP clients.

**Mitigations in place:**
- The TCP connection cap (`TCP_CONN_PER_IP_MAX = 20` per source IP) is the primary DoS
  control and is applied before the relay, so FD exhaustion attacks are blocked at source.
- TCP is inherently low-volume; most DNS traffic uses UDP.
- The loopback rate-limit bucket is sized generously (same `rps` × burst as any single IP).

**Resolution path:** Replacing the relay with an in-process per-query source-IP annotation
inside hickory-server would eliminate the limitation; this requires a non-trivial upstream
change or a custom hickory fork and is deferred.

---

## Reporting a vulnerability

Send a report to **redlemonbe@codix.be** with subject line `[SECURITY] Runbound`.
Please include a description of the vulnerability, reproduction steps, and
your assessment of its impact. We aim to respond within 48 hours.

Do not open a public GitHub issue for security vulnerabilities.
