# Security Architecture

This document covers the security model, defensive layers, and the audit findings
fixed in version 0.2.0.

---

## Defensive layers

```
Internet / LAN
      │
      ▼
┌─────────────────────────────────────┐
│  ACL check (allow / deny / refuse)  │  ← per-subnet rules, IPv4+IPv6
│  Rate limiter (token bucket)        │  ← per-source-IP, DashMap+ahash
│  Inflight semaphore (max 4096)      │  ← hard OOM backstop
├─────────────────────────────────────┤
│  XDP fast path (optional)           │  ← same ACL + rate limit enforced
├─────────────────────────────────────┤
│  DNS engine (hickory-server)        │
│  Zone lookup / forwarding           │
└─────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────┐
│  REST API (port 8081, configurable)  │
│  Bearer token (timing-safe cmp)     │  ← subtle::ConstantTimeEq
│  Entry limits (10k DNS, 100k BL)    │
│  zones_mutex (atomic write+swap)    │
└─────────────────────────────────────┘
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

## Inflight semaphore

Hard cap of **4,096 concurrent in-flight requests**. When the semaphore is exhausted,
new requests receive REFUSED immediately without allocating any memory. This prevents
OOM under DNS flood conditions.

---

## REST API security

**Authentication:** Bearer token via `Authorization` header. Compared using
`subtle::ConstantTimeEq` — not vulnerable to timing attacks.

**API key management:**
```bash
# Set via environment variable — never write in config files
export RUNBOUND_API_KEY="$(openssl rand -hex 32)"
```

**Entry limits:** Enforced server-side to prevent authenticated DoS:
- DNS entries: max 10,000
- Blacklist entries: max 100,000

**Concurrent write safety (SEC-01):** The entire load → validate → write → ArcSwap
sequence is performed inside `zones_mutex`. Two concurrent API writes cannot
overwrite each other.

---

## Feed security

**SSRF protection (SEC-04):** A custom `reqwest` redirect policy blocks:
- HTTPS → HTTP downgrades
- Redirects to private or loopback IP addresses (`10.x`, `172.16.x`, `192.168.x`,
  `127.x`, `169.254.x`, `::1`, etc.)

**TOCTOU re-validation (SEC-05):** Feed URLs are re-validated on every fetch, not
just at subscription time. A compromised feed record cannot redirect to a private
address after being subscribed.

**HTTPS enforcement (v0.2.5):** HTTP feed URLs are **rejected with 400 Bad Request** —
only `https://` URLs are accepted. This prevents man-in-the-middle injection of malicious
block-list data at the API layer before any network connection is made.

**File permissions (SEC-07):** Serialised feed files are written with `chmod 640` —
owner and group readable only.

---

## XDP path security

**ACL enforcement in XDP (SEC-02):** The AF/XDP fast path applies the full ACL before
answering any query. There is no bypass. `Deny` → silent drop; `Refuse` → REFUSED
frame crafted directly in the XDP worker.

---

## File permissions reference

| File | Recommended permissions | Owner |
|---|---|---|
| `/etc/runbound/runbound.conf` | `640` | `runbound:runbound` |
| `/etc/runbound/env` (API key) | `640` | `runbound:runbound` |
| `/etc/runbound/key.pem` (TLS key) | `640` | `runbound:runbound` |
| `/etc/runbound/cert.pem` | `644` | `runbound:runbound` |
| `/var/lib/runbound/*.json` (store) | `640` | `runbound:runbound` |
| `/var/log/runbound/` | `750` | `runbound:runbound` |

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

## Audit findings (v0.2.0)

| ID | Severity | Title | Status |
|---|---|---|---|
| SEC-01 | High | Race condition on concurrent API writes | ✅ Fixed |
| SEC-02 | High | XDP fast path bypassed ACL entirely | ✅ Fixed |
| SEC-03 | Medium | IPv4-mapped IPv6 skipped ACL rules | ✅ Fixed |
| SEC-04 | Medium | SSRF via HTTP redirect in feed fetcher | ✅ Fixed |
| SEC-05 | Medium | TOCTOU on feed URL validation | ✅ Fixed |
| SEC-06 | Medium | Unbounded data-store growth | ✅ Fixed |
| SEC-07 | Low | Feed data files world-readable | ✅ Fixed |
| SEC-08 | Low | Plaintext HTTP feeds accepted silently | ✅ Fixed |

---

## Reporting a vulnerability

Send a report to **redlemonbe@codix.be** with subject line `[SECURITY] Runbound`.
Please include a description of the vulnerability, reproduction steps, and
your assessment of its impact. We aim to respond within 48 hours.

Do not open a public GitHub issue for security vulnerabilities.
