# Security Policy

## Status

Runbound is **experimental** and has **not** undergone an external human security
audit. It is not yet recommended for production deployments handling sensitive
traffic. See [METHODOLOGY.md](METHODOLOGY.md) for the development approach and
[docs/ROADMAP-SOUVERAINETE.md](docs/ROADMAP-SOUVERAINETE.md) for planned hardening.

## Supported versions

Only the **latest released version** receives security fixes — there is no LTS.

| Version | Supported |
|---------|-----------|
| 0.12.x  | ✅ |
| < 0.12  | ❌ |

## Reporting a vulnerability

Please report privately via **GitHub Private Vulnerability Reporting**:
<https://github.com/redlemonbe/Runbound/security/advisories/new>

Do **not** open a public issue for security problems. We aim to acknowledge within
7 days. (A maintainer contact email and a firm disclosure SLA will be added as the
project matures.)

## Cryptography

- **Transport** (DoT / DoH / DoQ, master↔slave sync, WebUI): TLS via **rustls 0.23**
  — **TLS 1.2 and 1.3 only** (no SSLv3 / TLS 1.0 / 1.1).
- **WebUI password hashing:** argon2id (m=19456, t=2, p=1).
- **Sync relay authentication:** HMAC-SHA256 with anti-replay (timestamp ±30 s) and
  TOFU certificate-fingerprint pinning.
- **Audit log:** optional HMAC-SHA256 hash-chained, tamper-evident.
- **WebUI ↔ API:** HTTP-only session cookies + CSRF tokens on mutating requests.

## Built-in hardening

- **DNS amplification:** `ANY` queries are refused (RFC 8482); per-source-IP query
  rate limiting (`rate-limit`, with configurable v4/v6 prefix bucketing).
- **DNS rebinding:** `private-address` CIDRs are stripped from upstream answers.
- **Access control:** `access-control` ACLs; the REST API binds to localhost only
  (the WebUI server proxies `/api/*` internally).
- **systemd:** the shipped unit runs as a non-root `runbound` user with a scoped
  `CapabilityBoundingSet` (`CAP_NET_BIND_SERVICE`, `CAP_NET_RAW`, `CAP_NET_ADMIN`,
  `CAP_BPF`), `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`.
- **Bot/scanner defense:** honeypot trap routes with configurable banning.

## Known limitations

- No external human security audit yet.
- No reproducible build or signed release binaries yet.
- Strict Response Rate Limiting (RFC 5358) is not implemented (ANY-block + per-IP
  query limiting only).
- The REST API uses a bearer token over localhost HTTP (a Unix socket / localhost
  mTLS is on the roadmap).
