# Security Policy

## Status

Runbound is **experimental** and has **not** undergone an external human security
audit. See [METHODOLOGY.md](METHODOLOGY.md) for the development approach and
[THREAT_MODEL.md](THREAT_MODEL.md) for the threat model and planned hardening.

## Supported versions

Only the **latest released version** receives security fixes — there is no LTS.

| Version | Supported |
|---------|-----------|
| 0.15.x  | ✅ |
| < 0.15  | ❌ |

## Reporting a vulnerability

Please report privately via **GitHub Private Vulnerability Reporting**:
<https://github.com/redlemonbe/Runbound/security/advisories/new>

Do **not** open a public issue for security problems. Reports are handled on a
**best-effort** basis.

> Runbound is distributed under **AGPL-3.0 with no warranty** (see `LICENSE`,
> sections 15–16): under the open-source license there is no legal or contractual
> obligation to fix or disclose within a fixed timeframe. **Commercial-license**
> customers receive firm, contractual SLAs (e.g. critical fixes within 48 h — see
> [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md)). A formal open-source disclosure
> policy is being defined (issue #178).

## Cryptography

- **Transport** (DoT / DoH / DoQ, master↔slave sync, WebUI): TLS via **rustls 0.23**
  — **TLS 1.2 and 1.3 only** (no SSLv3 / TLS 1.0 / 1.1).
- **WebUI password hashing:** argon2id (m=19456, t=2, p=1).
- **Sync relay authentication:** HMAC-SHA256 with anti-replay (timestamp ±30 s) and
  TOFU certificate-fingerprint pinning.
- **Audit log:** optional HMAC-SHA256 hash-chained, tamper-evident.
- **WebUI ↔ API:** HTTP-only session cookies + CSRF tokens on mutating requests.

## Built-in hardening

- **DNS amplification:** `ANY` queries are refused (REFUSED) to mitigate amplification; per-source-IP query
  rate limiting (`rate-limit`, with configurable v4/v6 prefix bucketing).
- **DNS rebinding:** `private-address` CIDRs are stripped from upstream answers.
- **Access control:** `access-control` ACLs; the REST API binds to localhost only
  (the WebUI server proxies `/api/*` internally).
- **systemd:** the shipped unit runs as a non-root `runbound` user with a scoped
  `CapabilityBoundingSet` (`CAP_NET_BIND_SERVICE`, `CAP_NET_RAW`, `CAP_NET_ADMIN`,
  `CAP_BPF`), `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`.
- **Bot/scanner defense:** honeypot trap routes with configurable banning.
- **Supply chain:** release binaries are signed with **minisign** and ship a
  **CycloneDX SBOM** plus `SHA256SUMS`; reproducible-build and signature-verification
  steps are in [docs/BUILD.md](docs/BUILD.md). `cargo audit` / `cargo deny` run in CI.

## Known limitations

- No external human security audit yet.
- Strict Response Rate Limiting (RFC 5358) is not implemented (ANY-block + per-IP
  query limiting only).
- The REST API default transport is a bearer token over localhost HTTP; an
  owner-only Unix socket (mode 0600, `api-socket`) is available as a hardened
  alternative (localhost mTLS is on the roadmap).
