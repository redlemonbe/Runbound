# Security Policy

## Status

Runbound is **experimental** and has **not** undergone an external human security
audit. See [METHODOLOGY.md](METHODOLOGY.md) for the development approach and
[THREAT_MODEL.md](THREAT_MODEL.md) for the threat model and planned hardening.

## Supported versions

Only the **latest released version** receives security fixes — there is no LTS.

| Version | Supported |
|---------|-----------|
| 0.24.x  | ✅ |
| < 0.23  | ❌ |

## Reporting a vulnerability

Please report privately via **GitHub Private Vulnerability Reporting**:
<https://github.com/redlemonbe/Runbound/security/advisories/new>

Do **not** open a public issue for security problems. Reports are handled on a
**best-effort** basis.

> Runbound is distributed under **AGPL-3.0 with no warranty** (see `LICENSE`,
> sections 15–16): under the open-source license there is no legal or contractual
> obligation to fix or disclose within a fixed timeframe. **Commercial-license**
> customers receive firm, contractual SLAs (e.g. critical fixes within 48 h — see
> [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md)).

## Cryptography

- **Transport** (DoT / DoH / DoQ, master↔slave sync, WebUI): TLS via **rustls 0.23**
  — **TLS 1.2 and 1.3 only** (no SSLv3 / TLS 1.0 / 1.1).
- **WebUI password hashing:** argon2id (m=19456, t=2, p=1).
- **Sync relay authentication:** HMAC-SHA256 with anti-replay (timestamp ±30 s) and
  TOFU certificate-fingerprint pinning.
- **Audit log:** optional HMAC-SHA256 hash-chained, tamper-evident.
- **WebUI ↔ API:** HTTP-only session cookies + CSRF tokens on mutating requests.
- **DNSSEC signing:** in-house ECDSA P-256 signer on `ring` (RFC 6605 / 4034 / 5155 / 9276),
  served wire-native on the default path.
- **TSIG (RFC 8945):** HMAC on `ring`, with constant-time key-name lookup
  (`subtle::ConstantTimeEq`).

## Built-in hardening

- **DNS amplification:** `ANY` queries are refused (REFUSED) to mitigate amplification; per-source-IP query
  rate limiting (`rate-limit`, with configurable v4/v6 prefix bucketing).
- **DNS rebinding:** `private-address` CIDRs are stripped from upstream answers.
- **Cache poisoning:** the forward path validates the upstream response transaction-ID and
  question before accepting it.
- **Reduced attack surface (v0.23):** the default build is **fully hickory-free at
  runtime** — DNS is served by the in-house wire codec (`serve_wire`), and recursion +
  DNSSEC validation (RRSIG verification, DS/DNSKEY chain-of-trust, NSEC/NSEC3 denial)
  are entirely in-house (`dns::recursor_wire`, `dns::dnssec_*`), on by default. There
  is no `recursor` Cargo feature. `hickory-proto` remains only as a dev-dependency for
  differential oracle tests (`cargo tree -e normal` is hickory-free).
- **Access control:** `access-control` ACLs; the REST API binds to localhost only
  (the WebUI server proxies `/api/*` internally). The WebUI itself binds `127.0.0.1` by
  default (`ui-bind`); network exposure requires an explicit `ui-bind: 0.0.0.0`. For
  TCP/DoT/DoH the real client IP is carried to the handler via a PROXY v2 header so
  `axfr-allow` and split-horizon evaluate the true source.
- **systemd:** the shipped unit runs as a non-root `runbound` user with a least-privilege
  `CapabilityBoundingSet`/`AmbientCapabilities` of **`CAP_NET_BIND_SERVICE`** only,
  `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`. The XDP fast path and the
  firewall-manage feature need `CAP_NET_RAW`/`CAP_NET_ADMIN`/`CAP_BPF`/`CAP_PERFMON` — an
  explicit, commented opt-in.
- **Bot/scanner defense:** honeypot trap routes with configurable banning.
- **Supply chain:** release binaries are signed with **minisign** and ship a
  **CycloneDX SBOM** plus `SHA256SUMS`; reproducible-build and signature-verification
  steps are in [docs/BUILD.md](docs/BUILD.md). `cargo audit` / `cargo deny` are configured
  (`deny.toml`/`audit.toml`) and available via `make audit` / `make deny`, but are not yet
  wired into the GitHub Actions CI workflow.

## Known limitations

- No external human security audit yet.
- Strict Response Rate Limiting (RFC 5358) is not implemented (ANY-block + per-IP
  query limiting only).
- The REST API default transport is a bearer token over localhost HTTP; an
  owner-only Unix socket (mode 0600, `api-socket`) is available as a hardened
  alternative (localhost mTLS is on the roadmap).
