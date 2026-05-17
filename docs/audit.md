# Audit Process

Runbound applies defence-in-depth to its own supply chain.
This document describes the tooling, frequency, and procedures used to keep the
dependency tree clean of known vulnerabilities, licence violations, and stale crates.

---

## Tools

| Tool | Purpose | Install |
|---|---|---|
| `cargo audit` | CVE / RUSTSEC advisory scan | `cargo install cargo-audit` |
| `cargo deny` | Licence policy + advisory gate + ban rules | `cargo install cargo-deny` |
| `cargo cyclonedx` | SBOM generation (CycloneDX 1.4, JSON) | `cargo install cargo-cyclonedx` |
| `cargo outdated` | Stale dependency detection | `cargo install cargo-outdated` |

---

## Recommended frequency

| Check | When |
|---|---|
| `cargo audit` | At every release **and** weekly in CI |
| `cargo deny` | At every dependency addition or `Cargo.lock` update |
| SBOM | Generated automatically at every git tag |
| `cargo outdated` | Monthly, and before each minor/major release |

---

## Makefile targets

```bash
make audit       # cargo audit --deny warnings (zero CVE gate)
make deny        # cargo deny check (licence + advisory + bans)
make sbom        # cargo cyclonedx → sbom.cdx.json
make audit-full  # audit + deny + sbom + cargo outdated
```

---

## Reproducibility

**Cargo.lock is committed** — every build resolves to the exact same versions.
Dependency updates are a conscious, audited step, not a side-effect of `cargo update`.

**Rust toolchain:** pin the compiler version in `rust-toolchain.toml`:

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

This prevents silent breakage when new toolchains are released between CI runs.

---

## Critical third-party dependencies (manual review on each update)

These crates sit on the security-critical path. Every version bump requires a
manual check of the RUSTSEC advisory database and the upstream changelog before
merging.

| Crate | Why it matters |
|---|---|
| `rustls` / `rustls-webpki` | TLS stack — any CVE here breaks DoT/DoH/DoQ security |
| `tokio` | Async runtime — attack surface for all network I/O |
| `hickory-server` / `hickory-resolver` | DNS parsing — processes untrusted network input |
| `axum` / `hyper` | HTTP server — injection, path traversal, request smuggling |
| `serde_json` | JSON deserialisation — parses external (API) input |
| `ring` | Cryptographic backend — used by rustls for AEAD/HMAC |
| `rcgen` / `instant-acme` | Certificate management — ACME key handling |

---

## Release procedure

Before tagging any release, the following gates must pass with zero errors:

```bash
# 1. Zero known CVEs
cargo audit --deny warnings

# 2. Zero licence or ban violations
cargo deny check

# 3. Generate SBOM and attach to the GitHub release
cargo cyclonedx --format json --output sbom.cdx.json
# → upload sbom.cdx.json as a release asset

# 4. Tag with GPG signature
git tag -s v0.X.Y -m "release v0.X.Y"
git push origin v0.X.Y
```

Failing any of steps 1–2 blocks the release.

---

## SBOM (Software Bill of Materials)

The file `sbom.cdx.json` (CycloneDX 1.4 format) lists every transitive dependency
with its version, source hash, and licence. It is attached to every GitHub release
as a release asset.

**Use cases:**

- Enterprise customers and government agencies can verify the full dependency tree
  independently.
- Security auditors (CSPN, Common Criteria EAL) can cross-reference component
  versions against their own CVE databases.
- Incident response: if a new advisory is published for a transitive dependency,
  the SBOM lets operators immediately determine whether they are affected without
  rebuilding.

**Download:** available on the [GitHub releases page](https://github.com/redlemonbe/Runbound/releases/latest)
as `sbom.cdx.json`.

---

## Licence policy

Runbound is dual-licensed under AGPL-3.0 and a commercial licence.
The dependency licence policy (enforced by `deny.toml`) is:

**Allowed:** MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib, Unicode-DFS-2016, OpenSSL  
**Blocked:** GPL-2.0, LGPL without linking exception (incompatible with static linking
and with the commercial dual-licence model)

Any dependency addition that introduces a blocked licence will cause `cargo deny check`
to fail, preventing the merge.

---

## Manual source audit: priority areas

For formal audits (CSPN, Common Criteria EAL, enterprise security review),
the following source areas have the largest attack surface and should be
reviewed first:

| Area | File(s) | What to look for |
|---|---|---|
| Constant-time auth | `src/api/mod.rs` → `constant_time_eq` | Timing side-channels in Bearer token comparison |
| SSRF prevention | `src/dns/server.rs` → `SsrfSafeDnsResolver` | IP/domain validation completeness |
| Store integrity | `src/store.rs` | HMAC verification before deserialisation |
| DNS name parsing | `src/api/mod.rs` → `validate_dns_name` | Label length, charset, RFC 1035 boundaries |
| DNS query handler | `src/dns/server.rs` | ACL bypass, amplification vectors, identity probes |
| Sync/replication | `src/sync.rs` | Authentication, cert pinning, race conditions |

See [security-audit.md](security-audit.md) for the complete white-box audit report.
