# Supply-Chain & Security Audit — Runbound

This document describes the tooling, cadence, and procedures used to keep Runbound's
dependency tree free of known vulnerabilities, licence violations, and stale crates,
and to guide internal or third-party source-code audits.

> **Audit reports** live under [`docs/security-audit/`](security-audit/): the
> white-box report ([`SECURITY-AUDIT.md`](security-audit/SECURITY-AUDIT.md))
> and the aggressive pentest (PENT-1, consolidated into [`SECURITY-AUDIT.md`](security-audit/SECURITY-AUDIT.md)).
> Those files are point-in-time snapshots — do not rewrite them.

---

## Tools

| Tool | Purpose | Install |
|---|---|---|
| [`cargo audit`](https://github.com/rustsec/rustsec/tree/main/cargo-audit) | CVE / RUSTSEC advisory scan | `cargo install cargo-audit` |
| [`cargo deny`](https://github.com/EmbarkStudios/cargo-deny) | Licence policy + advisory gate + ban rules | `cargo install cargo-deny` |
| [`cargo cyclonedx`](https://github.com/CycloneDX/cyclonedx-rust-cargo) | SBOM generation (CycloneDX 1.4, JSON) | `cargo install cargo-cyclonedx` |
| [`cargo outdated`](https://github.com/kbknapp/cargo-outdated) | Stale dependency detection | `cargo install cargo-outdated` |

---

## Makefile targets

```bash
make audit       # cargo audit --deny warnings      — zero-CVE gate
make deny        # cargo deny check                 — licence + advisory + ban policy
make sbom        # cargo cyclonedx → sbom.cdx.json  — full dependency inventory
make audit-full  # runs all three above + cargo outdated
```

---

## Recommended cadence

| Check | Trigger |
|---|---|
| `make audit` | Every release, run manually (not currently CI-scheduled — see below) |
| `make deny` | Every dependency addition or `Cargo.lock` change, run manually |
| `make sbom` | Every git tag (CI runs `cargo cyclonedx` in `release.yml`, attaches `sbom.cdx.json` as a release asset) |
| `cargo outdated` | Monthly + before any minor or major release, run manually |

None of `make audit`/`make deny`/`cargo outdated` are wired into a scheduled or
per-push CI workflow today. The only cron-scheduled workflow in `.github/workflows/`
is `fuzz.yml` (`cron: '0 2 * * 1'`, weekly), and it only runs `cargo fuzz` targets
(`fuzz_dns_query`, `fuzz_config`, `fuzz_api_json`, `fuzz_dns_name`) — it does not run
`cargo audit` or `cargo deny`. `.github/workflows/ci.yml` runs on push/PR and only does
a SECURITY.md/Cargo.toml version-drift check, `cargo build --release`, `cargo clippy`,
and `cargo test` — no audit, no deny. The cadence above is a recommendation for the
maintainer to run locally, not an enforced schedule.

---

## Reproducibility

**`Cargo.lock` is committed.** Every build resolves to the exact same crate versions.
Dependency updates are a conscious, audited step — not a side-effect of a stale lockfile.

> **Keep the lockfile in sync:** ensure `Cargo.lock`'s own `runbound` package entry
> matches the version in `Cargo.toml` before every release. Any `cargo build`/`cargo
> check` rewrites the local package entry; commit the result. `hickory-resolver`/
> `hickory-server` are absent from the lockfile; only `hickory-proto` is present, and
> only as a transitive dev-dependency (see `Cargo.toml`'s `[dev-dependencies]`).

**Rust toolchain pinning.** Pin the compiler in `rust-toolchain.toml` to prevent silent
breakage when a new toolchain ships between CI runs:

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

---

## Licence policy (`deny.toml`)

Runbound is AGPL-3.0-or-later (with a commercial licence option).
The `deny.toml` licence policy allows:

**Permitted:** MIT · Apache-2.0 · Apache-2.0 WITH LLVM-exception · BSD-2-Clause ·
BSD-3-Clause · ISC · Zlib · Unicode-3.0 · CDLA-Permissive-2.0

**Blocked by omission (not listed = denied):**
GPL-2.0, LGPL-2.x/3.x without a linking exception — incompatible with static linking
and with the commercial dual-licence model.

Any dependency introducing an unlisted licence causes `cargo deny check` to fail,
blocking the merge.

---

## Critical third-party dependencies (manual review on every update)

These crates sit on the security-critical path. Every version bump requires a manual
check of the RUSTSEC advisory database and the upstream changelog before merging.

| Crate | File(s) | Risk surface |
|---|---|---|
| `rustls` / `rustls-webpki` | `src/main.rs`, `src/sync.rs` | TLS stack — CVE here breaks DoT/DoH/DoQ security |
| `tokio` | everywhere | Async runtime — attack surface for all network I/O |
| in-house wire codec (`src/dns/wire/`) | `src/dns/server.rs` → `serve_wire`, `src/dns/forward.rs` | DNS parsing — the default network-facing path processes untrusted input here (the wire-native handler is the default request path) |
| `hickory-proto` | tests only | `[dev-dependencies]` only, used solely by the differential oracle tests — the default runtime build serves DNS on the in-house wire codec |
| in-house recursor + DNSSEC (`src/dns/recursor_wire.rs`, `src/dns/dnssec_*.rs`) | `src/dns/` | Sovereign full-recursion resolver and DNSSEC validation, entirely in-house and always compiled in (no Cargo feature gates them) — but **off by runtime default**: `resolution: forward` and `dnssec-validation: no` are the defaults (`UnboundConfig::defaults()`); full-recursion and DNSSEC validation are opt-in via config (`resolution: full-recursion`, `dnssec-validation: yes`), not a build flag |
| `axum` / `hyper` | `src/api/mod.rs` | HTTP server — injection, path traversal, request smuggling |
| `serde_json` | `src/store.rs`, `src/api/mod.rs` | JSON deserialisation — parses external (API) input |
| `ring` | transitive via `rustls` | Cryptographic backend — AEAD, HMAC, ECDSA |
| `rcgen` / `instant-acme` | `src/tls.rs` | Certificate management — ACME key handling |
| `cryptoki` | `src/hsm.rs` | PKCS#11 FFI — HSM key extraction, unsafe at the boundary |

---

## Release procedure

Run the following manually before tagging a release:

```bash
# 1. Zero known CVEs or unsound/unmaintained advisories
make audit        # cargo audit --deny warnings

# 2. Zero licence or dependency ban violations
make deny         # cargo deny check

# 3. Generate and attach SBOM
make sbom         # → sbom.cdx.json
# Upload sbom.cdx.json as a GitHub release asset.

# 4. Tag with GPG signature
git tag -s "$VERSION" -m "release $VERSION"
git push origin "$VERSION"
```

Steps 1 and 2 are **not currently enforced by CI** — `.github/workflows/release.yml` only
builds the release binaries and generates the SBOM (`cargo cyclonedx`); neither it nor
`.github/workflows/ci.yml` runs `cargo audit` or `cargo deny`. `make audit`/`make deny` are
local, manual checks the releaser is expected to run themselves; a failure does not
currently block `git push --tags` or the release workflow. Wiring them into CI as a
blocking gate is a TODO, not a shipped control.
Step 3 (SBOM) is mandatory for enterprise and government customers, and is the one part
of this list CI actually performs (`release.yml` runs `cargo cyclonedx` on every tag).
Step 4 ensures every release can be traced to a verified committer identity.

---

## SBOM (Software Bill of Materials)

The file `sbom.cdx.json` (CycloneDX 1.4 format) lists every transitive dependency
with its version, source hash, and SPDX licence identifier. It is generated by
`cargo cyclonedx` and attached to every GitHub release.

**Use cases:**

| Audience | How they use the SBOM |
|---|---|
| Enterprise customers | Verify full dependency tree matches their approved software inventory |
| Government / ANSSI | Required artefact for CSPN qualification and supply-chain risk assessment |
| Security auditors (CC EAL) | Cross-reference component versions against national CVE databases |
| Incident response | Immediately determine whether a newly published advisory affects a running deployment |

**Download:** [github.com/redlemonbe/Runbound/releases/latest](https://github.com/redlemonbe/Runbound/releases/latest) → `sbom.cdx.json`

---

## Manual source audit — priority areas

For formal security evaluations (CSPN, Common Criteria EAL, enterprise red team,
government qualification), the following source areas have the largest attack surface
and should be reviewed first.

| Area | Location | What to verify |
|---|---|---|
| **Constant-time auth** | `src/api/mod.rs` → `constant_time_eq`, `security_middleware` | Timing side-channels in Bearer token comparison; brute-force brake placement (must be pre-comparison) |
| **SSRF prevention** | `src/feeds/mod.rs` → `SsrfSafeDnsResolver`, `ssrf_safe_client` | Private IP and RFC-1918 range filtering at DNS-resolution time, not just URL parse time |
| **HSM key management** | `src/hsm.rs` → `load_and_store`, `extract_key` | Key extraction path, `Zeroizing<T>` usage, session close after extraction, fatal-on-failure guarantee |
| **Store integrity** | `src/store.rs`, `src/integrity.rs` | HMAC-SHA256 verification before deserialisation; timing-safe MAC comparison |
| **DNS name parsing** | `src/api/mod.rs` → `validate_dns_name` | RFC 1035 §2.3.4 boundaries (253-char total, 63-char label, ASCII only); applies to `name` field AND CNAME/MX/NS/PTR/SRV targets |
| **DNS query handler (wire-native)** | `src/dns/server.rs` → `serve_wire` | Default serving path on the in-house wire codec (no hickory handler): ACL bypass vectors, ANY/AXFR blocking, CHAOS-class identity probe suppression |
| **Real client IP / PROXY v2** | `src/dns/server.rs` → `read_proxy_v2`, `proxy_v2_header`, loopback relay | Real client IP carried over the loopback relay (PROXY v2, read before the TLS handshake for DoT/DoH); `axfr-allow`, split-horizon and ACL must evaluate the true source, not `127.0.0.1` |
| **TSIG** | `src/dns/tsig.rs` | Constant-time key-name lookup (`subtle::ConstantTimeEq`), `ring::hmac::verify` MAC check, trailing-dot key-name normalisation |
| **Forward path** | `src/dns/forward.rs` → `response_matches` | Upstream response transaction-ID + question (name/type/class) validation before acceptance (cache-poisoning defence) |
| **HA sync** | `src/sync.rs` | mTLS TOFU cert pinning, constant-time sync-token comparison, write-block on slave |
| **Rate limiting** | `src/api/mod.rs` → `ApiRateLimiter`, `src/dns/ratelimit.rs` | Token-bucket correctness, IPv4-mapped IPv6 normalisation, XFF rejection |

### HSM threat model note

When HSM is enabled, keys are **extracted** from the device at startup into
`Zeroizing<Vec<u8>>` buffers and the PKCS#11 session is closed immediately.
The HSM is therefore not required during normal operation, but the key material
exists in process memory until shutdown (where `Zeroizing` scrubs it on drop).

For deployments requiring keys to **never leave the HSM** (banking, government FIPS 140-3 L3),
a custom integration that performs all HMAC/signing operations inside the device is needed —
this is beyond the current `src/hsm.rs` scope. See [`docs/hsm.md`](hsm.md) for details.

---

## Acknowledged advisories

| Advisory | Crate | Reason ignored |
|---|---|---|
| RUSTSEC-2025-0134 | `rustls-pemfile` | Maintenance notice only, no CVE. `rustls-pemfile 2.x` is a thin wrapper around `rustls-pki-types`. Migration planned at next rustls update cycle. |
| RUSTSEC-2024-0436 | `paste` | Compile-time proc-macro crate (identifier concatenation) with no runtime code and no security impact. Transitive via `cryptoki 0.6`, no upstream fix available yet. |

New advisories that cannot be ignored must block the release until the affected crate
is updated or the advisory is explicitly acknowledged in `deny.toml` with a dated justification.

---

## Cargo deny configuration

The full policy is in [`deny.toml`](../deny.toml) at the repository root:

- **`[advisories]`** — blocks CVEs, unsound crates, yanked versions; acknowledges RUSTSEC-2025-0134
- **`[licenses]`** — enforces the permit list above; exempts `runbound` itself (AGPL-3.0-or-later)
- **`[bans]`** — warns on multiple major versions of the same crate; bans wildcard version specs; skip-list for known transitive duplicates (rand/getrandom ecosystem, windows-sys, rcgen)
- **`[sources]`** — restricts to crates.io only; blocks unknown registries and git sources

## SBOM

A **CycloneDX SBOM** (`sbom.cdx.json`, all crates + versions) is generated in CI by
`cargo-cyclonedx` and attached to every GitHub release alongside the binaries and
`SHA256SUMS`. It is not committed to the repository (it would go stale); fetch it
from the release matching your binary.
