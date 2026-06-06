# Runbound — Sovereignty / Defense Remediation Roadmap

Tracking of the **valid** items from the 2026-06-06 sovereignty audit
([AUDIT-SOUVERAINETE-2026-06-06.md](AUDIT-SOUVERAINETE-2026-06-06.md)),
after maintainer review. False/overstated code findings are disputed in that
document and are **not** listed here.

## Done
- [x] Remove the unverifiable "World's First ASM-Accelerated DNS Server" claim from the README.
- [x] Maintainer review appended to the raw AI audit, disputing the false code findings.

## Documentation (no code change)
- [ ] **SECURITY.md** — supported versions, crypto (rustls, TLS 1.2/1.3), HMAC audit log, CVE contact + disclosure SLA.
- [ ] **THREAT_MODEL.md** — assets, trust boundaries, modeled attackers, in-scope / out-of-scope, current mitigations (ANY-block RFC 8482, per-IP rate limit, ACL, DNS-rebinding guard, systemd hardening) and known limits.
- [ ] Clarify the 128k (3-server comparative ceiling) vs 195k (Runbound cache-warm) figures so they are not read as contradictory.
- [ ] Document the AGPL §13 vs commercial-license boundary for integrators.
- [ ] Document an offline/air-gap mode (internal PKI instead of ACME, offline blocklist updates).

## Engineering (real enhancements, not bug fixes)
- [ ] **Reproducible build** + published `sha256` and **GPG/minisign signatures** for release binaries.
- [ ] **Strict RRL** (RFC 5358 Response Rate Limiting) on top of the existing per-IP query limit + ANY-block.
- [ ] **SIEM-ready structured logs** (JSON/CEF): per-query, per-API-action (who/what/when/from), security events.
- [ ] **API over a Unix socket** (or localhost mTLS) instead of a localhost bearer token in cleartext HTTP.
- [ ] **Formal SBOM** (CycloneDX) of all crates + versions + CVE status (cargo-deny/audit already in CI — formalize the artifact).
- [ ] Optional: explicit eBPF loader/worker privilege separation (current model = non-root worker with scoped CAP_BPF + NoNewPrivileges).

## External / long lead
- [ ] **Third-party human security audit** (e.g. Trail of Bits / NCC Group / CESTI ANSSI). The AI pentester does not replace it.
- [ ] CC EAL2 or ANSSI qualification (12–24 months, only after the above).

_Maturity: TRL 4–5 today; state usage targets TRL 7–8. The gap is trust paperwork, not code._
