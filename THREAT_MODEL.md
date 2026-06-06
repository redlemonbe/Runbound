# Runbound — Threat Model

> Status: **experimental**, AI-first development, no external human audit yet.
> This document states what Runbound does and does not defend against **today**.
> See [SECURITY.md](SECURITY.md) for crypto and reporting.

## Assets

- Integrity and availability of DNS resolution for clients.
- The block/allow policy (blacklist, feeds, local zones, split-horizon).
- Administrative control (REST API, WebUI, master→slave sync).
- Operator secrets (API keys, WebUI password, sync key).

## Trust boundaries

1. **Untrusted DNS clients** → UDP/TCP `:53` and DoT / DoH / DoQ.
2. **Untrusted network** → master↔slave sync relay (HMAC + TLS).
3. **Local host** → REST API (localhost-only) + WebUI (TLS).
4. **Kernel** → the eBPF/XDP program, loaded by the non-root service with scoped `CAP_BPF`.

## Attackers modeled

| Attacker | In scope | Mitigations today |
|---|:---:|---|
| Remote client flood / DNS amplification | ✅ | XDP fast path absorbs load; `ANY` refused (RFC 8482); per-IP query rate limit; XDP ICMP rate limiter |
| Remote answer poisoning / DNS rebinding | ✅ | `private-address` stripping; optional DNSSEC validation |
| Remote attacker on the sync channel | ✅ | HMAC-SHA256 + anti-replay + TLS (TOFU pinning) |
| Unauthorized administrative access | ✅ | API bearer auth + RBAC roles; WebUI argon2id + sessions/CSRF; API localhost-only |
| Malicious co-located local process | ⚠️ partial | API is localhost-only, but the bearer token is readable by a same-uid process — Unix-socket/mTLS is on the roadmap |
| Local **root** attacker | ❌ out of scope | A root attacker owns the host (standard assumption) |
| Volumetric DDoS **upstream of the NIC** | ❌ out of scope | Needs network/ISP-level mitigation; Runbound protects from the NIC inward |
| Supply-chain (crate compromise) | ⚠️ partial | `cargo-deny`/`cargo-audit` in CI; CycloneDX SBOM, reproducible-build doc and minisign-signed releases shipped (v0.15.0) |

## Out of scope (today)

- A local root attacker or a compromised kernel.
- Pre-NIC volumetric DDoS mitigation.
- Hardware side-channels.
- Formal certification (CC / ANSSI) — see roadmap.

## Notable design points

- The XDP fast path answers only **cache hits and local-zone data** in userspace;
  every other query falls through (`XDP_PASS`) to the hickory slow path, which
  applies the **same** blacklist/policy. TCP queries and kernel-reassembled
  fragments are therefore filtered on the slow path — **not** bypassed.
- The REST API never leaves localhost; the WebUI server proxies `/api/*` internally.
- eBPF runs in a non-root service with a scoped capability set and `NoNewPrivileges`
  (explicit loader/worker privilege separation is a roadmap item, not a current gap).
