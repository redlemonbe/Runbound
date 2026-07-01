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
4. **Kernel** → the eBPF/XDP program, loaded by the non-root service. The XDP fast path is an
   opt-in: only when `xdp: yes` is enabled does the service hold `CAP_NET_RAW`/`CAP_NET_ADMIN`/
   `CAP_BPF`/`CAP_PERFMON`. The default (`xdp: no`) service holds only `CAP_NET_BIND_SERVICE`.

## Attackers modeled

| Attacker | In scope | Mitigations today |
|---|:---:|---|
| Remote client flood / DNS amplification | ✅ | XDP fast path absorbs load; `ANY` refused (RFC 8482); per-IP query rate limit; XDP ICMP rate limiter |
| Remote answer poisoning / DNS rebinding | ✅ | Forward path validates the upstream response transaction-ID + question before accepting it (`src/dns/forward.rs`); `private-address` stripping; optional DNSSEC validation |
| Remote attacker on the sync channel | ✅ | HMAC-SHA256 + anti-replay + TLS (TOFU pinning) |
| Unauthorized administrative access | ✅ | API bearer auth + RBAC roles; WebUI argon2id + sessions/CSRF; API localhost-only; WebUI binds `127.0.0.1` by default (`ui-bind`) — network exposure requires explicit `ui-bind: 0.0.0.0` |
| Malicious co-located local process | ⚠️ partial | API is localhost-only; the bearer token is readable by a same-uid process, but an owner-only Unix-domain socket (mode 0600, `api-socket`) is available as a hardened alternative — localhost mTLS is on the roadmap |
| Local **root** attacker | ❌ out of scope | A root attacker owns the host (standard assumption) |
| Volumetric DDoS **upstream of the NIC** | ❌ out of scope | Needs network/ISP-level mitigation; Runbound protects from the NIC inward |
| Supply-chain (crate compromise) | ⚠️ partial | `cargo-deny`/`cargo-audit` configured (`deny.toml`/`audit.toml`, `make deny`/`make audit`) but not yet wired into the GitHub Actions CI workflow; CycloneDX SBOM, reproducible-build doc and minisign-signed releases shipped (v0.15.0) |

## Out of scope (today)

- A local root attacker or a compromised kernel.
- Pre-NIC volumetric DDoS mitigation.
- Hardware side-channels.
- Formal certification (CC / ANSSI) — see roadmap.

## Notable design points

- The XDP fast path answers only **cache hits and local-zone data** in userspace;
  every other query falls through (`XDP_PASS`) to the wire-native `serve_wire` slow
  path, which applies the **same** blacklist/policy. TCP queries and kernel-reassembled
  fragments are therefore filtered on the slow path — **not** bypassed. The serving path
  is entirely hickory-free: there is no hickory-dns request handler anywhere, and the
  slow path is the in-house wire codec (`serve_wire`) on every path (forward,
  full-recursion, local, AXFR, DDNS, TSIG). Full-recursion (`src/dns/recursor_wire.rs`)
  and DNSSEC validation (`src/dns/dnssec_*.rs`) are in-house too, always on by default —
  there is no `recursor` Cargo feature anymore, and no hickory dependency of any kind in
  the default runtime build. `hickory-proto` remains only as a `[dev-dependencies]` entry
  for the differential oracle tests.
- TCP/DoT/DoH are proxied through an internal loopback relay. v0.22 carries the **real
  client IP** to the handler via a PROXY v2 header (read before the TLS handshake for
  DoT/DoH), so `axfr-allow` and split-horizon (#10) evaluate the true source rather than
  `127.0.0.1` (this was a real bypass, now fixed).
- The REST API never leaves localhost; the WebUI server proxies `/api/*` internally.
- eBPF runs in a non-root service with a scoped capability set and `NoNewPrivileges`
  (explicit loader/worker privilege separation is a roadmap item, not a current gap).
