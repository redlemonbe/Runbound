# Runbound — Security Audit (0.9)

**Maintained by:** RedLemonBe — https://github.com/redlemonbe/Runbound

> **Status caveat.** Runbound has **not** undergone an external human security audit
> (see #170). The findings below come from AI-internal, AI-adversarial and automated
> cycles only — read them as such.

This document is the single authoritative security-audit reference for Runbound 0.9.
It consolidates every audit cycle run to date — the baseline whole-program audit plus
the double-pass (J..N), round-2 (O..Q), the 2026-07-06 offensive pentest, and the
QNAME-minimisation (#231) review — into one body of findings, organised by severity
and domain rather than by release. Status values are **mixed by design** — the audit is
never reported as "100% Fixed": individual findings are Fixed, Accepted, Open, or
Disputed depending on the evidence and the maintainer's remediation decision.

---

## Overview

Runbound 0.9 is an authoritative + forwarding/recursing DNS server written
in Rust. It combines an eBPF/XDP + AF_XDP fast path (zero-syscall packet handling), a
kernel-UDP slow path, and an in-house wire-native serving layer. The audited surface
includes:

- **Data path:** the eBPF/XDP program (`ebpf/dns_xdp.c`), AF_XDP UMEM/ring handling
  (`src/dns/xdp/`), the kernel-UDP slow path (`src/dns/kernel_loop.rs`), the SIMD/CRC32c
  kernels (`src/dns/simd.rs`, `src/dns/hasher.rs`), and the wire parsers/serialisers
  (`src/dns/wire/`, `src/dns/xdp/wire_builder.rs`).
- **DNS serving:** local zones, split-horizon, forwarding/racing, the sovereign recursor
  (config-gated via `resolution: full-recursion` — no Cargo feature) including QNAME
  minimisation (RFC 9156, #231) and RFC 2308 negative caching, AXFR/IXFR, DNS UPDATE
  (DDNS/TSIG, RFC 2136/8945), and the in-house DNSSEC signer (`src/dns/zone_signer.rs`,
  `dnssec_sign.rs`).
- **Transports:** UDP/TCP plus DoT/DoH/DoQ, with a public→loopback relay (PROXY v2) in
  front of the wire listeners.
- **Control plane:** the REST API + RBAC (`src/api/`), the HMAC-SHA256 relay/sync trust
  model (`src/sync.rs`, `src/api/relay.rs`), the WebUI (`src/webui/`), the config
  parser/writer (`src/config/`), the abuse/ban/alert engine (`src/alerts.rs`, `src/icmp.rs`),
  webhooks (`src/webhooks.rs`), and the anycast/exabgp integration (`src/anycast.rs`).

### Severity scale

- **CRITICAL** — exploitable without authentication, or bypass of a documented guarantee.
- **HIGH** — exploitable with authentication, silent data corruption, or a practical
  single-source DoS.
- **MEDIUM** — reduces defence-in-depth; preconditions required.
- **LOW** — best-practice deviation; no direct exploit path.
- **INFO** — architectural observation.

Code quality and documentation are **out of audit scope** and are not scored as findings.

### On mixed status

The audit deliberately carries all four status classes:

- **Fixed** — remediated in the code and (where noted) verified live.
- **Accepted** — understood residual risk kept as a deliberate trade-off.
- **Open** — a real gap or enhancement not yet remediated (some pending maintainer
  approval of the remediation plan).
- **Disputed** — a candidate finding (often from an adversarial model pass) refuted at
  the source, recorded with the refuting evidence rather than silently dropped.

No dependency versions in this document are Runbound versions — `quinn-proto 0.11.14` /
`0.11.15`, `rustls 0.23`, `cargo-audit`, etc. are third-party crate/tool versions.

---

## Audit cycles conducted

Findings in this document come from several distinct cycles. Each is labelled by source
per the audit conventions; the folded-in cycles kept their own severity scale and
mixed-status discipline, which this consolidation preserves.

| Cycle | Date | Label | Target / scope | Result summary |
|-------|------|-------|----------------|----------------|
| Baseline whole-program audit | 0.9 (through 2026-07-06) | `[AI-INTERNAL]` + `[AI-ADVERSARIAL]` + `[AUTOMATED-TOOL]` | Full tree: data path, DNS serving, transports, control plane | The bulk of the SEC-* / PENT-1..5 / VAL / PAR series below. No CRITICAL; no unauthenticated remote HIGH after SEC-2026-07-A. |
| Double-pass | 2026-07-07 | `[AI-ADVERSARIAL]` | `v0.9.2` HEAD `803634c`; surfaces landed after the baseline (RFC 2308 neg cache, compact-denial→NXDOMAIN, IPv6 slow path, prefetch scan, do-udp/do-tcp + axfr-enable gates) | 4 independent auditors on disjoint surfaces. No CRITICAL/HIGH. 1 MEDIUM authz gap + hardening. Findings SEC-2026-07-J..N. `Message::parse` fuzzed 1.7 M exec / 0 crash. |
| Double-pass round 2 | 2026-07-07 | `[AI-ADVERSARIAL]` | `v0.9.2` HEAD `2fc1bd2`; auto-ban hardening, live rate limiter (AtomicU64), alert per-rule refactor, serve-stale eviction | 4 independent auditors on disjoint surfaces. No CRITICAL/HIGH. 1 MEDIUM ban-enforcement gap + 2 hardening. Findings SEC-2026-07-O..Q. `Message::parse` fuzzed 4.75 M exec / 0 crash. |
| Offensive pentest | 2026-07-06 | `[AI-ADVERSARIAL]` | `feat/231-qname-minimisation`, whole-program surface; crash / exfil / write / RCE | 2 disjoint offensive passes + 4 cargo-fuzz campaigns (16.4 M total exec / 0 crash). No CRITICAL/HIGH/MEDIUM primitive. 1 LOW robustness defect (PENT-06-1) + 1 INFO (PENT-06-2). |
| QNAME minimisation (#231) | 2026-07-06 | `[AI-ADVERSARIAL]` | `feat/231-qname-minimisation`: `descend()` engine + QMIN (RFC 9156) + config wiring | 2 disjoint lanes + maintainer reproduction. No CRITICAL/HIGH/MEDIUM. Findings QMIN-1..5. DNSSEC fail-closed + off-path spoofing resistance preserved. |

`[HUMAN-EXTERNAL]` — no third-party human security review has been performed on any cycle
(tracked as OPEN-F1 / #170); the AI passes do not substitute for it.

---

## Methodology

Findings were produced by several complementary methods, labelled by source per the audit
conventions:

- `[AI-INTERNAL]` — a model reviewing the code with limited adversarial independence
  (fresh-context read-only passes, per-domain manual review, arbitration of candidate
  findings against the source).
- `[AI-ADVERSARIAL]` — an independent session or a different model family (Claude Opus 4.8
  red/blue exchanges; Gemini 2.5 Pro / 3.1 Pro cross-model passes; a local Qwen3-Coder-30B
  pass run entirely on-LAN so the private repo never left the network). The double-pass and
  round-2 cycles each ran **four** independent adversarial auditors on disjoint attack
  surfaces (memory-safety/crash/DoS, DNSSEC integrity/poisoning, injection/RCE/SSRF,
  auth/authz/relay), each required to produce a concrete reproducible trigger. Adversarial
  passes are high-recall / low-precision; every candidate was re-verified against the source,
  and over-rated or hallucinated items are recorded as **Disputed** with the refutation
  rather than dropped.
- `[HUMAN-EXTERNAL]` — third-party human security review. **None has been performed yet**
  (tracked as OPEN-F1 / #170); the AI passes do not substitute for it.
- `[AUTOMATED-TOOL]` — `cargo audit` + `cargo deny` for the supply chain; the wire/config/
  name/API parsers were fuzzed under AddressSanitizer. Across cycles: the baseline fuzzing
  (~23.4 M executions), the 2026-07-06 pentest's four cargo-fuzz campaigns
  (`fuzz_dns_query` 8.01 M, `fuzz_dns_name` 2.31 M, `fuzz_config` 3.03 M, `fuzz_api_json`
  3.03 M — 0 crashes), and the double-pass / round-2 re-fuzzing of `Message::parse`
  (1.75 M then 4.75 M exec) and name decompression (520 k exec) — **0 crash** throughout.

**Reproduction at the source.** Adversarial candidates were arbitrated line-by-line
against the current code and the eBPF-verifier guarantees before classification; an
unreproduced candidate is discarded, not recorded as a finding.
**Live pentests.** Several passes were validated by real request/flood batteries against
throwaway hardened instances (isolated config/data dirs and ports on a build host, or an
isolated netns / test VM) — never against production — and torn down afterwards.
**Re-audit independence.** Per convention, any applied fix must be re-reviewed in a
different session or model before a release tag; a two-model remediation re-audit was
performed on the SSRF/integrity/TSIG/relay fixes, and each later cycle read the prior
cycles first and excluded their Fixed/Accepted/Disputed items.

---

## Findings by severity

Each finding retains its original ID, severity, status, location, and technical
description. Statuses are mixed by design (see above). Findings whose ID begins with
`SEC-2026-07-J..N` are from the double-pass cycle, `SEC-2026-07-O..Q` from round 2,
`PENT-06-*` from the 2026-07-06 offensive pentest, and `QMIN-*` from the #231 review.

### HIGH

| ID | Status | Location | Summary |
|----|--------|----------|---------|
| SEC-2026-07-A | Fixed | `Cargo.lock` (quinn-proto) | RUSTSEC-2026-0185 (CVSS 7.5): remote memory-exhaustion in the QUIC stack (DoQ). quinn-proto bumped 0.11.14 → 0.11.15. |
| PENT-1 | Fixed | `src/dns/server.rs` (`serve_wire`) | AXFR allow-list bypass → unauthenticated full zone transfer (data extraction). Detail below. |
| SEC-O1 | Fixed | `src/dns/forward.rs` (`UdpUpstream::do_query`) | Forward cache-poisoning: missing transaction-ID and question validation on UDP upstream responses. Detail below. |
| SEC-J1 | Fixed | `src/api/mod.rs` (`add_split_horizon`), `src/config/writer.rs:276` | Config-directive injection via the split-horizon API — `name`/`subnet` written unescaped. Detail below. |
| SEC-M1 | Fixed | `src/config/writer.rs`, `PUT /api/alerts/rules` | Config-directive injection via the alert-rule writer — `notify-url` and other alert fields written unescaped. Detail below. |
| SEC-N1 | Fixed | `src/api/mod.rs` (`backup_export_handler`) | `GET /api/backup/export` had no admin gate — any authenticated key could exfiltrate the config plus secret state files. Detail below. |
| SEC-N2 | Fixed | `src/api/mod.rs` (`add_dns_handler`/`delete_dns_handler`) | DNS record handlers never enforced the per-user `zone_prefixes`, letting a non-admin write outside its zone. Detail below. |
| SEC-N10 | Fixed | `src/api/mod.rs:546` (`security_middleware`) | RBAC `may_write` keyed on the axum-stripped path → write-RBAC inert for `Dns`/`Operator`. Sec impact LOW (fail-closed), functional impact HIGH. Detail below. |
| SEC-L0 | Fixed | `src/dns/server.rs` (`TcpConnTracker::release`) | DashMap self-deadlock: one inbound TCP/DoT/DoH connection froze all subsequent TCP accepts — remote unauthenticated DoS. Detail below. |
| SEC-H7 | Fixed | `src/dns/kernel_loop.rs`, `src/dns/xdp/worker.rs`, `src/icmp.rs` | Rate-limit and bans not enforced on the kernel slow path (`xdp:no`) — cache hits served unthrottled, banned IPs kept being served. Detail below. |
| SEC-I23 | Fixed | `src/dns/server.rs` (`run_tcp_with_limit`) | Source-IP ACL not enforced on TCP/DoT/DoH — the loopback-relayed request was seen as `127.0.0.1`, bypassing the ACL. Detail below. |
| SEC-B1 | Fixed | `src/api/relay.rs` (`relay_tls_config`) | Relay TLS used `NoCertVerifier` despite an available TOFU pinning implementation. Detail below. |
| SEC-C1 | Fixed | `src/api/relay.rs:314` (`push_to_slaves`) | Cert pinning applied to `relay_forward_handler` but `push_to_slaves` still used `NoCertVerifier` unconditionally. Detail below. |
| PAR-1 | Fixed | `src/dns/server.rs` (`serve_wire`) | Query logging was dead in the default (non-recursor) build — `/api/logs` always empty in the shipped binary. Functional HIGH. Detail below. |
| SEC-B2 | Fixed | `src/sync.rs` | SSRF via private `relay_host` registration. |
| SEC-B3 | Fixed | `src/dns/server.rs` | Silent TSIG base64 drop (log level WARN→ERROR; drop surfaced). |
| SEC-B5 | Fixed | `src/webui/mod.rs` | WebUI login rate-limit concurrent bypass. |
| SEC-B6 | Accepted | `src/dns/axfr.rs` | No per-zone AXFR ACL (global allow-list only). Kept as a documented limitation. |

**SEC-2026-07-A — quinn-proto DoQ memory-exhaustion (RUSTSEC-2026-0185).**
`[AUTOMATED-TOOL]` `cargo audit` flagged RUSTSEC-2026-0185 (CVSS 7.5), a remote
memory-exhaustion in the QUIC stack used by DoQ. Fixed by bumping the dependency
`quinn-proto 0.11.14 → 0.11.15`. After this bump there is **no unauthenticated remote
HIGH** in the audited tree.

**PENT-1 — AXFR allow-list bypass → unauthenticated zone transfer (data extraction).**
`[AI-INTERNAL]` + `[AI-ADVERSARIAL]` (live). `axfr-allow` is meant to restrict zone
transfers to specific source IPs, stricter than the general ACL. The check lived in
`serve_wire` and used `peer.ip()` — but AXFR is TCP, and TCP/DoT/DoH connections are
proxied through an internal loopback relay before reaching the handler, so `peer.ip()`
is always `127.0.0.1`. Consequences proven live: with `axfr allow: 127.0.0.1` (the
natural local-test value) the handler compares `127.0.0.1 == 127.0.0.1`, so **every
ACL-reachable client can transfer the full zone** (the entire `corp.internal` zone —
SOA, NS, `secret-db` → 10.10.10.10, `vpn` → 10.10.10.20 — was dumped from an external
IP); with `axfr allow: 9.9.9.9` the transfer is REFUSED even from loopback (the handler
sees 127.0.0.1). The allow-list was therefore non-functional. **Impact:** full internal
DNS inventory disclosure to any network client. **Fixed:** the public relay prepends a
**PROXY v2 header** with the real client IP to the loopback connection, and every loopback
listener recovers it, so `serve_wire` sees the true source for the allow-list across plain
TCP, DoT and DoH (PROXY-before-TLS for the encrypted transports). Re-tested live: external
AXFR → REFUSED (0 records, real IP logged), loopback AXFR → served (6 records).

**SEC-O1 — forward cache-poisoning (missing txid/question validation).**
`[AI-INTERNAL]` + `[AI-ADVERSARIAL]` (independent convergence). `forward::UdpUpstream::do_query`
sent the query and accepted the first datagram `recv()` returned, parsing it as the answer
**without checking that the response transaction ID matched the query, nor that the response
question matched**. The socket is `connect()`ed to the upstream
(kernel source filter) and the source port is randomised, but an attacker able to spoof the
upstream's source IP:port (on-path, shared L2, a NATing/compromised upstream) could inject a
forged response taken verbatim → cache poisoning. The DoT path is unaffected (TLS
authenticates the upstream). **Fixed:** the query txid + question are captured before send;
on `recv` the response is rejected unless `id` and the first question (name case-insensitive
+ type + class) match, and the socket keeps reading until a matching response or the timeout,
so a single spoofed non-matching datagram no longer aborts resolution.

**SEC-J1 — config-directive injection via the split-horizon API.**
`[AI-ADVERSARIAL]` confirmed at code + live pentest. `add_split_horizon` accepted the
API-supplied `name`/`subnet`, validating only non-emptiness, then `render_config` wrote
them with `format!("    name: \"{}\"\n", se.name)` at `config/writer.rs:276-277`
**without `escape_str`** — unlike `local-zone` and forward-zone `name`, which escape. A
`name` containing a newline injected an arbitrary directive into the regenerated
`runbound.conf` — e.g. `ui-acme-hook: "/path"`, which `hook_run` (`acme.rs:415`,
`tokio::process::Command::new(script)`) later executes **as root** on the next ACME DNS-01
challenge. This crosses the API→OS trust boundary (an API key is not meant to grant
shell-root). Because the hook runs the binary directly (no shell), it is arbitrary-binary
execution, not shell-metacharacter injection. **Confirmed exploitable pre-fix:** a POST with
`name = "evilview\n    ui-acme-hook: \"/tmp/PWNED.sh\"\n#x"` was accepted (200) and produced
a standalone `ui-acme-hook` directive in the regenerated config. **Fixed:** the writer
escapes `name`/`subnet`/`local-data`, and `add_split_horizon` rejects control/newline input
at the API boundary (defence in depth).

**SEC-M1 — config-directive injection via the alert-rule writer.**
`[AI-INTERNAL]` + `[AI-ADVERSARIAL]`. The alert-rule writer emitted `name`/`metric`/`action`/
`notify-url` into `runbound.conf` with raw `format!` instead of `escape_str`, and
`PUT /api/alerts/rules` validated the rule *name* for control chars but **not** `notify-url`.
A malicious admin-token-reachable `notify-url` with an embedded newline could break out of
the quoted value and inject a separate directive on the next regeneration — the SEC-J1 class
(config-directive injection → command-running hook → RCE as the service user). **Fixed:**
`escape_str` on all four alert string fields in `config/writer.rs`, plus a control-char/
length (≤2048) check on `notify-url` in `put_alert_rules`. Verified live: a `notify-url`
with an embedded newline → `400 INVALID_NOTIFY_URL`; a rule name with a `"` → 200 but written
escaped, no injected directive, no file created.

**SEC-N1 — unauthenticated secret exfiltration via `/api/backup/export`.**
`[AI-INTERNAL]`, confirmed live. `backup_export_handler` had no admin gate — it base64-dumps
`runbound.conf` plus the secret state files (`api.key`, `sync-key.pem`, `webui-ca-key.pem`,
`webui-auth.conf`) to any authenticated key. In multi-user mode a non-admin (Read/Dns/Operator)
key could exfiltrate the master API key, the relay HMAC key and the WebUI CA private key —
full privilege escalation. (Single-user: no-op — the only key is admin.) **Fixed:** the admin
gate was added to the export, import, restore, create and delete backup handlers. Confirmed
under live attack: every backup endpoint returns 403 to the non-admin key with zero secret
leakage; admin export still returns a real backup.

**SEC-N2 — DNS zone-scope bypass.**
`[AI-ADVERSARIAL]` (surfaced by the cross-model pass, missed by the internal pass).
`add_dns_handler`/`delete_dns_handler` enforced only the path-level role, never the per-user
zone scope, so a non-admin `Dns`/`Operator` user could create or delete any record outside
its assigned `zone_prefixes`. **Fixed:** `caller.may_manage_name(name)` is checked on the
validated entry name (add) and on the loaded entry name before removal (delete); admin
bypasses. Confirmed live: 9/9 zone-escape variants → 403.

**SEC-N10 — RBAC keyed on the stripped path (write-RBAC inert).**
`[AI-INTERNAL]` (found by the live pentest, invisible to both static passes).
`security_middleware` called `may_write` with the axum-**stripped** path (`/dns`, not
`/api/dns`) — the auth layer sits on the inner router mounted via `nest("/api", ...)`, and
`nest` applies `StripPrefix`, while `may_write` keys on `/api/...` prefixes. It therefore
always returned false for a non-admin → every non-admin POST/DELETE fail-closed (403), so the
write-RBAC for `Dns`/`Operator` roles was inert and the SEC-N2 zone-scope check was dead code.
Security impact **LOW** (fail-closed, no escalation); functional impact **HIGH**. **Fixed:**
`may_write` now keys on the `OriginalUri` un-stripped path; an HTTP-level regression test
drives a non-admin role through the full nested router. SEC-N2 zone-scope is now reachable and
live.

**SEC-L0 — TcpConnTracker DashMap self-deadlock (DoS).**
`[AI-INTERNAL]`, found in functional testing. `TcpConnTracker::release` held a DashMap `get()`
shard read-guard across `remove_if` on the same shard, self-deadlocking. The first inbound
DNS-over-TCP / DoT / DoH connection from any tracked (non-loopback) client froze all subsequent
TCP/DoT/DoH accepts — a remote, unauthenticated DoS reachable with one connection (loopback
masked it, never inserted). **Fixed** by scoping the guard before `remove_if`; the audit
confirmed no double-decrement, no underflow, cap not bypassable. Verified live: 60 concurrent
DNS-over-TCP queries all answered, no freeze.

**SEC-H7 — rate-limit and bans not enforced on the kernel slow path (`xdp:no`).**
`[AI-ADVERSARIAL]` (red/blue). In `xdp: no` (the production mode) the kernel fast loop served
cache hits through the wire/cache responder without consulting the rate-limiter or the ban
set — a single source flooded cached answers unthrottled (1000 queries → 928 served at
`rate-limit:200`), and a banned IP kept being served (ban evasion / DoS). **Fixed:** a shared
`rl_should_drop` gate and `icmp_stats.is_banned()` are now called on both datapaths driven by
the same `RateLimiter`/ban set (one mechanism, two routes). Verified: 1000 → ~100–200 served;
banned source dropped; unban restored. Zero per-packet cost when disabled (atomic
short-circuit).

**SEC-I23 — source-IP ACL not enforced on TCP/DoT/DoH.**
`[AI-ADVERSARIAL]` + `[AI-INTERNAL]`. `run_tcp_with_limit` applied only the connection cap,
not `acl.check`: the per-IP-capped connection is relayed to the loopback listener, so
the request handler saw `127.0.0.1` — a client bypassed the ACL whenever loopback is allowed
(the common default). **Fixed:** `acl.check(src_ip)` is enforced on the real client before
relaying; Deny/Refuse drop the connection (loopback follows the same ACL as UDP).

**SEC-B1 / SEC-C1 — relay TLS used `NoCertVerifier`.**
`[AI-ADVERSARIAL]`. `relay_tls_config()` used `NoCertVerifier` despite a working TOFU
cert-pinning implementation (`PinnedCertVerifier`) already present. **SEC-B1 Fixed** for
`relay_forward_handler`. A residual regression (**SEC-C1**) left `push_to_slaves` (zone
replication, blacklist sync, feed pushes) on `NoCertVerifier` unconditionally; **Fixed** by
mirroring the pinning logic — `push_to_slaves` extracts `cert_fingerprint` from the registered
slave and uses `pinned_client_config(fp)` when available. **Residual:** nodes registered
without a stored fingerprint still use `NoCertVerifier` on relay connections until they
re-register (see Open items).

**PAR-1 — query logging dead in the default build (functional HIGH).**
`[AI-INTERNAL]`. `log_buffer.push_query` was called only by the (default-disabled) recursor
`record_query`; `serve_wire` emitted nothing, so the WebUI Logs panel / `GET /api/logs` were
always empty in the shipped binary (`default = ["xdp"]`, no `recursor`). **Fixed:** `serve_wire`
now logs every resolved query via a wire-native `log_query_wire` (sanitised name). ACL/RRL/
cookie refusals are intentionally not logged on the hot path (one alloc per spoofed packet
under flood). Live-proven: `dig` → `/api/logs` returns the queries.

---

### MEDIUM

| ID | Status | Location | Summary |
|----|--------|----------|---------|
| SEC-2026-07-B | Fixed | `webhooks.rs:300` (`is_safe_url`) | Webhook SSRF: no hostname resolution (DNS-rebinding), IPv6 ULA/link-local literals not blocked. Admin-configured URL. |
| SEC-2026-07-C | Fixed | `feeds/mod.rs:388` (`is_private_ip`) | Feed SSRF: `is_private_ip` omits CGNAT 100.64.0.0/10, inconsistent with the recursor filter. Feed-role gated. |
| SEC-2026-07-D | Fixed | `integrity.rs:89` (`verify_mac`) | Integrity store fails open when the key is set but the `.mac` sidecar is missing. Requires local FS write. |
| SEC-2026-07-J | Fixed | `src/api/mod.rs` (`audit_tail_handler`) | `GET /api/audit/tail` had no admin gate — any authenticated non-admin key could read the tamper-evident action log. Detail below. |
| SEC-2026-07-O | Fixed | `src/alerts.rs` (`AlertTracker::trigger` `block` arm) | Alert-rule `block` ban not mirrored into `icmp_stats` → bypassed on cache hits under `xdp: no`. Detail below. |
| SEC-N3 | Fixed (partial) | `src/icmp.rs`, ban engine | Kernel ban engine had no protected-IP allowlist — a verified high-QPS source behind CGNAT/corporate NAT could be banned, blackholing co-located users. Loopback/unspecified exemption added; upstream-resolver addrs not yet threaded (→ OPEN-N1). |
| PENT-2 | Fixed | `src/dns/server.rs` | Split-horizon bypassed for all TCP/DoT/DoH clients (same root cause as PENT-1). |
| PENT-3 | Fixed | `runbound.service`, `install.sh` | Over-privileged Linux capabilities granted unconditionally, incl. `xdp:no`. |
| SEC-L1 | Fixed | `src/dns/zone_signer.rs` | Asymmetric crypto DoS: DO=1 flood re-signed RRSIG/NSEC3 and rebuilt the ECDSA key per query. Fixed by building the per-zone signer once at load; per-answer cache → OPEN-L1. |
| SEC-L2 | Fixed | `src/dns/server.rs` | Silent downgrade: a signed zone fell through to an UNSIGNED NXDOMAIN/NODATA when the NSEC3/SOA proof could not be built. Now fails closed with SERVFAIL. |
| SEC-L3 | Fixed | `src/dns/server.rs` (TLS key write) | DoT/DoH private key written with umask (0644) then chmod 0600 — TOCTOU window; failed chmod swallowed. Now 0600 temp file + atomic rename. |
| SEC-L4 | Fixed | `src/dns/recursor.rs` | `PATCH /api/config {dnssec_validation}` did not rebuild the recursor → Bogus→SERVFAIL kept the stale policy. Now rebuilds on toggle. |
| SEC-I1 | Fixed | `src/webui/mod.rs` (`verify_csrf`) | CSRF token compared with `==` (timing oracle). Fixed: `subtle::ConstantTimeEq`. |
| SEC-I3 | Fixed | `src/webui/mod.rs` (`/api` proxy) | WebUI `/api` proxy forwarded the raw path; `reqwest` normalises `..`, escaping the `/api/` scope. Fixed: reject `..`. |
| SEC-I4 | Fixed | `src/config/writer.rs` (`render_config`) | Config-line injection at the serialization boundary (double-quoted values unescaped). Fixed: `escape_str` at the boundary. |
| SEC-I5 | Fixed | `src/api/relay.rs` (`relay_forward_handler`) | Relayed path built from a user segment without rejecting `..`; a slave could normalise it outside `/relay/`. Requires master-API auth. Fixed: reject `..`. |
| SEC-I7 | Fixed | `src/api/mod.rs` (`/api/clients/:ip`) | Unbounded per-IP domain map → memory exhaustion via random-subdomain flood + admin view. Fixed: cap at 50 000 domains/IP. |
| BUG-I10 | Fixed | firewall nftables backend | `"proto dport port"` passed as one `nft` arg → rule never installs → port stays closed (silent availability loss). Fixed: separate tokens. |
| SEC-H3 | Accepted | `src/api/relay.rs` (TOFU) | Relay TLS first-connection MITM (TOFU pin). Mitigated by HMAC; confidentiality-only residual. See Accepted section. |
| SEC-H6 | Fixed | `src/dns/server.rs` | DNSSEC AD flag never set — validated data indistinguishable from insecure (silent downgrade). Now sets `authentic_data` when validation is on and the answer is `Secure`. |
| SEC-J2 | Fixed | `src/webui/mod.rs` (`load_or_default_creds`) | WebUI fell back to default credentials `admin`/`admin` when the creds file was absent. Confirmed live pre-fix. Fixed: random one-time password logged once. |
| SEC-J3 | Fixed | `src/upstreams.rs:41` (`DNS_PROBE_PACKET`) | Upstream health-probe used a static DNS transaction ID → off-path spoofable "healthy" reply masking a dead upstream. Fixed: random ID per send, verified in reply. |
| SEC-J4 | Fixed / downgraded | `ebpf/dns_xdp.c` | Blacklist XDP fast-path match avoidable (case / VLAN / compression). Downgraded MEDIUM→LOW at pentest: the slow path enforces the blacklist case-insensitively, so these are fast-path defence-in-depth/perf losses, not blocking bypasses. |
| SEC-J9 | Fixed | `src/feeds/mod.rs` (`update_feed`) | Feed download fully buffered before parsing → memory exhaustion. Fixed: streaming read + 100 MiB cap. |
| SEC-C2 | Fixed | `src/sync.rs:1854` | Relay-propagated ICMP bans / DashMap consistency (ban applied to both DashMap and XDP fast path). |
| SEC-C3 | Fixed | `src/icmp.rs:66` | ICMP ban DashMap grew without bound under spoofed-IP flood. Fixed: hourly eviction, 24 h TTL, removes from DashMap + XDP. |
| SEC-C4 | Fixed | `ebpf/dns_xdp.c:110` | BPF `icmp_rl_counts` (8192 entries) exhaustible via IP spoofing, hiding attack IPs. Fixed: `max_entries` 8192 → 65536. |
| SEC-E1 | Fixed | `src/alerts.rs` (`webhook_sender`) | SSRF via alert webhook URL (metadata/internal targets). Fixed: `is_safe_webhook_url()` scheme/loopback/RFC-1918/link-local/metadata reject. |
| SEC-F1 | Fixed | `src/alerts.rs` | `blocked` DashMap unbounded growth under IP-rotation flood (24 h ban duration amplified it). Fixed: `MAX_BLOCKED_ENTRIES = 50_000` cap on all three insertion paths. |
| SEC-B7 | Fixed | `src/alerts.rs` | Alert-triggered blocks stored only in memory, cleared on restart. Fixed: persisted to `alert-blocks.json`. |
| SEC-B9 | Fixed | `src/dns/server.rs` | TSIG algorithm-mismatch log level too quiet. |
| SEC-B10 | Fixed | `src/webui/mod.rs` | Session DashMap unbounded growth. |
| SEC-B13 | Fixed | `src/api/relay.rs`, `src/sync.rs`, config | Hardcoded SNI values → dynamic derivation from peer address; new `forward-tls-hostname` directive. |
| SEC-B14 | Fixed | `src/webui/mod.rs` | CSRF bypass on proxied API endpoints. |
| VAL-1 | Fixed | `src/dns/server.rs`, `src/dns/tsig.rs` | TSIG key-name trailing-dot mismatch → a `tsig-key: "name."` config failed every signed UPDATE (silent DDNS breakage). Fixed: normalise stored key name. |
| SEC-B4 | Disputed | `src/api/mod.rs` | "Cache flush race" — a Mutex, not an atomic; not a vuln. |
| SEC-B12 | Disputed | `src/sync.rs` | "HMAC ±30 s replay window" — see Accepted (SEC-J6/N5); not a vuln in isolation. |
| SEC-B8, SEC-B11 | Accepted | `src/sync.rs`, `src/config/parser.rs` | `relay_host` parsing edge cases (quality); zone limit per-reload (root required to modify config). |
| SEC-M3 | Disputed | `POST /api/tls/self-signed` | Gemini: "removed hostname validation → DoS." Refuted: the 1..253-char/no-control validation is present and was never removed; only the signing path changed. |
| OPEN-I17 | Fixed | `src/api/mod.rs` (`/api/clients`) | Per-request whole-log scan (CPU; localhost+auth only). Fixed: 2 s memoized aggregation. |

**SEC-2026-07-B/C/D — SSRF and integrity gaps.** `[AI-ADVERSARIAL]` + `[AUTOMATED-TOOL]`.
Three admin/role-gated gaps in the outbound-request and integrity paths: the webhook
`is_safe_url` did not resolve the hostname (DNS-rebinding) and missed IPv6 ULA/link-local
literals (**B**); the feed `is_private_ip` omitted CGNAT 100.64.0.0/10, inconsistent with the
recursor's `is_public_ip` (**C**); `integrity.rs verify_mac` failed open when the store key was
set but the `.mac` sidecar was missing (**D**, requires local FS write). All **Fixed** (see the
Open items / remediation section for the follow-up that unified the three SSRF filters and made
the integrity path genuinely one-shot-migration rather than permanently fail-open).

**SEC-2026-07-J — audit log readable by any authenticated non-admin key.**
`[AI-ADVERSARIAL]` (double-pass). `GET /api/audit/tail` (`audit_tail_handler`) took
`(State, Query)` only and did no `caller.admin` check. The auth middleware enforces RBAC on
**writes** (`may_write`); every GET is reachable by any valid key, so in multi-user mode a
scoped `Read`/`Dns`/`Operator` key could `GET /api/audit/tail?n=1000` and read the
tamper-evident action log — per-actor usernames of every other user/admin, auth-failure
paths, config reloads, key rotations. The maintainer already gates the sibling disclosure
`/api/backup/export` to admins (SEC-N1); the audit trail is a security control, not
operational telemetry, and belongs behind the same gate. **Repro:** a non-admin key →
`curl -H "Authorization: Bearer <read-key>" .../api/audit/tail` returned the full tail (200).
**Fixed:** added the `caller_ext` extractor + `if !caller.admin { 403 }` gate. No-op in
single-user mode.

**SEC-2026-07-O — alert-rule `block` ban not mirrored into `icmp_stats` (bypassed on cache hits under `xdp: no`).**
`[AI-ADVERSARIAL]` (round 2). `AlertTracker::trigger()`'s `"block"` arm (`src/alerts.rs`)
inserted into `alert_tracker.blocked` and called `xdp_push()` (a no-op when `xdp: no`) but did
**not** add the IP to `icmp_stats.banned`. The kernel-UDP fast path (`kernel_loop.rs:358`) and
the XDP cache-hit path only consult `icmp_stats.is_banned()`, not `alert_tracker`. So on an
`xdp: no` node (the production master), an IP banned by an operator's `action: block` alert
rule was still served for any cached name (the bulk of a resolver's UDP traffic); the ban only
bit on cache-miss (slow-path fallback) and on DoT/DoH/DoQ. **Why MEDIUM:** partial bypass of an
explicitly-configured abuse mitigation; no DNSSEC-integrity impact; gated on the operator having
a `block` rule. The manual / bot / relay ban paths already double-write both systems (SEC-H7
lineage); this one automatic path was missed. **Fixed:** wire `icmp_stats` into `AlertTracker`
(`set_icmp_stats`, OnceLock) and, in the `block` arm, `icmp_stats.ban(ip, BanSource::Bot)` after
the `blocked.insert` — same as the bot path. Idempotent; no-op when no rule fires.

**SEC-L1/L2/L3/L4 — DNSSEC signing & recursor toggle.** `[AI-INTERNAL]` + `[AI-ADVERSARIAL]`.
Four MEDIUMs on the #201 signing / #202 recursion surface, all **Fixed**: asymmetric crypto DoS
(**L1**, per-zone signer built once at load), silent downgrade of authenticated denial to an
unsigned answer (**L2**, now fails closed with SERVFAIL), a TOCTOU/umask window on the DoT/DoH
private key (**L3**, atomic 0600 write), and the DNSSEC-validation toggle not rebuilding the
recursor so Bogus→SERVFAIL used a stale policy (**L4**, rebuild on toggle).

---

### LOW

| ID | Status | Location | Summary |
|----|--------|----------|---------|
| SEC-2026-07-E | Fixed | `multiuser/mod.rs:155` (`by_api_key`) | Non-constant-time HashMap lookup for the per-user API key. Mitigated by 256-bit keys + anti-bruteforce brake. |
| SEC-2026-07-F | Fixed | `dns/tsig.rs:37` | TSIG accepts HMAC-SHA1, inconsistent with DNSSEC rejecting SHA-1. Not practically broken (RFC 8945 still lists it). |
| SEC-2026-07-G | Fixed | `sync.rs:991` | Node register stores an attacker-chosen `cert_fingerprint` not bound to the peer's presented cert. Requires the sync-key. |
| SEC-2026-07-K | Fixed | `src/api/mod.rs` (`backup_import_handler`) | Backup import wrote restored secret files without `.mode(0o600)` (world-readable under `umask 022`). Detail below. |
| SEC-2026-07-L | Fixed | `src/dns/forward.rs` (`parse_response`/`soa_min_ttl`) | Forward negative-cache trusted any authority SOA with no in-bailiwick check. Detail below. |
| SEC-2026-07-P | Fixed | `src/dns/ratelimit.rs` (`RateLimiter::set_limits`) | Live `rate-limit-burst: 0` (rps>0) refused all non-loopback traffic (self-inflicted DoS, admin foot-gun). Detail below. |
| SEC-2026-07-Q | Fixed | `src/api` (`Role::may_write`) | `path.starts_with("/api/dns")` also matched `/api/dnssec*`/`/api/dns-*` — latent RBAC over-grant. Detail below. |
| PENT-06-1 | Fixed | `src/dns/cache_snapshot.rs` (`load_xdp_cache`) | `Instant`-overflow panic loading a corrupt persisted cache (`RBv1`) at startup. Detail below. (Originally PENT-1 in the 2026-07-06 pentest cycle.) |
| SEC-N4 | Fixed | slave relay/register receiver | Request body buffered before the 64 KiB cap (memory amplification, TLS+HMAC-gated). Fixed: `http_body_util::Limited` caps before `collect()`. |
| SEC-N5 | Fixed | relay/sync HMAC | HMAC accepted any valid signature in the ±30 s window with no replay nonce. Fixed: bounded seen-signature cache (16 384 hard cap), recorded only after HMAC verifies, fails open on lock poisoning. |
| SEC-K1 | Fixed | `src/anycast.rs` (`exabgp_bin`) | `exabgp-path` spawned without validation (Gemini rated HIGH RCE — disputed down; config-file-only, no API setter). Fixed: `validate_exabgp_path` rejects whitespace/shell metachars + must be an existing regular file. |
| SEC-L5 | Fixed | `src/dns/zone_signer.rs` | RRSIG inception set to "now" → a validator with a fast clock rejects fresh signatures. Fixed: backdate inception 1 h. |
| SEC-L6 | Fixed | `src/dns/recursor.rs` (`resolve_recursive`) | No outer time fuse on recursion → a flood toward deep delegations occupies a worker. Fixed: 5 s `RECURSION_TIMEOUT` → SERVFAIL. |
| SEC-L7 | Fixed | `src/dns/zone_signer.rs` (`sign_chain`) | CNAME chains in a signed local zone were not signed end-to-end (DNSSEC-correctness gap, not forgery). Fixed for CNAME; wildcard is a follow-up. |
| SEC-L8 | Fixed | (folded into SEC-L3) | Orphan private key left at the fixed path on a failed config write. Eliminated by the atomic-rename key write. |
| SEC-L12 | Accepted | per-IP DNS rate-limiter | Coarse flood mitigator (per-thread 10 ms-allow / 100 ms-deny cache), not a precise QPS cap. A precise token cap would add per-packet hot-path cost. |
| SEC-I2 | Fixed | `src/webui/mod.rs` (`handle_login`) | Username compared with `!=` (timing → admin username enumeration). Fixed: constant-time. |
| SEC-I6 | Fixed | `src/api/relay.rs` | Relay-forward error body returned `e.to_string()`, leaking the internal slave host:port. Fixed: generic body, full error in WARN log. |
| BUG-I8 | Fixed | `src/dns/ratelimit.rs` | Rate-limiter token refill `rps * elapsed_ms` could overflow `u64`. Fixed: `u128` + `saturating_add`. |
| BUG-I9 | Fixed | `src/dns/ratelimit.rs` | IPv4 `/0` prefix → `1u32 << 32` (debug panic; release wrong mask). Fixed: explicit `/0` case. |
| SEC-I11 | Fixed | `src/dns/kernel_loop.rs` (`sendmmsg`) | `iov_len = resp_len` directly; the replaced `send_to(&buf[..n])` had bounds-checked it — an oversized `resp_len` would read past the frame (info leak). Real regression. Fixed: clamp `iov_len` to `DNS_BUF_SIZE`. |
| BUG-I12 | Fixed | `src/cpu.rs` | `CPU_SET(core_id, …)` had no `CPU_SETSIZE` bound (stack write on a >1024-CPU host). Fixed: guard `core_id < CPU_SETSIZE`. |
| SEC-I24 | Fixed | slow-path auto-tune | `xdp-interface` name flows into sysfs paths without validation → traversal (admin-config, not API). Fixed: reject path-bearing names at the parse choke point. |
| SEC-I15 | Fixed | firewall `ufw` backend | `ufw` close-rule deleted by `port/proto`, risking removal of a same-port admin rule. Fixed: delete the exact rule (port/proto + our comment tag) with a broad-match fallback. |
| SEC-I16 | Fixed | `write_config_atomic` | Predictable `.tmp` filename (TOCTOU symlink). Fixed: unpredictable temp name + `O_EXCL` (`create_new`). |
| SEC-G1 | Fixed | `src/dns/axfr.rs:30` (`cidr_matches`) | AXFR-allow `/0` entry → `1u32 << 32` (debug panic; release matches nothing — fail-closed foot-gun). Fixed: clamp `prefix == 0 → mask 0`. |
| SEC-G8 | Fixed | `src/api/mod.rs` (`backup_import_handler`) | `fs::write(tmp, …)` followed a symlink pre-planted at the predictable tmp path → arbitrary file overwrite (precondition: data-dir write + admin import). Fixed: `create_new` (`O_CREAT|O_EXCL`). |
| SEC-H1 | Fixed | `src/api/mod.rs` (`/health`) | Unauthenticated `/health` disclosed the exact version + operational counters. Fixed: version dropped from unauthenticated `/health`. |
| SEC-H5 | Accepted | `src/dns/ratelimit.rs`, `ebpf/dns_xdp.c` | Rate-limit/ban table exhaustion via spoofed-source flood. Bounded by design (`MAX_RATE_LIMIT_BUCKETS` + idle eviction; LRU 65536). Transient cold-bucket eviction accepted (availability-over-fairness). |
| SEC-H8 | Fixed | `src/dns/kernel_loop.rs` (`recvmmsg`, `sockaddr_to_std`) | New `unsafe` receive path. No exploitable path found (fixed buffers, `iov_len` bound, family-checked parse); parse edge-case tests added, fuzz follow-up. |
| SEC-H9 | Fixed | `src/icmp.rs` (`persist_blacklist`) | Persistent IP blacklist written 0644 (local read) and unbounded growth. Fixed: 0600 + 100k-entry cap (load path also capped). |
| SEC-J5 | Fixed | `src/sync.rs:134` | Legacy header-only HMAC still accepted (rolling-upgrade compat) → theoretical body tampering only if TLS is also defeated. Fixed: legacy fallback removed (body-covering only). |
| SEC-J7 | Fixed | `src/sync.rs` (`ensure_relay_cert`, `ensure_sync_cert`) | TLS private keys `fs::write` then chmod 0600 (brief world-readable window). Fixed: `OpenOptions::mode(0o600)` atomically. |
| SEC-J13 | Fixed | `src/main.rs` | API Unix-socket setup TOCTOU (local). Fixed: unlink only if it is actually a socket. |
| SEC-J14 | Fixed | `src/upstreams.rs:380` (`add_upstream`) | Unbounded upstream addition via API (resource growth). Fixed: cap + dedup on (addr, port, protocol). |
| SEC-J6 | Accepted | `src/sync.rs` | Anti-replay is a ±30 s window with no nonce cache; replay only behind a defeated pinned-TLS channel. Defence-in-depth (nonce cache landed as SEC-N5). |
| SEC-J10 | Accepted | `src/dns/kernel_loop.rs` | Slow-path TX length not re-clamped to the written length; the send already clamps `tx_lens[i].min(DNS_BUF_SIZE)`. Explicit clamp-to-written-length is cheap hardening. |
| SEC-J11 | Accepted | `src/dns/xdp/umem.rs` | Ring/UMEM size integer-overflow; sizes are admin-config, validated to powers-of-two in `[64, 65536]`, not network-controlled. |
| SEC-C5 | Accepted | `src/sync.rs:103` | HMAC compare uses a hand-rolled XOR-fold over `zip` (final step `subtle::ct_eq`). Constant-time for the fixed 64-hex length; length-only leak is not secret. |
| SEC-C7 | Accepted | `src/sync.rs:1567` | Relay request body buffered before the 65 KB size check (needs a compromised `sync_key`; relay port LAN-only). |
| SEC-A2 | Fixed | `src/webui/mod.rs` | Session cookies missing the Secure flag. |
| SEC-A3 | Fixed | `src/webui/mod.rs` | Minimum WebUI password 4 chars (raised to 12). |
| SEC-A1 | Fixed | `src/webui/mod.rs` | No brute-force protection on WebUI login. |
| SEC-B15 | Accepted | `src/sync.rs` | `/proc/meminfo` not bounds-checked (reporting only). |
| SEC-B16 | Fixed | `src/api/mod.rs` | Unicode bidi control characters in log fields. |
| SEC-B17 | Fixed | `src/api/mod.rs` | Lock poisoning → process crash. |
| SEC-K2 | Accepted | `src/config/writer.rs` (`render_config`) | Anycast values re-emitted without `escape_str` — not currently reachable (config-file-only, no API setter). Standing note: escape if an anycast API setter is ever added. |
| PENT-4 | Fixed | `src/config/parser.rs` | WebUI `ui_bind` defaulted `0.0.0.0` (admin panel network-exposed). Fixed: default `127.0.0.1`. |
| PENT-5 | Fixed | `src/dns/tsig.rs` (`verify_request`) | TSIG key-name lookup not constant-time (key-name enumeration). Fixed: `subtle::ConstantTimeEq`, no early exit. |
| SEC-G2 | Fixed | `src/api/relay.rs:35` | Relay `NoCertVerifier` / TOFU bootstrap window (this is the SEC-B1 line, now pinned after first contact; out-of-band pin still an enhancement — OPEN item). |
| SEC-G7 | Open | `src/sync.rs:306` (`record_slave`) | `connected_slaves` map never pruned → slow unbounded growth. HMAC-gated + IP-keyed (bounded by distinct slave IPs); the live view filters to ≤ 5 min but the backing map is not pruned. Harden: drop entries older than the window. |
| VAL-2 | Fixed | `src/config/parser.rs` | Directives after an `axfr:`/`io-uring:` sub-block were misattributed and silently dropped (e.g. WebUI never started). Fixed: fall back to the parent `server` section on a non-sub-block key. |
| SEC-E2 | Fixed | `src/dns/simd.rs` (`find_zero_sse2`) | Inline-asm `options(nomem)` while `movdqu` reads memory — violates the inline-asm contract. Fixed: `nomem` removed. |
| SEC-A5 | Fixed | `src/sync.rs` | IPv6 link-local not blocked in `relay_host` validation. |
| QMIN-1 | Fixed | `src/dns/recursor_wire.rs` (`descend`) | QMIN relaxed-fallback latch was descent-wide, not cut-local → full QNAME leaked to deeper cuts / root on restart (privacy). Detail below. |
| QMIN-2 | Fixed | `src/dns/recursor_wire.rs` | `MAX_DEPTH` shared between delegation depth and per-cut probing → deep/flat legal names spuriously SERVFAIL (completeness). Detail below. |
| QMIN-3 | Accepted | `src/dns/recursor_wire.rs` | QMIN query amplification per validated resolution — hard-bounded (≤ `MAX_QUERIES=80` per descend). Detail below. |
| SEC-H2 | Disputed | `src/api/mod.rs:509` | "Bearer key timing side-channel" — refuted: `constant_time_eq` / `ct_eq`, no early exit. |
| SEC-H4 | Disputed | `src/sync.rs:103` | "Forge/replay of relay commands" — empirically rejected on the live slave (all vectors → 401; forged IP never banned). |
| SEC-G3 | Disputed | `src/sync.rs:101` | HMAC length-only timing signal — fixed 64-hex length, constant `false`; not exploitable. |
| SEC-G4 | Disputed | `ebpf/dns_xdp.c:108` | ICMP-echo per-source LRU churn via spoofed IPs — opt-in, LRU-bounded; bounded DoS of an optional feature. |
| SEC-C6 | Disputed | `ebpf/dns_xdp.c:292` | "ICMP checksum corruption on LE" — refuted: the double byte-swap cancels; responder disabled by default. |
| SEC-C8 | Disputed | `src/icmp.rs:80` | "`IcmpStats::ban()` leaves XDP unenforced" — refuted: `ban()` updates reporting state; all three call sites enforce XDP separately. |

**SEC-N4/N5 — relay body cap + HMAC replay nonce.** `[AI-INTERNAL]`. The slave relay/register
receiver buffered the body before enforcing the 64 KiB cap (**N4**, memory amplification bounded
by the TLS + HMAC gate — fixed with `http_body_util::Limited`); and the relay/sync HMAC accepted
any valid signature within the ±30 s window with no replay nonce (**N5** — fixed with a bounded
seen-signature cache recorded only after the HMAC verifies, pruned to the window, 16 384 hard
cap; fails open on lock poisoning, where the HMAC and window still gate authenticity).

**SEC-2026-07-K — backup import writes secret files without 0600.**
`[AI-ADVERSARIAL]` (double-pass). `backup_import_handler` wrote each restored file via
`OpenOptions::write(true).create_new(true)` with **no `.mode(0o600)`**. `BACKUP_STATE_FILES`
includes `api.key`, `webui-auth.conf`, `sync-key.pem`, `webui-ca-key.pem`; under `umask 022`
these landed `0644` — a window an unprivileged local reader could use. Every other secret-write
path forces `0600`; this one was the outlier (re-opens the window SEC-J7/SEC-L3 closed).
Admin-gated + local reader → LOW, but a real regression of the 0600 invariant. **Fixed:**
`.mode(0o600)` on tmp-file creation (all restored files). **Correctness sub-note (Fixed):**
`apply_config_hot_reload` re-reads zones/alerts/resolution only — a restored `api.key`/registry/
WebUI creds bind at startup and are inert until restart while the old secret keeps working (fails
safe). The success response no longer claims "applied live — no restart needed" for restored
secret material; it now states a restart is required.

**SEC-2026-07-L — forward negative-cache trusts the authority SOA with no in-bailiwick check.**
`[AI-ADVERSARIAL]` (double-pass). In `Forward` mode (the **default**), `parse_response` /
`soa_min_ttl` (`src/dns/forward.rs`) derived the RFC 2308 negative TTL from **any** `Rdata::Soa`
in `msg.authority`, with no check that the SOA owner encloses the qname — unlike the recursor
path (`validated_negative_authority`, which drops a forged/unsigned/out-of-bailiwick SOA). A
malicious/NATing upstream, or an on-path spoofer who already defeats the SEC-O1 window, could pin
a negative for a name under an unrelated zone's SOA. **Bounded to LOW:** forward mode does not
DNSSEC-validate (the configured upstream is a trusted actor entitled to deny), and the only
untrusted actor (on-path spoofer) must already beat SEC-O1 — with which it could inject a forged
positive instead; the negative-cache path grants no new capability. Poisoning is scoped to the
exact `(qname, qtype)` and the TTL is hard-clamped to `NEG_CACHE_MAX_TTL = 900 s`. **Fixed:**
`zone_soas()` / the `soa_min_ttl` guard keep only SOAs where `qname.is_in_zone(&soa.name)`, using
the response's own (SEC-O1-matched) question as the anchor; new unit test
`negative_soa_out_of_bailiwick_is_dropped`. **Documented limitation:** `is_in_zone` treats an
ancestor/root SOA as enclosing, so a laterally-unrelated SOA is rejected but an ancestor SOA
(`.`/`tld`) is not; its impact is identical and already bounded (exact-key scope + 900 s clamp),
so no stronger check is warranted without the delegation chain forward mode lacks.

**SEC-2026-07-P — live `rate-limit-burst: 0` refuses all non-loopback traffic.**
`[AI-ADVERSARIAL]` (round 2). `RateLimiter::set_limits` stored `burst` verbatim.
`PATCH /api/config {"rate_limit":N,"rate_limit_burst":0}` (N>0) left every non-loopback bucket at
`tokens=0` forever (tokens never refill above `burst`) → self-inflicted DoS. Authenticated (admin
bearer, RBAC-gated), so an operator foot-gun, not an unauthenticated vector. **Fixed:** clamp
`burst.max(1)` when `rps>0` in `set_limits`.

**SEC-2026-07-Q — `Role::may_write` prefix match grants `/api/dns*` beyond `/api/dns/`.**
`[AI-ADVERSARIAL]` (round 2). `path.starts_with("/api/dns")` also matches `/api/dnssec*` /
`/api/dns-*`. Inoffensive today (`/api/dnssec/ds` is GET-only, never `may_write`-checked; no
write-only admin route begins with `/api/dns`), but a latent trap: a future write endpoint under
`/api/dnssec` would be reachable by the `Dns` role by accident. **Fixed:** a segment-aware match
(`path == base || path[base..].starts_with('/')`) for dns/zones/blacklist/feeds. Defence-in-depth,
zero runtime cost.

**PENT-06-1 — `Instant`-overflow panic loading a corrupt persisted cache.**
`[AI-ADVERSARIAL]` (2026-07-06 pentest; originally PENT-1 in that cycle). `load_xdp_cache`
computes `expires_at = instant_now + Duration::from_secs(pe.expires_secs - now_unix)`
(`src/dns/cache_snapshot.rs`). The prior `if pe.expires_secs <= now_unix { continue }` guard
rules out the underflow, but a corrupt or crafted persisted cache file (`RBv1`) carrying an absurd
`expires_secs` makes `remaining` span centuries and `Instant + remaining` **panics on overflow at
startup** — a boot-time crash on a merely corrupt (not necessarily malicious) cache file.
**Reach:** local write to the cache file only (not network, not unauthenticated) — hence LOW, but
a genuine `panic` path and the sole one the whole pentest surfaced. **Fixed:**
`instant_now.checked_add(remaining)`; on overflow skip the entry, matching the existing
"corrupt entry — skip" pattern.

**QMIN-1/2/3 — QNAME minimisation (#231).** `[AI-ADVERSARIAL]` (two disjoint lanes + maintainer
reproduction). **QMIN-1 (Fixed, privacy):** `descend()`'s `full` fallback latch was initialised
once per descent and never reset, so a single lame/mute/hostile cut — or a dead cached cut (#230)
forcing a root restart — disabled minimisation for the entire remaining descent, leaking the full
query name to every deeper cut (and, on a root restart, to the root/TLD). Integrity unaffected
(answers still DNSSEC-validated). **Fixed:** reset `full = false` (and `extra = 0`) on every
accepted referral and on the root restart, making the fallback strictly cut-local. **QMIN-2
(Fixed, completeness):** `MAX_DEPTH` was shared between real delegation depth and per-cut probing
(`extra += 1` + relaxed fallback), so a legal but pathologically deep/flat name (≈20+ labels under
one or two cuts) could exhaust `MAX_DEPTH = 24` and return a spurious SERVFAIL for a name that
resolves with minimisation off. Bounded failure — no spin, no amplification. **Fixed:** count only
real delegation steps against `MAX_DEPTH` (separate `delegations` counter); the loop stays
hard-bounded by the query budget. **QMIN-3 (Accepted, DoS):** minimisation raises the worst-case
upstream-query constant per descent (~1 → up to `1 + MAX_MINIMISE + 1 ≈ 12` per cut); layered on
the pre-existing #230 per-fetch `MAX_QUERIES` reset, the client→upstream ratio grows. It remains
hard-bounded (each `descend` caps at 80 queries via the shared `&mut budget`; fetches bounded by
`MAX_CNAME` × chain depth). A single amplification budget threaded through the whole
`resolve_validated` operation is the correct hardening, tracked as future work; `MAX_MINIMISE = 10`
matches Unbound.

---

### INFO

| ID | Status | Location | Summary |
|----|--------|----------|---------|
| SEC-2026-07-H | Accepted | `api/relay.rs:46` | Relay TLS accepts any cert before the TOFU pin is established; authenticity rests on HMAC-SHA256. Pin applied after first contact. |
| SEC-2026-07-I | Accepted | `webui/mod.rs:206` | Random one-time bootstrap admin password logged once (refuses `admin/admin`); only the Argon2 hash is persisted. |
| SEC-2026-07-M | Fixed | `src/dns/dnssec_denial.rs` (`parse_nsec`) | `parse_nsec` sliced the NSEC type bitmap at the presentation name length rather than bytes-consumed. Detail below. |
| SEC-2026-07-N | Accepted | `src/webui/index.html`, session TTL | WebUI 8 h absolute `SESSION_TTL` vs the 5-minute idle auto-logout — stolen cookie valid up to 8 h only if the victim's tab is closed. Detail below. |
| PENT-06-2 | Accepted | `src/dns/plain_server.rs` (`run_tcp`) | Plain-TCP listener has no per-source connection cap — generic connection-exhaustion pressure. Detail below. (Originally PENT-2 in the 2026-07-06 pentest cycle.) |
| QMIN-4 | Accepted | `src/config/parser.rs` | `qname-minimisation` accepts any non-`"no"` token as ON (`val != "no"`) — deliberate fail-toward-privacy default. Detail below. |
| QMIN-5 | Disputed | `src/dns/recursor_wire.rs` | Minimised probe question is low-entropy content — refuted: does not reduce off-path spoofing resistance (defending entropy is txid + source port + root choice). Detail below. |
| SEC-N6 | Fixed | `src/config/writer.rs` | Several config-writer string fields written unescaped — not reachable across a trust boundary (config-file only). Fixed as defence-in-depth (`escape_str`). |
| SEC-N7 | Fixed (partial) | `src/alerts.rs` (webhook SSRF guard) | SSRF guard rejected only literal-IP hosts, not hostnames resolving to private/metadata addresses. Fixed: resolve + re-check each IP (incl. IPv6 ULA/link-local), fail-closed. Resolve/connect TOCTOU remains → OPEN-N2. |
| SEC-L9 | Fixed | `/api/dnssec/ds` | Rebuilt the signer with `load_or_generate` on every GET (wrote fresh keys on a read; on a slave minted divergent local keys). Fixed: read the live in-memory signer. |
| SEC-L10 | Fixed | `/api/tls/*` | Mutating TLS handlers now carry an internal `caller.admin` check (defence-in-depth) atop the deny-by-default allow-list and slave-guard. |
| SEC-L11 | Fixed | `import_key` | Defence-in-depth: `import_key` rejects any `file` other than `ksk.key`/`zsk.key`. The relayed `file` is slave-hardcoded and the relay is HMAC-authenticated, so the flagged traversal is not reachable; fenced anyway. |
| SEC-O3 | Accepted | `src/dns/tsig.rs` (`verify_request`) | TSIG replay: ±300 s window kept, no replay nonce → a captured valid signed UPDATE replayable within 300 s (inherent single-message TSIG property, RFC 8945 §5.2.3). Detail below. |
| SEC-O5 | Accepted | `src/dns/tsig.rs` (`verify_request`) | Full-tag compare rejects a legitimately truncated MAC (RFC 8945 §5.2.2.1) — interop, not security. Detail below. |
| SEC-O6 | Fixed | `src/dns/server.rs` | Inaccurate comment about recursion/TSIG/AXFR handling corrected — TSIG/AXFR are served wire-native. |
| SEC-K4 | INFO (positive) | `src/anycast.rs` (`generate_exabgp_conf`) | exabgp config-injection guard verified effective (hex/`.`/`:`/`/` whitelist blocks newline/`;`/`{}`); `local-as`/`peer-as` typed `u32`. No change needed. |
| SEC-K5 | INFO (positive) | `src/anycast.rs` (child reaping) | Child reaping correctly depends on the systemd cgroup (`KillMode=control-group`); `PR_SET_PDEATHSIG` best-effort; running outside a cgroup supervisor documented as a hard requirement. |
| SEC-H10 | Fixed | slave `runbound.conf` | Slave ran without DNSSEC validation. Fixed: `dnssec-validation: yes` on the slave (matches master). |
| SEC-H11 | Accepted | NIC / network layer | L3 volumetric flood saturating the NIC — mitigated upstream (scrubbing), out of DNS-application scope. |
| SEC-A4 | Accepted | `src/webui/mod.rs` | CSRF token non-constant-time compare (superseded by SEC-I1 fix). |
| SEC-A6 | Accepted | dependency chain | Unmaintained-crate advisories (no active CVEs). Re-checked under `cargo audit`/`cargo deny` in the automated pass. |
| INFO-E1 | Accepted | `src/api/mod.rs:514` | `AUTH_FAILURES` reset race (`Relaxed`): a coarse braking counter, may slightly under-count (safe, more lenient). |
| INFO-E2 | Accepted | `src/dns/simd.rs`, `src/dns/hasher.rs` | SIMD unsafe blocks reviewed: capacity-before-write, lifetime-bound pointers, feature gates match dispatch. No exploitable memory-safety issue. |
| SEC-G5 | Disputed | `src/dns/hasher.rs`, `src/dns/simd.rs` | Hand-written asm/SIMD kernels — asm/scalar equivalence exhaustively test-verified; not a vulnerability. |
| SEC-G6 | Disputed | `src/dns/xdp/wire_builder.rs` | TSIG-signed A/AAAA answered by the wire fast path without TSIG validation — authorisation is by source-IP ACL, not TSIG; answering a public A while ignoring an attached TSIG grants nothing beyond the ACL. Defensive note: pass to the slow path on a non-OPT additional record. |
| SEC-O4 | Disputed | `src/dns/tsig.rs` | "Original ID not substituted before the MAC (RFC 8945 §4.3.3)." Refuted for request verification: for a request the received header ID equals the Original ID, so a matching request verifies and an ID-tampered one fails — the correct, stronger behaviour. |
| INFO-F1, E-001..E-004 | Accepted / No finding | `src/webhooks.rs`, `src/api/mod.rs` | Webhook/serde INFO items: serde syntax errors reflect only line/column; webhook SSRF `is_safe_url` validated; unbounded delivery queue (admin-config, retry-bounded) accepted; `/webhooks/test` auth-gated. |
| BUG-E1 | Fixed | `src/alerts.rs` (`block_bot`) | Logic bug: sent the literal `"bot_ban"` as a webhook URL; bot events never delivered. Fixed: removed the bad send (events still recorded). |
| ACC-E1/E2, ACC-F1/F2/F3 | Accepted | `src/sync.rs`, `src/alerts.rs`, `src/webui/mod.rs` | HMAC 30 s replay window (nonce landed as SEC-N5); TOFU first-registration window; ban injection via compromised slave (relay is one-directional — false-positive threat); AlertTracker hot-reload (RwLock correct); `ui-tls-san` SAN injection (rcgen validates all SANs). |
| DOC-F1, DOC-F2 | Fixed | README, `SECURITY.md`, `THREAT_MODEL.md` | Unverifiable marketing claim removed; missing `SECURITY.md`/`THREAT_MODEL.md` added. (Documentation — recorded for completeness, out of severity scope.) |
| PERF-C1 | Open | `src/dns/hasher.rs`, `ebpf/dns_xdp.c:166` | Hash inconsistency: Rust CRC32c vs BPF FNV-1a (+lowercasing divergence) breaks per-domain CPU affinity (#67). Affects only the XDP domain-routing feature (off by default). |
| PERF-C2 | Accepted | `ebpf/dns_xdp.c:309` | CPUMAP domain-routing limited to 64 cores — experimental feature, off by default. |
| SEC-J8 | Open (deferred) | `ebpf/dns_xdp.c` | ICMP rate-limiter off-by-one (`>=` vs `>`) — one extra packet per window. Cosmetic; deferred (touches the datapath). |
| INFO-R2-1 | Accepted | `src/dns/server.rs:2157` (`read_proxy_v2`) | PROXY-v2 header allocates a peer-controlled `u16` length (≤64 KiB/connection, bounded by `TCP_CONN_PER_IP_MAX`); `proxy-protocol` off by default and, when on, the peer is a trusted L7 proxy. Optional len-validation not taken. |

**PENT-3 / capabilities.** `[AI-INTERNAL]`. The systemd unit granted
`CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF CAP_PERFMON` unconditionally; with
`xdp: no` (the prod default) only `CAP_NET_BIND_SERVICE` is needed. `NET_ADMIN`/`NET_RAW`/
`BPF`/`PERFMON` widen the blast radius of any future memory-safety bug from "crash a worker" to
"manipulate the host network / load kernel programs." No RCE was found, but the blast radius was
unnecessarily wide. **Fixed:** default `AmbientCapabilities`/`CapabilityBoundingSet` reduced to
`CAP_NET_BIND_SERVICE`; the XDP/firewall caps are a commented opt-in. Re-tested: `CapEff =
cap_net_bind_service` only.

**SEC-O3 / SEC-O5 — TSIG replay + truncated MAC (Accepted).** `[AI-INTERNAL]`. `tsig::verify_request`
enforces a ±300 s window but keeps no replay nonce, so a captured valid signed UPDATE can be
replayed within 300 s (**O3**) — the inherent single-message TSIG property (RFC 8945 §5.2.3);
add/delete are idempotent for the common case, and the relay/sync path has a nonce (SEC-N5).
`verify_request` compares the full tag, so a legitimately truncated MAC (RFC 8945 §5.2.2.1) is
rejected (**O5**) — interop, not security. Both **Accepted**.

**SEC-2026-07-M — `parse_nsec` sliced the type bitmap at the presentation name length.**
`[AI-ADVERSARIAL]` (double-pass). `parse_nsec` (`src/dns/dnssec_denial.rs`) computed the bitmap
offset as `next.len()` (decompressed presentation length) rather than the decoder's consumed byte
count. RFC 4034 §4.1.1 forbids compression in the NSEC next-name, so in practice `next.len()` ==
bytes-consumed; a violating peer could mis-offset the bitmap, but the path is fail-closed (a
compression pointer inside the RDATA parses backward and hits `NameTooLong`/`MAX_POINTERS` → `Err`
→ `None`; the `> rdata.len()` guard keeps the slice panic-free) and config-gated behind
`resolution: full-recursion` + `dnssec-validation: yes`; the worst case is a denial proof failing
→ Bogus → SERVFAIL (safe direction). **Fixed** to slice at `dec.pos()` (exact bytes read).

**SEC-2026-07-N — WebUI 8 h absolute session vs the 5-minute idle auto-logout (Accepted).**
`[AI-ADVERSARIAL]` (double-pass), maintainer decision 2026-07-07. The idle auto-logout is real and
works: `index.html` `resetIdleTimer()` (5 min, sliding — reset on click/keydown/mousemove/
touchstart) fires `POST /logout`, which the server honours by removing the token from
`state.sessions` (a genuine server-side invalidation). The residual — a stolen cookie is valid up
to the 8 h `SESSION_TTL` only if the victim's tab is closed (idle JS not running) — is accepted:
the `HttpOnly`/`SameSite` cookie plus the working idle logout cover the realistic cases.

**PENT-06-2 — plain-TCP listener has no per-source connection cap (Accepted).**
`[AI-ADVERSARIAL]` (2026-07-06 pentest; originally PENT-2 in that cycle). `run_tcp`
(`src/dns/plain_server.rs`) spawns one task per accepted connection with no per-source or global
concurrency limit — generic connection-exhaustion pressure (not a crash; each message allocation is
`u16`-bounded). The primary serving paths (XDP / kernel-UDP) sit behind the per-source rate-limiter
and inflight cap. **Decision — Accepted** (defence-in-depth; a per-IP TCP accept cap is reasonable
future hardening).

**QMIN-4 / QMIN-5 — parser default & probe entropy.** `[AI-ADVERSARIAL]` (#231). **QMIN-4
(Accepted, INFO):** `parser.rs` uses `val != "no"`, so a typo (`nope`, `0`, `false`) parses
`qname-minimisation` to ON, unlike sibling booleans that use `== "yes"`. Chosen deliberately: the
default is ON and the relaxed engine never breaks resolution, so an ambiguous value fails toward
more privacy, never toward a silent disable. **QMIN-5 (Disputed):** the first probe to a root
server is a guessable `(TLD, A)`, but this does not reduce off-path spoofing resistance — the
defending entropy is the random 16-bit txid + the ephemeral source port (connected UDP socket) +
which of 13 root IPs was chosen, none of which minimisation changes; the question content was never
a secret. Recorded for completeness, refuted as a vulnerability.

---

## Verified with no exploitable finding (negative space)

The following areas were reviewed adversarially and/or exercised live and carry no finding.
They are an explicit part of the audit, not an omission.

- **Wire parser & name decompression.** `wire::Name::parse` resists the classic
  compression-pointer DoS: `MAX_POINTERS = 127`, strictly-backward pointers (`target >= pos`
  rejected), `MAX_NAME_WIRE = 255` budget, full bounds checks, reserved label types rejected.
  2091 hostile packets (self-referential/forward/out-of-range pointers, truncation at every
  offset, `0xffff` record counts, over-long labels, malformed EDNS, 2000 random-byte packets,
  all 16 opcodes) → **0 crash, 0 restart**. This refuted an adversarial "CRITICAL panic in
  `Name::parse`" claim (`resume = Some(pos)` is set at the root terminator before the break, so
  `resume.expect()` is never reached with `None`). Re-fuzzed in later cycles: `Message::parse`
  1.75 M then 4.75 M exec, name decompression 520 k exec — **0 crash** (double-pass / round 2),
  and the pentest's `fuzz_dns_query` (8.01 M) / `fuzz_dns_name` (2.31 M) — **0 crash**.
- **XDP/UMEM memory safety.** Kernel descriptors are bounds-checked via `checked_add` before
  deref; the eBPF verifier statically rejects any unbounded packet access (existing guards:
  `(void*)(dns+1) > data_end`, `(icmp+1) > data_end`, `(ip->ihl & 0xF) != 5 → XDP_PASS` for IP
  options, fixed 40-byte IPv6, `if (cpu >= 64) return XDP_PASS`). The XDP fast-path parser
  (`wire_builder.rs`) has all `buf[..]` indexing length-gated; response builders compute `total`
  and bail before writing.
- **SIMD / inline-asm.** Guarded vector loads with a scalar tail; asm/scalar equivalence is
  exhaustively test-verified across all input lengths; capacity is reserved before raw writes and
  `set_len` runs only after initialisation.
- **DNSSEC.** Fail-closed; Bogus → SERVFAIL and **never cached** (all four sites; CD=1 excepted);
  zone↔qname binding against downgrade; SHA-1 rejected; wildcard denial required; the compact-denial
  NODATA→NXDOMAIN path is gated on a validated in-bailiwick NSEC with `owner == qname` carrying
  NXNAME(128); the in-house signer is oracle-proven byte-identical to the `hickory-proto`
  differential test oracle and delv-validated (positive A, SOA apex, CNAME chain, NSEC3 NXDOMAIN +
  NODATA all "fully validated"). AD is set only for Secure + DO=1 and faithfully reflects validation
  state. Live across cycles: `cloudflare.com → Secure`, `dnssec-failed.org → Bogus (SERVFAIL)`,
  `google.com → Insecure`, `iana.org / verisign.com / isc.org / nic.cz → Secure`.
- **Recursor & QNAME minimisation (#231).** Hard budgets (`MAX_QUERIES=80` / `MAX_DEPTH` /
  `MAX_CNAME` / `MAX_MINIMISE=10` / timeouts); referrals must move strictly down-tree; qname-min
  widening bounded; the referral filter matches the real `qname`, not the probe prefix, so a
  lame/hostile in-bailiwick server gains no new delegation reach. DNSSEC fail-closed preserved
  through minimisation (every probing branch `continue`s; terminal returns guarded by `!probing`,
  so the validated message always carries the real `(qname, qtype)`); DS-at-parent anchoring (#230)
  intact; the sole `.expect()` in `minimised()` is provably unreachable. Packet capture of a cold
  resolution shows the root receiving only `com. / org. / net. / one.` — never a full FQDN.
- **rkyv cache load** — the **validating** path (`rkyv::from_bytes` / `from_bytes`, not
  `access_unchecked`), magic-prefixed (`RBv1`), corrupt file logged and ignored (cold start), not
  panicked (memory-safe; the one arithmetic edge is PENT-06-1, fixed).
- **Relay HMAC & TSIG.** Relay HMAC is constant-time with a ±30 s replay window and a bounded
  anti-replay cache; forge/replay vectors (no headers / forged sig / replayed old timestamp /
  empty sig / plain-HTTP) were all rejected `401`/connection-refused on the live slave, and a
  forged ban IP never appeared in the slave's banned set. TLS is TOFU cert-pinned (re-pin rejected).
  TSIG MAC verification is constant-time (`ring::hmac::verify`) and fail-closed (no keys → REFUSED;
  `allow-update: no` → REFUSED before any parse).
- **Master API key.** Constant-time compare backed by `subtle::ConstantTimeEq`, a pre-comparison
  brute-force brake (sleep applied before the compare, so it is not a timing signal), a 429
  lockout after repeated invalid attempts, audit events, and RBAC write-gating. The API binds
  loopback and never trusts `X-Forwarded-For`.
- **RBAC (measured across 4 roles).** The allowlist is fail-closed and keyed on the un-stripped
  URI; `PATCH /api/config` (rate-limit), ban/unban, blacklist, rotate-key, users, backup are all
  admin-only (403 for Read/Dns/Operator). The audit-log actor is folded into the per-entry MAC
  (not header-spoofable).
- **Command execution.** The firewall backend and the ACME/exabgp spawns use argv arrays
  (`Command::new(cmd).arg(..)`), no shell; the executable paths that are run come from the
  admin-only config file, not the API — no authenticated config-write → RCE path (`PatchConfigBody`
  is typed to a single `dnssec_validation` field; the one API path that reached a directive, SEC-J1,
  is fixed; rendered config is re-parsed before rename). `ethtool` iface via
  `sanitize_iface_name()` (`[A-Za-z0-9._-]`, ≤15).
- **Path traversal.** Strict UUID validation and `..` rejection on API/backup/routing paths;
  `include:` uses `canonicalize()` + `starts_with(top_dir)` + caps; backup/feed/config writes use
  `O_EXCL`; the router is case-sensitive; WebUI `/webui/../../etc/passwd` and encoded variants → 404.
- **Secret disclosure.** The configured TSIG secret and the API key value are not echoed by any
  endpoint (`/api/config` / `/api/system` expose only field names); no private-key bytes are logged
  or returned.
- **ACL Deny semantics.** A `Deny` verdict returns an empty buffer which both the UDP and TCP
  listeners drop without sending — a silent drop, not a malformed empty datagram.
- **Rate limiter & resource limits.** Bounded and HashDoS-resistant (bucket table capped 65536 with
  flood eviction; shift-by-32 UB guarded; `u128` `saturating_add`); per-IP TCP connection cap
  (exactly 20 held, the rest dropped); over-threshold queries REFUSED; a UDP flood did not degrade
  local-zone latency. Every ban path routes through a central insert with loopback/unspecified
  exemption and caps (`MAX_BANNED=100k`, `MAX_BLOCKED_ENTRIES=50k`, `MAX_CLIENT_BUCKETS=100k`);
  `record()` escalates only verified sources, so an off-path spoofer cannot get a victim IP banned.
- **Log injection.** Query names with raw control bytes are stored escaped in `/api/logs` — no
  log-line injection; Unicode bidi controls neutralised (SEC-B16).
- **DDNS.** TSIG mandatory, 300 s skew window, refuses deleting statically-configured names.
- **Transport gates.** `axfr-enable: no` hands the server an empty allow-list and refuses every
  transfer (the real list is never read on a disabled gate); `do-udp`/`do-tcp` gates behave.
- **Datapath stability across the serving and feature work.** For the DNSSEC-signing,
  recursion and anycast work, the XDP/eBPF/AF_XDP packet code is confirmed byte-identical to
  its baseline (empty `git diff` over `src/dns/xdp/`, `ebpf/`, `src/dns/kernel_loop.rs`,
  `src/dns/hasher.rs`), so no fast-path finding could be introduced by that work. The one
  exception is a single `bans_active`-gated per-packet ban
  lookup added for the abuse engine: an A/B X710 NIC-truth bench (gate vs pre-gate baseline, two
  rounds, order reversed) measured ~10.09–10.11 M qps served both ways (Δ ±0.12 %, within
  run-to-run noise), and the program passed the kernel verifier at load — no fast-path
  regression.

No CRITICAL was found in any cycle. After SEC-2026-07-A (quinn-proto) there is no unauthenticated
remote HIGH.

---

## Open items & remediation

### Open findings and enhancements

| ID | Severity | Status | Item |
|----|----------|--------|------|
| OPEN-F1 (#170) | — | Open | No third-party human security audit yet — the AI passes do not replace it. |
| OPEN-F3 | — | Open (not planned) | Strict Response Rate Limiting (RFC 5358) not implemented (ANY-block per RFC 8482 + per-IP limiting only). |
| OPEN-N1 | MEDIUM | Open | Thread the configured upstream-resolver addresses into the ban allowlist so a self-hosted resolver cannot be banned by its own traffic (partial fix in SEC-N3). |
| OPEN-N2 | INFO | Open | Pin the SSRF-vetted resolved IP into the webhook request to close the resolve/connect (DNS-rebinding) TOCTOU (partial fix in SEC-N7). |
| OPEN-L1 | LOW | Open | Cache the signed RRSIG + NSEC3 chain per (zone, owner-set) with a TTL so a DO=1 random-name flood cannot force repeated signing (SEC-L1 removed the dominant per-RR key reconstruction). Deferred to avoid stale-denial risk. |
| OPEN-K1 | INFO | Open | BGP withdrawal is liveness-only, not readiness-based: an alive-but-degraded node keeps its announcement. Proposed: optional health-gated withdraw behind a config toggle, keeping liveness as default. |
| OPEN-O1 | — | Open | Per-upstream UDP socket pool to bound FD use / cut bind churn on the forward path (SEC-O2 self-raised `RLIMIT_NOFILE`; the per-query bind is still wasteful). |
| SEC-G7 | LOW | Open | Prune the `connected_slaves` map to the last-seen window. |
| SEC-J8 | LOW | Open (deferred) | ICMP rate-limiter off-by-one — deferred (touches the eBPF datapath). |
| PAR-6 | LOW | Open | Prefetch is an incomplete feature (counts but no executor drains it) in both builds — needs a prefetch loop. |
| PAR-7 | INFO | Open | DDR (#204, RFC 9462) SVCB synthesis is recursor-only — needs a wire-native SVCB builder to port. |
| PAR-8 | INFO | Open | Forward-path DNSSEC AD tracking + slow-path negative caching are recursor-only (local signed zones + XDP negative cache unaffected). |
| PERF-C1 | INFO | Open | Rust CRC32c vs BPF FNV-1a hash inconsistency (XDP domain-routing, off by default). |
| QMIN-3 | LOW | Accepted (future work) | Thread a single amplification budget through the whole `resolve_validated` operation (per-fetch `MAX_QUERIES` reset is the residual). |

The following were also HIGH-related residuals rather than clean closures, and are called out
explicitly: **SEC-B6** (no per-zone AXFR ACL) is Accepted; **SEC-C1/SEC-B1** leave a residual —
nodes registered without a stored `cert_fingerprint` still use `NoCertVerifier` on relay
connections and must re-register to activate full pinning; **SEC-2026-07-G** notes the registered
`cert_fingerprint` is not bound to the peer's presented cert (fixed, but the bind is the durable
hardening). SEC-2026-07-H (relay TLS pre-pin) and the TOFU first-contact window (SEC-G2/SEC-H3)
remain the documented bootstrap assumption; an out-of-band fingerprint pin would close it.

### Remediation plan (pending maintainer approval)

Per the audit conventions, some remediation is filed against a plan that awaits maintainer
approval before it is applied, and any applied fix must be re-reviewed in a different session or
model. The outstanding plan:

1. **Unify the three SSRF filters** (feeds, webhooks, recursor) into one shared function:
   RFC1918 + CGNAT + all IPv6 special ranges + resolution-time filtering. Closes SEC-2026-07-B
   and -C at the root and removes OPEN-N2's TOCTOU. *(A first cut landed: `is_private_ip` was
   redefined as the exact inverse of `recursor_wire::is_public_ip`, and webhook `is_safe_url`
   gained `.internal/.corp/.lan` guards; the full unification is the durable form.)*
2. **SEC-2026-07-D:** when the store key is configured, treat a missing `.mac` as `Err` (refuse
   load) with an explicit one-shot migration flag instead of a permanent fail-open. *(Applied:
   migration mode now writes the missing sidecar genuinely once, and callers handle the
   fail-closed `Err` without panicking.)*
3. **SEC-2026-07-E/F/G:** constant-time `by_api_key`; drop/deprecate HMAC-SHA1 in TSIG; bind the
   registered `cert_fingerprint` to the peer's presented certificate.

### Known limitations and accepted risks

1. **No third-party human review.** All findings are AI-produced or maintainer-verified. These
   audits do not substitute for professional penetration testing (OPEN-F1 / #170).
2. **Relay bootstrap.** The relay is designed for controlled LAN environments; the TOFU
   first-contact window is a documented assumption, mitigated by the HMAC-SHA256 command
   authenticity layer. Pre-pinning nodes require re-registration.
3. **Rate-limit precision.** The per-IP DNS rate-limiter is a coarse flood mitigator, not a
   precise QPS cap (SEC-L12) — a deliberate performance-vs-precision trade-off on the hot path.
4. **Forward mode does not DNSSEC-validate.** By design — forward mode trusts the configured
   upstream (`resolution: forward`); users needing on-path integrity use `resolution:
   full-recursion` (in-house validation, fail-closed). SEC-2026-07-L hardens the SOA hygiene
   within that trust model; a tiny SOA `minimum` floored to `cache_min_ttl` can linger up to
   `min(cache_min_ttl, 900 s)` (bounded cache-pollution class, already Accepted as SEC-H5/I7).
5. **eBPF ICMP responder** is disabled by default; several ICMP/anycast items (SEC-C6, SEC-G4,
   SEC-J8, PERF-C2) concern opt-in features.
6. **Anycast trust boundary.** The `anycast:` block is config-file-only (no API setter); an
   operator who can edit the config already has root-equivalent access — this caps the severity
   of anycast config-value findings at the operator-trust level (SEC-K1/K2/K4/K5).
7. **`unsafe` surface.** The SIMD, CRC32c, `recvmmsg`/`sockaddr`, and AF_XDP paths carry
   `unsafe`; reviewed and (for the receive path) parse-edge-case-tested, with fuzz/MIRI follow-up
   recommended. The recursor `descend()` state machine is not yet directly fuzzed (reachable only
   via live sockets); a `recursor_wire::descend` fuzz target fed crafted referral/glue responses
   is the highest-value next coverage.

### Cross-cycle validation

Each folded-in cycle ran a clean build with `cargo clippy --release` zero warnings and the unit
suite green: the pentest cache suite (27 passed) and the #231 unit suite (467 passed), then the
double-pass and round-2 cycles (468 passed / 0 failed, including the new in-bailiwick test). The
performance-sensitive hot path was untouched by the double-pass, round-2 and #231 work (no re-bench
required for those cycles); the one datapath-adjacent change (the abuse-engine ban lookup) was
A/B-benched on the X710 with no regression (see negative space).
