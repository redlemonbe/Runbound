# Runbound — Security Audit Master Document

**Current version:** v0.9.40  
**Last updated:** 2026-05-25  
**Maintained by:** RedLemonBe — https://github.com/redlemonbe/Runbound

This document consolidates all security and performance audit cycles conducted on Runbound. Individual per-cycle files in this directory are historical records; this file is the authoritative status reference.

---

## Audit Cycle History

| Cycle | Version range | Date | Sources | Open findings |
|-------|--------------|------|---------|---------------|
| [Pre-release](#pre-release-audits-v045--v094) | v0.4.5 → v0.9.4 | 2026-05-23/24 | AI-INTERNAL, AI-ADVERSARIAL (Gemini 2.5 Pro) | 0 (all fixed or accepted) |
| [A](#cycle-a--v0910) | v0.8.2 → v0.9.10 | 2026-05-25 | AI-INTERNAL | 0 (all fixed or accepted) |
| [B](#cycle-b--v0915) | v0.9.10 → v0.9.15 | 2026-05-25 | AI-ADVERSARIAL | 1 open (SEC-B13) |
| [C](#cycle-c--v0938) | v0.9.15 → v0.9.38 | 2026-05-25 | AI-ADVERSARIAL + AI-ADVERSARIAL (Gemini 2.5 Pro) | 0 (all fixed, accepted, or disputed) |

---

## Current Open Findings

As of v0.9.40, the following findings remain unresolved:

| ID | Severity | File | Description |
|----|----------|------|-------------|
| SEC-B13 | MEDIUM | relay.rs | Relay SNI hardcoded to `"runbound-relay"` — fix depends on full fleet re-registration |

All other previously-open findings have been fixed (SEC-B7, SEC-B10, SEC-B16, SEC-C1, SEC-C2, SEC-C3, SEC-C4), accepted (SEC-B6, SEC-B8, SEC-B11, SEC-B15, SEC-C5, SEC-C7, PERF-C2), or classified as false positives (SEC-C6, SEC-C8).

---

## Cycle C — v0.9.38

**Date:** 2026-05-25  
**Version audited:** v0.9.38  
**Sources:**
- [AI-ADVERSARIAL: Claude Sonnet 4.6] — adversarial audit, separate session from implementation
- [AI-ADVERSARIAL: Gemini 2.5 Pro via CLI on VM2] — independent model, separate audit session (R10)

**Scope:** Relay, ICMP, eBPF, and domain hasher subsystems added or changed between v0.9.15 and v0.9.38.

---

### SEC-C1 — Config push uses NoCertVerifier (SEC-B1 partial regression)
**Severity:** HIGH  
**Source:** [AI-ADVERSARIAL: Claude Sonnet 4.6] confirmed by [AI-ADVERSARIAL: Gemini 2.5 Pro]  
**File:** `src/api/relay.rs:314`  
**Status:** ✅ Fixed in v0.9.40  
**Verification:** Code review — `push_to_slaves` now clones `slave.cert_fingerprint` and passes it to the spawned task, which calls `pinned_client_config(fp)` when a fingerprint is available.

**Description:** The Cycle B fix for SEC-B1 applied cert pinning to `relay_forward_handler` but left `push_to_slaves` (DNS zone replication, blacklist sync, feed pushes) using `NoCertVerifier` unconditionally.

**Fix:** `push_to_slaves` now mirrors the logic in `relay_forward_handler`: extracts `cert_fingerprint` from the registered slave and uses `pinned_client_config(fp)` when available, falling back to `NoCertVerifier` only for nodes without a stored fingerprint.

**Residual risk:** Pre-v0.9.15 nodes without a stored fingerprint still use `NoCertVerifier` on config push. Re-registration is required for full protection.

---

### SEC-C2 — Relay-propagated ICMP bans and DashMap consistency
**Severity:** MEDIUM  
**Source:** [AI-ADVERSARIAL: Claude Sonnet 4.6]  
**File:** `src/sync.rs:1854`  
**Status:** ✅ Fixed in v0.9.38 (already in code at time of audit)  
**Verification:** Code inspection — relay ban handler at sync.rs:1854 calls both `relay.icmp_stats.ban(ip, BanSource::Relay)` (DashMap) and `ban_cmd_tx.send(IcmpBanCmd::Ban(ipv4))` (XDP fast path).

**Note:** This finding was closed before the Cycle C audit was published. The audit document incorrectly listed it as open.

---

### SEC-C3 — ICMP ban DashMap grows without bound
**Severity:** MEDIUM  
**Source:** [AI-ADVERSARIAL: Claude Sonnet 4.6] confirmed by [AI-ADVERSARIAL: Gemini 2.5 Pro] (as PERF-C3)  
**File:** `src/icmp.rs:66`  
**Status:** ✅ Fixed in v0.9.40  
**Verification:** `IcmpStats::cleanup_expired_bans(ttl_secs)` added; background task spawned at startup runs hourly with a 24-hour TTL. Expired entries are removed from the DashMap and from the XDP fast path via `ban_cmd_tx.send(IcmpBanCmd::Unban)`.

**Description:** `IcmpStats.banned` had no eviction policy. Under sustained ICMP flood from many spoofed IPs, the DashMap grew without bound.

---

### SEC-C4 — BPF icmp_rl_counts map exhaustible via IP spoofing
**Severity:** MEDIUM  
**Source:** [AI-ADVERSARIAL: Gemini 2.5 Pro]  
**File:** `ebpf/dns_xdp.c:110`  
**Status:** ✅ Fixed in v0.9.40  
**Verification:** `icmp_rl_counts` `max_entries` changed from 8192 to 65536, matching `icmp_rate_limit`.

**Description:** With only 8192 entries, an attacker sending ICMP from 8192+ spoofed IPs could exhaust the BPF rate-limit counter map, hiding real attack IPs from the flood detector.

---

### SEC-C5 — HMAC verification uses hand-rolled constant-time comparison
**Severity:** LOW  
**Source:** [AI-ADVERSARIAL: Gemini 2.5 Pro]  
**File:** `src/sync.rs:103`  
**Status:** ⚠️ Accepted risk

**Description:** `hmac_verify_with_ts` uses a manual XOR-fold over a `zip` iterator instead of `subtle::ConstantTimeEq` on the full slice. For SHA256 hex output (always 64 characters), the comparison is effectively constant-time. The final step uses `subtle::ct_eq`.

**Acceptance rationale:** No timing leak on content for equal-length (64-char) inputs. Different-length inputs leak only "not 64 characters" — not a secret. Refactoring to `subtle::ConstantTimeEq` would be cleaner but changes no security property for this use case.

---

### SEC-C6 — ICMP checksum update in eBPF (Disputed)
**Severity:** HIGH (Gemini initial) → 🔄 Disputed  
**Source:** [AI-ADVERSARIAL: Gemini 2.5 Pro] disputed by [AI-ADVERSARIAL: Claude Sonnet 4.6]  
**File:** `ebpf/dns_xdp.c:292`  
**Status:** 🔄 Disputed — not a bug

**Gemini's claim:** `bpf_htons(ICMP_ECHO << 8)` produces `0x0008` on LE, corrupting checksums.

**Dispute:** `csum16_add` operates on host-byte-order values. `icmp->checksum` is read by the LE CPU as `0xCDAB` (when network value is `0xABCD`). Adding `bpf_htons(0x0800) = 0x0008` gives the correct result — the double byte-swap cancels:
```
0xCDAB + 0x0008 = 0xCDB3 → written → packet sees 0xB3CD = 0xABCD + 0x0800 ✓
```

The ICMP responder is disabled by default. A live ping test on x86_64 would confirm.

---

### SEC-C7 — Request body buffered before size check in relay handler
**Severity:** LOW  
**Source:** [AI-ADVERSARIAL: Claude Sonnet 4.6]  
**File:** `src/sync.rs:1567`  
**Status:** ⚠️ Accepted risk

**Description:** `handle_relay_request` buffers the full body before the 65 KB size check. An attacker with `sync_key` could OOM the process with a large chunked body. Requires compromised `sync_key`; relay port is LAN-only.

---

### SEC-C8 — IcmpStats::ban() and XDP enforcement (Disputed)
**Severity:** HIGH (Gemini initial) → 🔄 Disputed  
**Source:** [AI-ADVERSARIAL: Gemini 2.5 Pro] disputed by code analysis  
**File:** `src/icmp.rs:80`  
**Status:** 🔄 Disputed — not a bug

**Gemini's claim:** `IcmpStats::ban()` does not send `IcmpBanCmd::Ban` to `ban_cmd_tx`, leaving bans unenforced in the XDP fast path.

**Dispute:** `ban()` is intentionally a DashMap-only function. All three call sites handle XDP enforcement separately:
- Flood detector (`main.rs:356`): calls `h.icmp_ban_ip(ip_be32)` directly after `ban()`
- API ban handler (`api/mod.rs:5970`): calls `ban_cmd_tx.send(IcmpBanCmd::Ban(ipv4))` after `ban()`
- Relay ban handler (`sync.rs:1854`): calls `ban_cmd_tx.send(IcmpBanCmd::Ban(ipv4))` after `ban()`

The design is consistent: `ban()` updates reporting state; callers own XDP enforcement.

---

### Cycle C Performance Findings

#### PERF-C1 — Hash inconsistency between Rust (CRC32c) and BPF (FNV-1a)
**Impact:** HIGH  
**Source:** [AI-ADVERSARIAL: Gemini 2.5 Pro]  
**File:** `src/dns/hasher.rs` (Rust), `ebpf/dns_xdp.c:166` (BPF)  
**Status:** ⏳ Open

**Description:** The Rust domain hasher (v0.9.39) uses CRC32c SSE4.2, while the BPF XDP hasher uses FNV-1a. The BPF hasher also ASCII-lowercases the QNAME; the Rust implementation does not. These divergences break per-domain CPU affinity (issue #67).

**Fix:** Unify on FNV-1a with consistent ASCII-lowercasing in both layers, or implement CRC32c in BPF via software table.

**Note:** The CRC32c implementation improves `LocalZoneSet` lookup throughput; the inconsistency affects only the XDP domain-routing feature (disabled by default).

#### PERF-C2 — CPUMAP domain-routing limited to 64 cores
**Impact:** LOW  
**Source:** [AI-ADVERSARIAL: Gemini 2.5 Pro]  
**File:** `ebpf/dns_xdp.c:309`  
**Status:** ⚠️ Accepted risk — experimental feature, off by default

---

## Cycle B — v0.9.15

**Date:** 2026-05-25  
**Version audited:** v0.9.14 (fixes applied in v0.9.15)  
**Source:** [AI-ADVERSARIAL: Claude Sonnet 4.6]  
**Scope:** Relay, WebUI, DNS server, alert subsystems.

### Summary Table

| ID | Severity | Status | File | Description |
|----|----------|--------|------|-------------|
| SEC-B1 | CRITICAL | ✅ Fixed v0.9.15 | relay.rs | No cert verification on relay TLS |
| SEC-B2 | HIGH | ✅ Fixed v0.9.15 | sync.rs | SSRF via private relay_host registration |
| SEC-B3 | HIGH | ✅ Fixed v0.9.15 | server.rs | Silent TSIG base64 drop (WARN→ERROR) |
| SEC-B4 | HIGH | ❌ Not a vuln | api/mod.rs | Cache flush race — Mutex, not atomic |
| SEC-B5 | HIGH | ✅ Fixed v0.9.15 | webui/mod.rs | Login rate limit concurrent bypass |
| SEC-B6 | HIGH | ⚠️ Accepted | axfr.rs | No per-zone AXFR ACL (global allow-list) |
| SEC-B7 | MEDIUM | ✅ Fixed v0.9.40 | alerts.rs | Alert blocks not persisted across restarts |
| SEC-B8 | MEDIUM | ⚠️ Accepted | sync.rs | relay_host parsing edge cases (quality) |
| SEC-B9 | MEDIUM | ✅ Fixed v0.9.15 | server.rs | TSIG algorithm mismatch log level |
| SEC-B10 | MEDIUM | ✅ Fixed v0.9.39 | webui/mod.rs | Session DashMap unbounded growth |
| SEC-B11 | MEDIUM | ⚠️ Accepted | parser.rs | Zone limit per-reload (root required to modify config) |
| SEC-B12 | MEDIUM | 🔄 Disputed | sync.rs | HMAC ±30s replay window — not a vuln |
| SEC-B13 | MEDIUM | ⏳ Open | relay.rs | SNI hardcoded; fix requires full fleet re-registration |
| SEC-B14 | MEDIUM | ✅ Fixed v0.9.15 | webui/mod.rs | CSRF bypass on proxied API endpoints |
| SEC-B15 | LOW | ⚠️ Accepted | sync.rs | /proc/meminfo not bounds-checked (reporting only) |
| SEC-B16 | LOW | ✅ Fixed v0.9.39 | api/mod.rs | Unicode bidi control characters in log fields |
| SEC-B17 | LOW | ✅ Fixed v0.9.15 | api/mod.rs | Lock poisoning → process crash |

### Key Cycle B Findings (detail)

**SEC-B1 (CRITICAL, Fixed):** `relay_tls_config()` used `NoCertVerifier` despite a working TOFU cert-pinning implementation (`PinnedCertVerifier`) already present in `sync.rs`. Fixed in v0.9.15 for `relay_forward_handler`; residual regression in `push_to_slaves` fixed in v0.9.40 (SEC-C1).

**SEC-B7 (MEDIUM, Fixed v0.9.40):** Alert-triggered blocks were stored only in memory. On restart, all blocks (including permanent ones) were cleared silently. Fixed: `AlertTracker` now persists the block set to `{base_dir}/alert-blocks.json` on every block/unblock event. Blocks are loaded on startup; expired entries are skipped.

**SEC-B13 (MEDIUM, Open):** SNI hardcoded to `"runbound-relay"`. With cert pinning now enforced (SEC-B1/SEC-C1 fixed), the SNI is no longer the trust anchor for pinned nodes. Remaining risk is limited to pre-registration nodes. Full fix requires removing `NoCertVerifier` fallback after all nodes are re-registered with v0.9.15+.

---

## Cycle A — v0.9.10

**Date:** 2026-05-25  
**Source:** [AI-INTERNAL: Claude Sonnet 4.6]  
**Scope:** WebUI authentication, relay security, ACL, feed SSRF, dependency chain.

### Summary Table

| ID | Severity | Status | Description |
|----|----------|--------|-------------|
| SEC-A1 | MEDIUM | ✅ Fixed v0.9.11 | No brute-force protection on WebUI login |
| SEC-A2 | LOW | ✅ Fixed v0.9.11 | Session cookies missing Secure flag |
| SEC-A3 | LOW | ✅ Fixed v0.9.11 | Minimum password 4 characters (raised to 12) |
| SEC-A4 | INFO | ⚠️ Accepted | CSRF token non-constant-time comparison (negligible) |
| SEC-A5 | INFO | ✅ Fixed v0.9.11 | IPv6 link-local not blocked in relay_host validation |
| SEC-A6 | INFO | ⚠️ Accepted | Unmaintained crate advisories (no active CVEs) |

Verified fixed from earlier cycles: SEC-2026-05-24-03 through SEC-2026-05-24-06 (SSRF variants, ACL bypass, relay_host attacks).

---

## Pre-Release Audits (v0.4.5 → v0.9.4)

The following audits were conducted before the named-cycle system was established. All findings are closed.

| File | Version | Type | Findings | Status |
|------|---------|------|---------|--------|
| v0.4.5-code-audit.md | v0.4.5 | AI-INTERNAL | 12 quality, 5 perf | All addressed |
| v0.5.4-benchmark.md | v0.5.4 | AI-INTERNAL | Performance baseline | Reference only |
| v0.6.9-audit.md | v0.6.9 | AI-INTERNAL | 11 security, 10 perf | All fixed (v0.7.0–v0.8.2) |
| v0.6.9-pentest.md | v0.6.9 | AI-INTERNAL | SEC-11 (SSRF 0.0.0.0) | Fixed v0.6.11 |
| v0.8.1-phase2.md | v0.8.1 | AI-INTERNAL | 4 security | All fixed v0.8.2 |
| v0.8.1-reaudit.md | v0.8.1 | AI-ADVERSARIAL | 1 residual SSRF | Fixed v0.8.2 |
| v0.9.1-icmp-webui.md | v0.9.1 | AI-INTERNAL | 7 (ICMP + WebUI) | All fixed or accepted |
| v0.9.3-gemini.md | v0.9.3 | AI-ADVERSARIAL (Gemini 2.5 Pro) | 4 new | All fixed v0.9.4 |
| v0.9.3-prerelease.md | v0.9.3 | AI-INTERNAL | 8 | All fixed or deferred |
| v0.9.4-remediation.md | v0.9.4 | Tracking | Remediation status | Complete |

Notable pre-release findings now closed:
- **SEC-AGV-01 (HIGH)**: DDNS could overwrite static zones — fixed in v0.9.4 with static zone protection
- **CSRF (HIGH)**: WebUI form submissions — fixed with double-submit cookie pattern
- **Stale cache OOM**: LRU eviction added
- **DNSSEC oscillation**: Hysteresis timer added

---

## Performance Finding Registry

### Open

| ID | Impact | Cycle | File | Description |
|----|--------|-------|------|-------------|
| PERF-C1 | HIGH | C | hasher.rs / dns_xdp.c | Hash inconsistency Rust CRC32c vs BPF FNV-1a |
| PERF-2 | HIGH | B | dns/ratelimit.rs | Rate limiter double DashMap lookup (mitigated for known IPs by PERF-5) |
| PERF-4 | HIGH | B | api/mod.rs | Atomic hotspot on per-domain stats counter |
| PERF-6 | MEDIUM | B | api/mod.rs | QPS percentile recalculation on every /api/stats call |
| PERF-7 | MEDIUM | B | dns/cache_snapshot.rs | Blocking cache serialization on shutdown — no timeout |
| PERF-8 | MEDIUM | B | dns/server.rs | String allocation inside log callsites |
| PERF-C2 | LOW | C | dns_xdp.c | CPUMAP routing limited to 64 cores (experimental feature, off by default) |

### Fixed

| ID | Impact | Fix version | Description |
|----|--------|------------|-------------|
| PERF-1 | HIGH | v0.9.17 | Full DashMap clone every 10ms — CACHE_WRITE_GEN generation counter |
| PERF-3 | HIGH | v0.9.x | jemalloc global allocator |
| PERF-5 | HIGH | v0.9.x | Thread-local rate-limit shadow cache (10ms/100ms TTL) |

---

## Known Limitations and Accepted Risks

1. **No live network testing.** TLS interception (SEC-C1, SEC-B1), ICMP responses (SEC-C6 dispute), and HMAC timing (SEC-C5) were evaluated by code review only. A live mitmproxy test on the master-slave segment is recommended before any production relay deployment.

2. **No fuzzing.** DNS wire format parsing, config parser, and relay handler deserialization have not been fuzz-tested.

3. **No dependency audit in recent cycles.** `cargo audit` was last run in Cycle A. SEC-A6 (unmaintained crates, no CVEs) remains accepted but has not been re-evaluated since v0.9.10.

4. **eBPF/XDP fast path partial coverage.** `ebpf/dns_xdp.c` was reviewed for correctness in Cycles B and C. BPF verifier safety, BTF compatibility, and map exhaustion scenarios beyond ICMP were not systematically analyzed.

5. **Pre-v0.9.15 relay nodes.** Nodes registered before v0.9.15 have no stored `cert_fingerprint` and continue to use `NoCertVerifier` on relay connections. Re-registration is required to activate full cert-pinning protection (SEC-B1, SEC-C1).

6. **Alert block persistence is best-effort.** `alert-blocks.json` is written synchronously on block/unblock events. A crash between the block decision and the file write would lose the block. This is an acceptable trade-off for a periodic-persistence design.

7. **ICMP ban TTL is not configurable.** The 24-hour TTL for ICMP ban cleanup (SEC-C3 fix) is hardcoded. Environments with persistent attackers may want a longer TTL; environments with high false-positive rates may want shorter. Future: add `icmp-ban-ttl` config option.

8. **All findings are AI-reviewed.** No external human security review has been conducted. Source labels `[AI-INTERNAL]` and `[AI-ADVERSARIAL]` are used consistently throughout, per R1. These audits do not substitute for professional penetration testing.

---

## Methodology Notes

**Source labels** (per R1):
- `[AI-INTERNAL]` — same model that produced the code; limited adversarial independence
- `[AI-ADVERSARIAL]` — separate session or different model; stronger independence  
- `[AI-ADVERSARIAL: Gemini 2.5 Pro]` — different model family; satisfies R10 for re-audit
- `[AUTOMATED-TOOL: cargo-audit 0.21.x]` — automated dependency scanner

**Severity calibration** (per R2):
- CRITICAL — exploitable without auth, or bypass of a documented guarantee
- HIGH — exploitable with auth, silent data corruption, or practical single-source DoS
- MEDIUM — reduces defense-in-depth; preconditions required
- LOW — best-practice deviation; no direct exploit path
- INFO — architectural observation

**R10 (re-audit independence):** Cycle B fixes were re-evaluated by Gemini 2.5 Pro (different model) in Cycle C. Cycle C fixes (v0.9.40) have not yet been independently re-audited. Re-audit should use a different model or human reviewer before next release.
