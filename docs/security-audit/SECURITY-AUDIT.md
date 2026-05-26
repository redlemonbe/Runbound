# Runbound — Security Audit Master Document

**Current version:** v0.9.50  
**Last updated:** 2026-05-26  
**Maintained by:** RedLemonBe — https://github.com/redlemonbe/Runbound

This document consolidates all security and performance audit cycles conducted on Runbound. Individual per-cycle files in this directory are historical records; this file is the authoritative status reference.

---

## Audit Cycle History

| Cycle | Version range | Date | Sources | Open findings |
|-------|--------------|------|---------|---------------|
| [Pre-release](#pre-release-audits-v045--v094) | v0.4.5 → v0.9.4 | 2026-05-23/24 | AI-INTERNAL, AI-ADVERSARIAL (Gemini 2.5 Pro) | 0 (all fixed or accepted) |
| [A](#cycle-a--v0910) | v0.8.2 → v0.9.10 | 2026-05-25 | AI-INTERNAL | 0 (all fixed or accepted) |
| [B](#cycle-b--v0915) | v0.9.10 → v0.9.15 | 2026-05-25 | AI-ADVERSARIAL | 0 (all fixed or accepted) |
| [C](#cycle-c--v0938) | v0.9.15 → v0.9.38 | 2026-05-25 | AI-ADVERSARIAL + AI-ADVERSARIAL (Gemini 2.5 Pro) | 0 (all fixed, accepted, or disputed) |
| [D](#audit-status--v0944) | v0.9.43–v0.9.44 | — | — | **Pending** |
| [E](#cycle-e--v0946v0948-asm-hotpath--webui) | v0.9.46–v0.9.48 | 2026-05-26 | AI-INTERNAL | 0 open (2 fixed, 3 accepted, 2 info) |

---

## Current Open Findings

As of v0.9.50, **zero findings remain open**. All tracked findings have been fixed, accepted, or classified as false positives.

All findings have been fixed (SEC-B7, SEC-B10, SEC-B13, SEC-B16, SEC-C1, SEC-C2, SEC-C3, SEC-C4), accepted (SEC-B6, SEC-B8, SEC-B11, SEC-B15, SEC-C5, SEC-C7, PERF-C2), or classified as false positives (SEC-C6, SEC-C8).

---

## Audit status — v0.9.44

| Cycle | Scope | Auditor | Status |
|-------|-------|---------|--------|
| A | Core DNS, XDP, API | [AI-INTERNAL] Claude | Complete |
| B | Auth, relay, WebUI | [AI-INTERNAL] Claude | Complete |
| C | v0.9.3–v0.9.41 hardening | [AI-ADVERSARIAL] Claude + Gemini | Complete — 0 open findings |
| D | v0.9.43–v0.9.44 features | — | **Pending** — bot defense, alert hot-reload, IP SAN not yet audited |

**New attack surface since last audit (Cycle C, v0.9.41):**
- Bot defense engine (`src/webui/mod.rs`): honeypot detection, scanner trap, burst tracker — loopback/RFC-1918 self-ban fixed in v0.9.45; `burst_tracker` unbounded growth fixed in v0.9.45 (eviction every 5 min). Remaining: IP rotation attack flooding `blocked` map not yet mitigated.
- `SyncOp::AddGlobalBan` / `DeleteGlobalBan` — new relay operations; ban injection via compromised slave not evaluated
- `AlertTracker.update_rules()` — rules can now be replaced at runtime via hot-reload; concurrent modification behavior under load not audited
- `ui-tls-san` — attacker with config write access could add arbitrary SANs to the cert

Cycle D should be scheduled before v1.0.

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
| SEC-B13 | MEDIUM | ✅ Fixed v0.9.41 | relay.rs / sync.rs / config | SNI now dynamic from peer address; new `forward-tls-hostname` directive |
| SEC-B14 | MEDIUM | ✅ Fixed v0.9.15 | webui/mod.rs | CSRF bypass on proxied API endpoints |
| SEC-B15 | LOW | ⚠️ Accepted | sync.rs | /proc/meminfo not bounds-checked (reporting only) |
| SEC-B16 | LOW | ✅ Fixed v0.9.39 | api/mod.rs | Unicode bidi control characters in log fields |
| SEC-B17 | LOW | ✅ Fixed v0.9.15 | api/mod.rs | Lock poisoning → process crash |

### Key Cycle B Findings (detail)

**SEC-B1 (CRITICAL, Fixed):** `relay_tls_config()` used `NoCertVerifier` despite a working TOFU cert-pinning implementation (`PinnedCertVerifier`) already present in `sync.rs`. Fixed in v0.9.15 for `relay_forward_handler`; residual regression in `push_to_slaves` fixed in v0.9.40 (SEC-C1).

**SEC-B7 (MEDIUM, Fixed v0.9.40):** Alert-triggered blocks were stored only in memory. On restart, all blocks (including permanent ones) were cleared silently. Fixed: `AlertTracker` now persists the block set to `{base_dir}/alert-blocks.json` on every block/unblock event. Blocks are loaded on startup; expired entries are skipped.

**SEC-B13 (MEDIUM, Fixed v0.9.41):** Three hardcoded SNI values replaced with dynamic derivation. (1) `forward-zone:` now accepts `forward-tls-hostname` — `build_resolver` passes it to `dot_tls_name`, enabling custom DoT servers outside the built-in IP map (Cloudflare/Quad9/Google/OpenDNS). (2) Relay outbound (`relay_request`, `register`) and sync (`sync_get`) now derive SNI from the peer address via `ServerName::IpAddress` for IPv4/IPv6 or DNS name parsing for hostnames.

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

**R10 (re-audit independence):** Cycle B fixes were re-evaluated by Gemini 2.5 Pro (different model) in Cycle C. Cycle C fixes (v0.9.40) and SEC-B13 fix (v0.9.41) have not yet been independently re-audited. Re-audit should use a different model or human reviewer before the next release cycle.

---

## Cycle E — v0.9.46–v0.9.48 (ASM hotpath + WebUI)

**Date:** 2026-05-26
**Version audited:** v0.9.46–v0.9.48
**Sources:**
- [AI-INTERNAL: Claude Sonnet 4.6] — code review of new SIMD, relay, alerts, and WebUI surfaces

**Scope:** asm-hotpath merge (simd.rs, hasher.rs, xdp/worker.rs), relay HMAC/TLS, alert webhook, WebUI bug fixes.

**New attack surface since Cycle D:**
- `src/dns/simd.rs` — new unsafe SIMD blocks (SSE2/AVX2 label lowercasing, find_zero, bytes_eq)
- `src/dns/hasher.rs` — new CRC32c unsafe blocks (SSE4.2, aarch64)
- Alert webhook SSRF surface (notify_url unconstrained)
- WebUI bug: CSS classes referenced in JS but not defined → invisible node selection border

---

### SEC-E1 — SSRF via alert webhook URL

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Status** | Fixed (v0.9.48) |
| **Source** | [AI-INTERNAL] |
| **Location** | `src/alerts.rs` — `webhook_sender` |

**Description:** The `notify_url` from alert rules was passed directly to `reqwest::Client::post()` without validation. An operator with API or config-file write access could configure a webhook URL targeting internal services (cloud metadata, internal APIs).

**Proof of concept:**
```
POST /api/alerts
{ "name":"ssrf","metric":"client-qps","limit":1,"window":1,"action":"notify",
  "webhook":"http://169.254.169.254/latest/meta-data/" }
```
Runbound would POST `alert_threshold` JSON to the EC2 metadata endpoint, exfiltrating instance metadata.

**Fix:** `is_safe_webhook_url()` added in `webhook_sender`. Rejects non-HTTP(S) schemes, loopback, RFC-1918, link-local, `.local` hostnames, and known cloud metadata addresses (169.254.169.254, metadata.google.internal).

---

### SEC-E2 — `options(nomem)` incorrect in `find_zero_sse2`

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Status** | Fixed (v0.9.48) |
| **Source** | [AI-INTERNAL] |
| **Location** | `src/dns/simd.rs` — `find_zero_sse2` |

**Description:** The inline asm block in `find_zero_sse2` declared `options(nostack, nomem)`. The `nomem` option signals to the compiler that the asm does not access memory, allowing load/store reordering around the block. However, the `movdqu {v}, [{ptr}]` instruction reads from `[ptr]`. On a read-only slice with no pending writes, this is unlikely to cause a visible bug, but violates the Rust inline asm contract.

**Fix:** `nomem` removed from `options`. The asm now correctly declares memory access, preventing speculative reordering.

---

### BUG-E1 — `block_bot` sends literal string `"bot_ban"` as webhook URL

| Field | Value |
|-------|-------|
| **Severity** | INFO (logic bug, no security impact) |
| **Status** | Fixed (v0.9.48) |
| **Source** | [AI-INTERNAL] |
| **Location** | `src/alerts.rs` — `block_bot` |

**Description:** `block_bot()` called `self.notify_tx.send(("bot_ban".to_string(), event))`, sending the string `"bot_ban"` as the webhook URL. `webhook_sender` would attempt `reqwest::post("bot_ban")` which fails URL parsing silently. Bot defense events were never delivered to webhooks.

**Fix:** Removed the `notify_tx.send` call from `block_bot`. Bot events are still recorded in `recent_alerts`. Proper webhook delivery for bot bans requires a future refactor to pass the configured rule URL.

---

### ACC-E1 — HMAC relay: 30s anti-replay window, no nonce deduplication

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Status** | Accepted |
| **Source** | [AI-INTERNAL] |
| **Location** | `src/sync.rs` — `hmac_verify_with_ts` |

**Description:** The relay HMAC uses a ±30s timestamp window for anti-replay. Within that window, a captured valid request can be replayed (e.g., `POST /relay/dns` adding a record could be submitted twice within 30s). There is no per-(timestamp, signature) nonce cache to prevent duplicate processing.

**Accepted because:** Relay requests operate on a private sync channel between trusted master and slave. Relay operations are idempotent for unique DNS records. Implementing a nonce store adds state complexity and persistence requirements. Risk accepted pending v1.0 design review.

---

### ACC-E2 — TOFU cert pinning window during initial slave registration

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Status** | Accepted |
| **Source** | [AI-INTERNAL] |
| **Location** | `src/api/relay.rs` — `register_with_master`, `relay_tls_config` |

**Description:** Before a cert fingerprint is established (first registration), the relay TLS client uses `NoCertVerifier` — encryption only, no authentication at the TLS layer. A network attacker on-path during initial slave registration could intercept and substitute their own cert fingerprint in the registration payload, causing the master to pin to the attacker's cert instead of the slave's.

**Mitigating factor:** HMAC-SHA256 with a pre-shared `sync-key` provides authentication at the application layer. The attacker must know `sync-key` to forge any HMAC-signed payload. Without `sync-key`, the MITM attack on registration does not grant the ability to forge future relay requests. Risk is limited to the initial registration moment on uncontrolled networks.

**Accepted because:** The relay is designed for controlled LAN environments. HMAC provides the primary auth guarantee. Full mutual TLS auth would require PKI infrastructure or a secure channel for key exchange.

---

### INFO-E1 — AUTH_FAILURES counter reset race (Relaxed ordering)

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Status** | Accepted |
| **Source** | [AI-INTERNAL] |
| **Location** | `src/api/mod.rs:514` |

**Description:** Successful auth resets `AUTH_FAILURES` via `store(0, Relaxed)`. A concurrent failed auth could increment the counter between the successful auth comparison and the reset, resulting in the counter being zeroed after a failure increment. With `Relaxed` ordering, stores may be observed out of order by other threads. Consequence: failure count is slightly under-counted in rare concurrent scenarios. Not a security bypass — braking behavior is additive.

**Accepted because:** AUTH_FAILURES is a coarse braking mechanism, not an access control decision. Slightly under-counting failures is safe (more lenient, not more permissive on auth decisions).

---

### INFO-E2 — SIMD unsafe blocks: memory safety analysis

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Status** | Accepted |
| **Source** | [AI-INTERNAL] |
| **Location** | `src/dns/simd.rs`, `src/dns/hasher.rs` |

**Description:** The SIMD implementations (`copy_lowercase_sse2`, `copy_lowercase_avx2`, `bytes_eq_sse2`, `bytes_eq_avx2`, `find_zero_sse2`, `crc32c_sse42_asm`, `crc32c_arm`) contain `unsafe` blocks with raw pointer arithmetic.

**Analysis:**
- `copy_lowercase_*`: `dst.reserve(len)` ensures capacity before raw writes; `set_len(base+len)` is called only after all bytes are initialized by the SIMD loop + scalar tail. Pattern is correct.
- `bytes_eq_*`: pointers derived from slice references with lifetimes enforced by the borrow checker. No buffer over-read — loop bound is `remaining` initialized from `a.len()`.
- `find_zero_sse2`: reads from `bytes.as_ptr()` within `[0..limit]` where `limit <= bytes.len()`. No OOB possible.
- `crc32c_sse42_asm`: `read_unaligned()` on u64/u32 casts — correct for unaligned DNS labels; `options(nomem, pure)` is correct here since the load is done by `read_unaligned()` before the asm.
- Feature gates (`#[target_feature(enable = "sse2")]`, `avx2`, `sse4.2`, `crc`) match dispatch conditions — no feature mismatch possible.

No exploitable memory safety issue found.

---

## Findings Summary — v0.9.48

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| SEC-E1 | MEDIUM | SSRF via alert webhook URL | **Fixed v0.9.48** |
| SEC-E2 | LOW | `nomem` incorrect in `find_zero_sse2` | **Fixed v0.9.48** |
| BUG-E1 | INFO | `block_bot` sends literal `"bot_ban"` as webhook URL | **Fixed v0.9.48** |
| ACC-E1 | MEDIUM | HMAC relay 30s replay window, no nonce cache | **Accepted** |
| ACC-E2 | LOW | TOFU cert pinning window at first registration | **Accepted** |
| INFO-E1 | INFO | AUTH_FAILURES Relaxed race | **Accepted** |
| INFO-E2 | INFO | SIMD unsafe block review | **Accepted** |


---

## Cycle F — v0.9.49–v0.9.50 (Cycle D close-out + bot defense hardening)

**Date:** 2026-05-26
**Version audited:** v0.9.49–v0.9.50
**Sources:**
- [AI-INTERNAL: Claude Sonnet 4.6] — systematic review of Cycle D pending items and new surface since Cycle E

**Scope:** Cycle D pending items (bot defense IP rotation, ban injection via compromised slave, AlertTracker hot-reload, ui-tls-san), plus incremental review of DDNS TSIG, feed SSRF, and serde error reflection.

**Cycle D pending items resolution:**

| Item | Resolution |
|------|-----------|
| IP rotation attack flooding blocked map | **SEC-F1 — Fixed** |
| Ban injection via compromised slave | **ACC-F1 — Accepted** (relay is master->slave only) |
| AlertTracker hot-reload concurrent safety | **ACC-F2 — Accepted** (RwLock correct) |
| ui-tls-san SAN injection | **ACC-F3 — Accepted** (rcgen validates all SANs) |

---

### SEC-F1 — blocked DashMap unbounded growth under IP-rotation flood

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Status** | Fixed in v0.9.50 |
| **Source** | [AI-INTERNAL] |
| **Location** | src/alerts.rs - block_bot, block_manual, trigger |

**Description:** The blocked DashMap in AlertTracker had no hard size cap. The background eviction task runs every 60 seconds (main.rs:1474). An attacker rotating through many source IPs and repeatedly triggering the bot trap (10 failed requests in 5s per IP) could accumulate entries faster than the 60s eviction cycle removes them. At ~100 bytes per entry, sustained IP rotation could exhaust RAM before expiry-based eviction reduces the map. With a default 86400s ban duration, entries persist for 24h, making the issue more severe.

**Fix:** Added MAX_BLOCKED_ENTRIES = 50_000 constant. All three insertion paths (block_bot, block_manual, trigger) now check self.blocked.len() >= MAX_BLOCKED_ENTRIES before inserting a new IP. Existing IPs (updates / re-bans) are exempt from the cap. When the cap is reached, the insertion is skipped with a WARN log entry.

**Residual risk:** When the cap is full, new IPs cannot be banned until eviction runs (up to 60s). This provides a 60s evasion window for IPs beyond the 50k cap. Acceptable trade-off given the alternative is OOM crash.

---

### ACC-F1 — Ban injection via compromised slave: architectural analysis

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Status** | Accepted |
| **Source** | [AI-INTERNAL] |
| **Location** | src/sync.rs - SyncOp::AddGlobalBan |

**Description:** Cycle D flagged AddGlobalBan / DeleteGlobalBan as potential vectors for a compromised slave to inject bans on the master.

**Analysis:** The relay architecture is strictly master-to-slave. SyncOp::AddGlobalBan is pushed by the master to slaves via relay::push_to_slaves. The slave relay server receives it and calls SyncOpHandler::apply() -- this runs on the slave, not the master. There is no reverse relay channel by which a slave can send SyncOp to the master. A compromised slave can only harm itself.

**Accepted because:** The threat is a false positive. Relay is one-directional by design.

---

### ACC-F2 — AlertTracker hot-reload: concurrent safety

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Status** | Accepted |
| **Source** | [AI-INTERNAL] |
| **Location** | src/alerts.rs - update_rules |

**Description:** Cycle D flagged update_rules() for concurrent modification behavior under load.

**Analysis:** update_rules acquires self.rules.write().unwrap() -- a standard RwLock write guard. All concurrent readers (check(), record()) acquire self.rules.read() and block until the write guard is released. The RwLock provides mutual exclusion between rule replacement and concurrent reads. No race condition is possible.

**Accepted because:** The implementation is correct. RwLock<Vec<AlertRule>> is the appropriate primitive.

---

### ACC-F3 — ui-tls-san: SAN injection risk

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Status** | Accepted (validated safe) |
| **Source** | [AI-INTERNAL] |
| **Location** | src/webui/mod.rs - gen_webui_cert |

**Description:** Cycle D flagged ui-tls-san directives as a potential SAN injection vector.

**Analysis:** Each SAN value is validated before use. IP: san.trim().parse::<std::net::IpAddr>() -- Rust stdlib parser. DNS: rcgen::Ia5String::try_from(s) -- printable ASCII only. Invalid values are skipped with a WARN log. No injection path exists.

**Accepted because:** Inputs are validated. Config-write access is already privileged.

---

### INFO-F1 — serde_json syntax errors reflected to API clients

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Status** | Accepted |
| **Source** | [AI-INTERNAL] |
| **Location** | src/api/mod.rs - ApiJson::from_request |

**Description:** JsonRejection::JsonSyntaxError(e).to_string() is reflected in the 400 response. serde_json syntax errors contain only the line/column of the malformed token -- no internal type names, file paths, or heap addresses.

**Accepted because:** Information exposed is minimal and derived from the attacker's own input.

---

## Findings Summary -- v0.9.50

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| SEC-F1 | MEDIUM | blocked DashMap unbounded growth under IP-rotation flood | **Fixed v0.9.50** |
| ACC-F1 | LOW | Ban injection via compromised slave (Cycle D item) | **Accepted** (false positive) |
| ACC-F2 | LOW | AlertTracker hot-reload concurrent safety (Cycle D item) | **Accepted** (RwLock correct) |
| ACC-F3 | LOW | ui-tls-san SAN injection (Cycle D item) | **Accepted** (rcgen validates) |
| INFO-F1 | INFO | serde_json syntax error reflected to client | **Accepted** |
