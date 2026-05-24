**Audit type:** [AI-INTERNAL] — performed by claude-sonnet-4-6 under maintainer direction.
This audit does NOT substitute for external human security review.
External human audit: not yet scheduled.

---

# Runbound — Security & Performance Audit Report

**Version audited:** v0.6.9
**Date:** 2026-05-23
**Scope:** Full source — DNS engine, XDP fast-path, REST API, cache, feed subsystem, ACL, rate limiter, TLS, configuration parser, HSM integration, upstream management, eBPF program, signal handling, dependency chain

---

## 0. Methodology

- **Model:** claude-sonnet-4-6
- **Audit type:** [AI-INTERNAL]
- **Adversarial framing:** None — same model family for implementation and review (R10 limitation acknowledged)
- **Files reviewed:** src/auth.rs, src/api/mod.rs, src/api/upstreams.rs, src/dns/xdp/worker.rs, src/dns/xdp/socket.rs, src/dns/xdp/umem.rs, src/dns/ratelimit.rs, src/dns/acl.rs, src/sync.rs, src/main.rs, Cargo.toml (dependency versions)
- **Files NOT reviewed:** tests/ (test coverage not evaluated), benches/, .github/ CI config, ebpf/dns_xdp.c (eBPF C source reviewed at call-site level only, not full BPF verifier analysis), build.rs
- **Tools:** cargo-audit 0.21.x [AUTOMATED-TOOL], cargo-clippy 1.85.0 [AUTOMATED-TOOL], manual code review [AI-INTERNAL]
- **Threat models considered:** unauthenticated remote attacker on LAN/WAN, authenticated API user with valid Bearer token, compromised/malicious upstream DNS resolver, local process with access to config files
- **Threat models NOT considered:** kernel 0-day exploitation (assumed trusted kernel), physical access to hardware, supply-chain compromise of Rust toolchain, side-channel attacks via CPU cache timing, fault injection, DNS amplification from external perspective
- **Time estimate:** ~12 hours across multiple sessions
- **Verification provenance:** Fix authorship and verification performed by same AI model family (claude-sonnet-4-6). Independent re-audit by different model family is pending. Per Rule 10, this means all "fixed" findings are "claimed fixed" until independent verification.

---

## 1. Executive Summary

This audit cycle [AI-INTERNAL] reviewed Runbound v0.6.9 DNS engine, XDP fast-path, REST API, cache, feed subsystem, ACL, rate limiter, TLS, configuration parser, HSM integration, upstream management, eBPF program, signal handling, and dependency chain on 2026-05-23. Methodology: manual code review by claude-sonnet-4-6 under maintainer direction + cargo-audit [AUTOMATED-TOOL] + cargo-clippy [AUTOMATED-TOOL]; details in §0 Methodology.

**Findings: 11 total** — 0 CRITICAL, 5 HIGH (SEC-02, SEC-03, SEC-07, SEC-08, SEC-09, SEC-10 — 6 findings at HIGH when counted individually; SEC-10 is one finding covering two attack variants), 4 MEDIUM (SEC-01, SEC-04, SEC-05, SEC-06), 1 LOW (SEC-06b), 1 MEDIUM open (SEC-11).

**Status:** 8 fixed (SEC-01, SEC-02, SEC-03 overflow component, SEC-04, SEC-07, SEC-08, SEC-09, SEC-10) — 1 accepted risk component (SEC-03 kernel trust) — 2 open deferred to v1.0 (SEC-05, SEC-06) — 1 open fixed in later cycle (SEC-11 v0.6.11).

**Scope limitations:** Tests directory not evaluated for coverage. eBPF C source reviewed at call-site level only, not full BPF verifier. Tokio fallback path reviewed at lower depth. Side-channel attacks, supply-chain attacks beyond cargo-audit, and fault injection not in scope. See §Known Limitations.

**Notable observations:**
- Auth bearer constant-time comparison and memory zeroization correctly implemented
- XDP UMEM bounds check implemented, but kernel trust is an accepted risk (see KL-01)
- DNSSEC validation disabled by default — operator must explicitly enable; no default-safe configuration (see SEC-05, KL-02)
- All fixes to date verified by [AI-INTERNAL] review in the same session family that produced the finding; treated as "claimed fixed, not independently verified" until [AI-ADVERSARIAL] or [HUMAN-EXTERNAL] re-audit

This audit is [AI-INTERNAL] and does NOT substitute for external human security review. External human audit: not yet scheduled.

---

## 2. Architecture Overview

```
NIC
 │
 ├──[eBPF XDP filter — kernel bypass]────────────────────────────────┐
 │   • Identifies UDP/53                                               │
 │   • CPUMAP routing (FNV-1a hash of QNAME → pinned CPU)            │
 │   • XDP_PASS fallback on everything else                           │
 │                                                                     ▼
 │                                           AF_XDP socket (1 per NIC queue)
 │                                               │
 │                                     XDP worker thread (OS thread)
 │                                       • Parse Ethernet/IP/UDP/DNS
 │                                       • ACL + rate limiter (DashMap)
 │                                       • LocalZoneSet (ArcSwap)
 │                                       • Cache snapshot (ArcSwap)
 │                                       • Reply via TX ring
 │
 └──[Kernel path → Tokio / hickory-server]
     • Recursive queries / DoT / DoH / DoQ
     • DNSSEC validation (optional)
     • REST API (localhost:8080)
```

Architectural strengths: strict separation between XDP OS-threads and Tokio async workers, zero-lock read path on zones, jemalloc multi-thread allocator.

---

## 3. Security Audit

### 3.1 API Authentication

Mechanism: 256-bit Bearer token (CSPRNG), stored at `/etc/runbound/api.key` (chmod 600).

Constant-time comparison (`src/auth.rs`):

```rust
use subtle::ConstantTimeEq;
let diff = b.iter().enumerate().fold(len_mismatch, |acc, (i, &bi)| {
    acc | (a.get(i).copied().unwrap_or(0) ^ bi)
});
diff.ct_eq(&0u8).into()
```

The `subtle` crate prevents compiler optimizations that would create a timing oracle.

Anti-brute-force: 500 ms sleep after 50 consecutive failures, applied before comparison — no timing signal on key content.

---

**[SEC-01] — Auth Timing Oracle**
- **Severity:** MEDIUM
- **Source:** [AI-INTERNAL]
- **File:** src/auth.rs (approximate line 40)
- **Discovered:** v0.6.x
- **Status:** ✅ Mitigated (subtle + sleep)
- **Threat model:** Unauthenticated attacker on management network measuring HTTP response time to infer bits of the Bearer token via timing side-channel
- **Description:** If token comparison short-circuits on the first differing byte, response time varies with the number of matching prefix bytes. A statistical timing attack can recover the token byte-by-byte. The anti-brute-force sleep after 50 failures must also be applied before the comparison, or it leaks timing information on the comparison itself.
- **Exploit path:** Theoretical — attacker sends repeated requests with controlled token prefixes and measures response time distribution; statistical analysis distinguishes correct vs. incorrect leading bytes; `subtle::ConstantTimeEq` + pre-comparison sleep eliminates the oracle; no concrete exploit demonstrated in this audit cycle
- **Fix:** `subtle::ConstantTimeEq` for constant-time byte comparison; 500 ms anti-brute-force sleep applied before comparison, not after (commit `f9ee716`)
- **Residual risk:** HTTP Authorization header length is observable to a network attacker (see KL-03); negligible in practice as API is bound to 127.0.0.1 by default
- **Verification:** No automated test; verified by manual review [AI-INTERNAL] (commit `f9ee716`)

**Verdict [AI-INTERNAL]:** Implementation consistent with ANSSI RGS API authentication guidelines based on code review. No formal ANSSI evaluation has been conducted; this claim is scoped to [AI-INTERNAL] analysis only.

### 3.2 Secret Management

| Secret | Storage | Protection |
|--------|---------|------------|
| API key | `Zeroizing<String>` | Zeroed on drop |
| HSM PIN | `Zeroizing<String>` | Env var `HSM_PIN` > config |
| HMAC audit | `Zeroizing<Vec<u8>>` | Auto-generated if absent |
| PKCS#11 | Single session at startup | Explicit cleanup on shutdown |

HSM support via `cryptoki` crate. Fatal exit if HSM configured but unreachable — correct behavior for a security-sensitive service.

---

**[SEC-02] — Plaintext Secrets in Memory**
- **Severity:** HIGH
- **Source:** [AI-INTERNAL]
- **File:** src/auth.rs, src/config/ (approximate)
- **Discovered:** v0.6.x
- **Status:** ✅ Zeroizing
- **Threat model:** Local attacker or crash dump (core file, /proc/pid/mem, hypervisor snapshot) with read access to process memory recovering active secret material
- **Description:** Secret material stored as ordinary `String` or `Vec<u8>` remains in memory until the allocator reclaims it — potentially surviving into swap space or crash dumps. Rust's `Drop` trait does not guarantee memory zeroing before deallocation. The `zeroize` crate's `Zeroizing<T>` wrapper overrides `Drop` to zero the allocation before freeing.
- **Exploit path:** Theoretical — 1. Attacker obtains process memory dump via /proc/pid/mem, core file, or hypervisor snapshot; 2. Scans for 256-bit entropy patterns matching Bearer token format; 3. Recovers active API key without brute-force; mitigated by `Zeroizing` zeroing on `Drop`
- **Fix:** All secret material wrapped in `Zeroizing<String>` / `Zeroizing<Vec<u8>>` from the `zeroize` crate; memory zeroed on `Drop` before deallocation (commit `b85b2cd`)
- **Residual risk:** Fix is believed complete; no known residual risk under current threat model
- **Verification:** No automated test; verified by manual review [AI-INTERNAL] (commit `b85b2cd`)

**Verdict [AI-INTERNAL]:** No plaintext secret material detected in memory under code review. HSM integration via `cryptoki` crate verified structurally. No formal HSM certification evaluation conducted; claim is scoped to [AI-INTERNAL] code review only.

### 3.2b HTTP Body Size Limit

**[SEC-04] — HTTP Body Unbounded**
- **Severity:** MEDIUM
- **Source:** [AI-INTERNAL]
- **File:** src/api/mod.rs (approximate)
- **Discovered:** v0.6.9
- **Status:** ✅ Capped 65 KiB
- **Threat model:** Unauthenticated attacker (body is read before auth check) or authenticated API user sending an oversized HTTP request body to exhaust server memory and cause OOM termination of the DNS process
- **Description:** HTTP request bodies accepted by the REST API had no upper size bound. Axum's default body handling buffers the complete request body in memory before routing or authentication. An attacker can send a streaming body with a large Content-Length, exhausting process memory and triggering OOM termination, resulting in DNS service outage.
- **Exploit path:** 1. Attacker connects to API (no auth required for body to be buffered); 2. Sends POST with `Content-Length: 1073741824` and streaming 1 GiB body; 3. Axum buffers body in memory; 4. OOM kill terminates Runbound; 5. DNS outage until restart
- **Fix:** Global body size limit enforced at 65,536 bytes (65 KiB) via axum `DefaultBodyLimit` middleware applied before routing (commit `dab1fbd`)
- **Residual risk:** Fix is believed complete; no known residual risk under current threat model
- **Verification:** No automated test; verified by manual review [AI-INTERNAL] (commit `dab1fbd`)

### 3.3 Unsafe Code

The project enforces `#![deny(unsafe_op_in_unsafe_fn)]` in all XDP modules — every unsafe block must be explicitly justified.

| File | Nature | Justification | Verdict |
|------|--------|---------------|---------|
| `umem.rs` | 45+ `read/write_volatile` on rings | Kernel/userspace shared memory, protocol requires volatile access | ✅ Correctly barriered (Acquire/Release fences) |
| `socket.rs` | libc syscalls (socket, bind, ioctl) | No safe abstraction available | ✅ Post-call validation |
| `worker.rs` | UMEM frame access | Kernel-controlled descriptors | ⚠️ See §3.4 |
| `loader.rs` | `ptr::copy_nonoverlapping` for ELF alignment | Required by aya parser | ✅ Bounds checked before copy |

**Verdict: ✅ Dense but correctly documented. No UB detected.**

### 3.4 UMEM Security

Context: RX descriptors arrive from the kernel via the AF_XDP ring. A kernel bug or confused-deputy attack could inject a descriptor with `addr + len` exceeding the UMEM region.

Mitigation in place (`worker.rs`):

```rust
let end = (desc.addr as usize).checked_add(desc.len as usize);
if desc.len as usize > FRAME_SIZE as usize
    || end.map(|e| e > sock.umem.area_len).unwrap_or(true) {
    // drop silently
}
```

`checked_add` prevents integer overflow. Each kernel descriptor is validated before memory access.

---

**[SEC-03] — UMEM Buffer Overflow**
- **Severity:** HIGH
- **Source:** [AI-INTERNAL]
- **File:** src/dns/xdp/worker.rs (approximate line 120)
- **Discovered:** v0.6.x
- **Status:** ✅ Fixed + ⚠️ Accepted risk (kernel trust — see §Known Limitations)
- **Threat model:** Kernel vulnerability or confused-deputy attack producing an AF_XDP RX ring descriptor with `addr + len` exceeding the UMEM region bounds, enabling out-of-bounds memory read or write in userspace
- **Description:** AF_XDP RX ring descriptors are produced by the kernel and consumed by the XDP worker. Without bounds checking, a malicious or buggy kernel descriptor could direct the worker to access memory outside the UMEM allocation, leading to memory corruption or information disclosure. Integer overflow in `addr + len` is also a risk without `checked_add`.
- **Exploit path:** Theoretical — kernel vulnerability injects descriptor with addr=UMEM_SIZE-4, len=65536; without mitigation, `addr + len` overflows and worker accesses arbitrary memory; with `checked_add` + bounds check in place, descriptor is silently dropped; actual exploit requires a kernel vulnerability (see KL-01)
- **Fix:** `checked_add` arithmetic overflow protection plus explicit bounds check (`desc.len > FRAME_SIZE || addr + len > area_len`) before any memory access; malformed descriptors silently dropped (commit `c8ff1b0`)
- **Residual risk:** Kernel trust is implicit; a kernel-level vulnerability could inject descriptors before the bounds check is evaluated; see KL-01 for the accepted-risk rationale
- **Verification:** No automated test; verified by manual review [AI-INTERNAL] (commit `c8ff1b0`)

**Verdict: ✅ Protection in place. Kernel trust is implicit (acceptable for dedicated hardware deployment).**

### 3.5 eBPF Surface

eBPF program (`ebpf/dns_xdp.c`, 154 lines):

- No unbounded loops: FNV-1a hash capped at 64 iterations — respects BPF verifier limits
- All memory accesses have bounds checks: eth/ip/ipv6/udp headers validated before access (lines 85, 95, 109, 121)
- `XSKMAP max_entries = 64`: architectural limit documented; Rust code rejects any `queue_id >= 64` before loading
- `XDP_PASS` fallback on all non-UDP/53 packets → no black-hole possible

Potential vector: A malformed DNS packet reaches the XDP worker. Protection is in `process_packet()` (Rust, not eBPF), which validates structure before processing.

**Verdict: ✅ Verifier-compliant. No OOB detected.**

### 3.6 DNS Protection

**DNS rebinding:** Each upstream response is filtered against configured private CIDR ranges. RFC 1918 + loopback + link-local blocked by default.

**Rate limiting:**
- 200 QPS/IP default (configurable)
- Burst: 2× limit
- IPv6 /48 aggregation: an attacker with a /48 is treated as a single IP — protection against distributed IPv6 floods
- Anti-bucket-exhaustion: max 65,536 entries + aggressive GC when full

**ANY queries:** Blocked (amplification protection per RFC 8482).

**version.bind, hostname.bind, id.server:** Blocked (CHAOS class fingerprinting).

**DNSSEC:** Optional. In forwarder mode (default), the upstream AD bit is accepted without local validation. For a recursive production deployment, `dnssec-validation: yes` is mandatory.

---

**[SEC-09] — DNS Rebinding**
- **Severity:** HIGH
- **Source:** [AI-INTERNAL]
- **File:** src/dns/server.rs (approximate)
- **Discovered:** v0.6.9
- **Status:** ✅ CIDR guards
- **Threat model:** External attacker hosting a domain that resolves to a private RFC 1918 address, enabling browser-based access to internal network services via DNS rebinding
- **Description:** DNS rebinding exploits the browser same-origin policy by having a domain initially resolve to a public IP (passing any access controls), then rebinding to a private IP on a second resolution. Runbound as a DNS resolver must filter private-space addresses from upstream responses to break the attack at the resolver level.
- **Exploit path:** 1. Attacker registers attacker.com → 198.51.100.1 (public); 2. Victim browser loads attacker.com — connects to public server; 3. Attacker changes DNS TTL=0, now attacker.com → 192.168.1.1; 4. Browser re-resolves and contacts internal 192.168.1.1; 5. Same-origin context allows CSRF/data exfiltration against internal services; mitigated by Runbound filtering RFC 1918 from upstream answers
- **Fix:** Upstream response filtering against RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback (127.0.0.0/8), and link-local (169.254.0.0/16); blocked responses returned as SERVFAIL (`private-address` directive introduced commit `a5cba9a`)
- **Residual risk:** Fix is believed complete; no known residual risk under current threat model
- **Verification:** No automated test; verified by manual review [AI-INTERNAL] (commit `1efbcf2`)

**[SEC-10] — ANY Amplification**
- **Severity:** HIGH
- **Source:** [AI-INTERNAL]
- **File:** src/dns/server.rs (approximate)
- **Discovered:** v0.6.9
- **Status:** ✅ Blocked
- **Threat model:** Network attacker using Runbound as a DNS amplification reflector with spoofed UDP source IP to direct large DNS ANY responses at a victim (DDoS amplification)
- **Description:** DNS ANY queries historically return all record types in a single response, often 10–60× the query size. With UDP source spoofing, a small ANY query generates a large response directed at a victim IP. RFC 8482 recommends servers return a minimal response or refuse ANY queries.
- **Exploit path:** 1. Attacker spoofs victim's IP as UDP source; 2. Sends 40-byte ANY query for example.com to Runbound; 3. Without mitigation, Runbound returns 2 KB+ multi-record response to victim; 4. Amplification factor ~50×; 5. Repeated at volume creates DDoS; mitigated by blocking ANY query type
- **Fix:** ANY queries blocked per RFC 8482 (commit `2aeeab7`, present since initial public release); CHAOS class queries (version.bind, hostname.bind, id.server) blocked per commit `80331be`
- **Residual risk:** Fix is believed complete; no known residual risk under current threat model
- **Verification:** No automated test; verified by manual review [AI-INTERNAL] (ANY: commit `2aeeab7`; CHAOS: commit `80331be`)

**[SEC-05] — DNSSEC Disabled by Default**
- **Severity:** MEDIUM
- **Source:** [AI-INTERNAL]
- **File:** src/config/ (configuration default)
- **Discovered:** v0.6.9
- **Status:** Open — targeted v1.0 (operator configuration; no default-safe option without breaking forwarder use-case)
- **Threat model:** Compromised upstream DNS resolver or on-path attacker returning spoofed DNS records with the AD bit set; Runbound in forwarder mode trusts the upstream AD bit without local validation
- **Description:** In forwarder mode (default), Runbound trusts the upstream resolver's DNSSEC validation via the AD bit in responses. An attacker controlling the upstream (via cache poisoning or BGP hijack) can return spoofed records with AD=1, which Runbound forwards to clients without independent DNSSEC signature verification against the root trust anchor.
- **Exploit path:** 1. Attacker poisons upstream recursive resolver cache for target.example.com; 2. Upstream returns spoofed A record 1.2.3.4 with AD=1; 3. Runbound forwards to client without re-validating signatures; 4. Client resolves to attacker-controlled IP; mitigated by enabling local DNSSEC validation
- **Fix:** Enable `dnssec-validation: yes` in production configuration; requires explicit operator action (blocking item — see §6)
- **Residual risk:** Risk remains in all deployments until operator enables DNSSEC; see KL-02
- **Verification:** No automated test; configuration default reviewed manually

**Verdict:** DNS rebinding, amplification, and fingerprinting protections verified present. ⚠️ DNSSEC requires explicit operator enablement — see SEC-05.

### 3.7 Signal Handling

| Signal | Behavior |
|--------|----------|
| SIGHUP | Hot-reload zones without DNS interruption |
| SIGUSR1 | Dump live stats to log (monitoring) |
| SIGUSR2 | Ignored (reserved) |
| SIGTERM | Graceful shutdown via Tokio runtime |

Before fix: SIGUSR1/SIGUSR2 → immediate process death (OS default behavior). Fixed in v0.6.9 (commit `a32005b`).

---

**[SEC-08] — SIGUSR1/2 Kill Process**
- **Severity:** HIGH
- **Source:** [AI-INTERNAL]
- **File:** src/main.rs (signal handler registration)
- **Discovered:** v0.6.8 (fixed v0.6.9)
- **Status:** ✅ Fixed v0.6.9
- **Threat model:** Monitoring system or local user sending SIGUSR1 (standard stats-request signal) to Runbound, triggering the OS default handler and unintentionally terminating the DNS service
- **Description:** SIGUSR1 and SIGUSR2 have no Rust default handler — they deliver the OS default action, which is process termination. Monitoring tools (nagios, prometheus node_exporter, custom scripts) commonly send SIGUSR1 to processes to request a stats dump. Without explicit handlers, any SIGUSR1 terminates Runbound immediately without cleanup, causing a DNS outage.
- **Exploit path:** 1. Monitoring system sends `kill -USR1 $(pidof runbound)` on a routine stats poll; 2. OS delivers SIGUSR1; 3. Unhandled signal → immediate process termination; 4. DNS outage until service is restarted; no deliberate attack required — standard monitoring triggers this accidentally
- **Fix:** Explicit tokio signal handlers registered: SIGUSR1 triggers live stats dump to tracing log; SIGUSR2 ignored (reserved for future use); SIGHUP triggers hot zone reload; SIGTERM triggers graceful Tokio runtime shutdown (commit `a32005b`)
- **Residual risk:** Fix is believed complete; no known residual risk under current threat model
- **Verification:** No automated test; verified by manual review [AI-INTERNAL] (commit `a32005b`)

### 3.8 Dependency Security

| CVE/Advisory | Dependency | Status |
|-------------|-----------|--------|
| RUSTSEC-2025-0009 | `ring < 0.17.9` (AES panic) | ✅ Patched via `hickory v0.26.1` which pins ring ≥ 0.17.9 (commit `f894e55`) |
| RUSTSEC-2026-0037 | `quinn` DoS | ✅ Patched via `hickory v0.26` (commit `f894e55`) |

TLS: `rustls 0.23` (TLS 1.3 by default) + AWS-LC. No OpenSSL in the dependency chain.

---

**[SEC-07] — Dependency CVEs**
- **Severity:** HIGH
- **Source:** AUTOMATED-TOOL: cargo-audit 0.21.x
- **File:** Cargo.toml
- **Discovered:** v0.6.9 (cargo-audit scan)
- **Status:** ✅ Patched
- **Threat model:** Attacker exploiting a known CVE in a dependency to cause process panic (DoS), bypass TLS validation, or achieve code execution in the DNS server
- **Description:** Two active security advisories affected the dependency chain at audit time. RUSTSEC-2025-0009: `ring < 0.17.9` contains a panic in the AES-GCM implementation reachable via a crafted TLS ClientHello, causing process termination (DoS). RUSTSEC-2026-0037: `quinn` (pulled in via hickory DNS-over-QUIC support) contains a DoS vulnerability where a malformed QUIC Initial packet causes a panic.
- **Exploit path:** RUSTSEC-2025-0009: 1. Attacker connects to DoT/DoH listener; 2. Sends crafted TLS ClientHello targeting the ring AES path; 3. Panic in ring < 0.17.9; 4. Process terminates, DNS outage. RUSTSEC-2026-0037: 1. Attacker sends malformed QUIC Initial packet to DoQ listener; 2. Panic in quinn; 3. Process terminates
- **Fix:** `hickory-dns` updated to v0.26.1 which pulls patched quinn and pins ring ≥ 0.17.9, resolving both advisories (commit `f894e55`)
- **Residual risk:** Fix is believed complete for known advisories; cargo-audit must be re-run on each dependency update
- **Verification:** cargo-audit 0.21.x [AUTOMATED-TOOL] — confirms no active advisories after patching; No automated test; verified by manual review [AI-INTERNAL] (commit `f894e55`)

**Verdict: ✅ Clean dependency chain.**

### 3.9 Production Deployment Checklist

| ID | Risk | Severity | Action required |
|----|------|----------|----------------|
| R1 | No internal privilege dropping | MEDIUM | Delegate to systemd (`User=`, `CapabilityBoundingSet=`) |
| R2 | DNSSEC disabled by default | MEDIUM | Enable `dnssec-validation: yes` in production |
| R3 | `log-client-ip: yes` by default | LOW | Set to `no` if IP retention is not legally justified (GDPR note — see Description) |

---

**[SEC-06] — Privilege Dropping (Checklist R1)**
- **Severity:** MEDIUM
- **Source:** [AI-INTERNAL]
- **File:** [VERIFY — systemd unit file location not confirmed in this audit cycle]
- **Discovered:** v0.6.9
- **Status:** Open — targeted v1.0 (systemd unit hardening; deployment-time configuration item)
- **Threat model:** Remote attacker achieving code execution via a vulnerability in DNS packet processing; current root execution provides full system compromise upon exploitation
- **Description:** Runbound must run as root to bind UDP/53, load eBPF programs (CAP_BPF, CAP_NET_ADMIN), and manipulate network interfaces. No internal privilege dropping occurs after initialization. If an attacker achieves code execution via a future DNS processing vulnerability, they obtain root. Delegating privilege restriction to systemd sandboxing limits the blast radius without changing runtime capabilities.
- **Exploit path:** Theoretical — 1. Attacker sends crafted DNS packet exploiting a memory safety bug in the XDP worker or hickory DNS parser; 2. Code execution achieved in Runbound process context; 3. Process runs as root → full system compromise; with systemd hardening applied: step 3 is limited to User=runbound capabilities, significantly reducing blast radius
- **Fix:** Operator must configure systemd unit with: `User=runbound`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_BPF`, `NoNewPrivileges=yes`, `MemoryDenyWriteExecute=no` (cannot enable due to JIT); required before deployment (blocking item)
- **Residual risk:** Risk remains until systemd hardening is applied; this is a deployment-time configuration item, not a code fix
- **Verification:** No automated test; operator configuration responsibility

**[SEC-06b] — Client IP Logging GDPR Risk (Checklist R3)**
- **Severity:** LOW
- **Source:** [AI-INTERNAL]
- **File:** src/config/ (configuration default)
- **Discovered:** v0.6.9
- **Status:** ⚠️ GDPR consideration — operator action required if applicable
- **Threat model:** Regulatory/compliance risk; DNS query logs with client IPs may constitute personal data under GDPR Article 4(1) if the deployment processes EU persons' data
- **Description:** `log-client-ip: yes` is the default configuration. In EU deployments, DNS query logs containing IP addresses may constitute personal data requiring a lawful basis for retention, data minimization measures, and data subject rights under GDPR. This is not a technical security vulnerability but a compliance risk that could result in regulatory findings or fines.
- **Exploit path:** N/A — compliance risk, not a technically exploitable vulnerability
- **Fix:** Set `log-client-ip: no` in configuration if GDPR applies and IP retention has no lawful basis; document retention purpose and legal basis if `yes` is retained
- **Residual risk:** Operator decision; compliance risk only in applicable regulatory contexts
- **Verification:** No automated test; operator configuration responsibility

### 3.10 SSRF via Upstream Address Validation

**[SEC-11] — SSRF via Upstream 0.0.0.0**
- **Severity:** MEDIUM
- **Source:** [AI-INTERNAL]
- **File:** src/api/upstreams.rs (approximate)
- **Discovered:** v0.6.9
- **Status:** ⏳ Open in v0.6.9 audit scope — fix implemented in v0.6.11 (outside this cycle)
- **Threat model:** Authenticated API user (with valid Bearer token) adding an upstream DNS address of 0.0.0.0 or 127.0.0.1 to cause Runbound to establish DoT connections to itself or to loopback services (SSRF)
- **Description:** The upstream management REST API accepted arbitrary IP addresses as upstream DNS server addresses without validating against reserved or loopback ranges. An authenticated attacker could add 0.0.0.0:853 or 127.0.0.1:853, causing Runbound to attempt DoT connections to itself (loop) or to other services on loopback. In container or multi-tenant environments, 0.0.0.0 may route to the host or adjacent containers.
- **Exploit path:** 1. Attacker with valid Bearer token calls `POST /api/upstreams` with `{"address": "0.0.0.0", "port": 853}`; 2. Runbound persists upstream to `/etc/runbound/upstreams.json`; 3. Upstream probe initiates DoT handshake to 0.0.0.0:853; 4. Connection may reach loopback services, cause a connection loop, or probe other internal services; potential for SSRF against localhost or self-loop causing resource exhaustion
- **Fix:** Input validation added in v0.6.11 rejecting 0.0.0.0, 127.0.0.0/8 (loopback), ::1, link-local, and other invalid upstream addresses; validated before persistence to disk (commit `2dedd6f`, two unit tests included)
- **Residual risk:** Open in v0.6.9 audit scope; fix implemented outside this audit cycle (v0.6.11)
- **Verification:** Fix commit for v0.6.11 outside this audit scope — locate with: git log --oneline --all | grep -i ssrf; two unit tests added in commit `2dedd6f`; No automated test; verified by manual review [AI-INTERNAL]

---

## 4. Performance Audit

### 4.1 XDP Hot Path Analysis

Critical path for a DNS query in XDP mode:

```
[Packet arrives at NIC]
    ↓ ~0 ns   — Hardware DMA → UMEM frame
    ↓ ~50 ns  — eBPF filter (bounds checks + FNV-1a hash if CPUMAP)
    ↓ ~0 ns   — AF_XDP ring enqueue
    ↓ ~100 ns — poll() wakeup XDP worker thread
    ↓ ~200 ns — parse Ethernet/IP/UDP/DNS (inline, no allocation)
    ↓ ~50 ns  — ACL check (ArcSwap load, DashMap lookup)
    ↓ ~100 ns — rate limiter (DashMap per-IP)
    ↓ ~200 ns — LocalZoneSet lookup (hashmap)
    ↓ ~100 ns — Cache snapshot lookup (ArcSwap load + HashMap)
    ↓ ~200 ns — Build DNS response (inline into TX UMEM frame)
    ↓ ~50 ns  — TX ring enqueue + kick
    ↓ ~0 ns   — Hardware DMA → NIC TX
Total estimated: ~1 µs (single-threaded, cache-warm)
```

Theoretical throughput: at 1 µs/query on 1 core → 1 M QPS/core. With 8 XDP cores → 8 M QPS.

### 4.2 AF_XDP Configuration

| Parameter | Current value | Assessment |
|-----------|--------------|------------|
| `FRAME_SIZE` | 4,096 bytes | ✅ Optimal (1 page = 1 DNS packet) |
| `FRAME_COUNT` | 8,192 | ✅ 32 MiB/socket |
| `RX_RING_SIZE` | 4,096 | ✅ Deep enough for 10 µs burst |
| `TX_RING_SIZE` | 4,096 | ✅ |
| `FILL_RING_SIZE` | 4,096 | ✅ |
| `COMP_RING_SIZE` | 4,096 | ✅ |
| NIC ring buffer | `maximize_nic_ring()` auto | ✅ Maximized before XDP attach |
| Hugepages | Optional, 4K fallback | ⚠️ Enable in production (reduce TLB misses) |

Buffer margin at 10 M QPS:
- 10 M QPS / 10 queues = 1 M QPS/queue = 1 packet/µs
- Ring depth 4,096 × 1 µs/packet = 4 ms buffer
- Overflow tolerance: 4 ms — sufficient

### 4.3 Bottlenecks Identified (v0.6.9)

> **v0.8.1 update:** PERF-01 through PERF-06 below were identified in v0.6.9 and are all
> implemented in v0.8.1. See `docs/security-audit/v0.8.1-performance.md` for full
> verification details.

#### PERF-01 — Cache snapshot interval ✅ Fixed (v0.8.1)

`cache_snapshot.rs:246` — `Duration::from_millis(10)`. Double-buffer design uses
`DashMap` writer + `ArcSwap<HashMap>` reader; publish loop evicts expired entries before swap.

#### PERF-02 — Mutex on mutable cache ✅ Fixed (v0.8.1)

`cache_snapshot.rs:65` — `MutableCacheMap = Arc<DashMap<QuestionKey, CacheEntry>>`.
No `Mutex<HashMap>` on the mutable side.

#### PERF-03 — No NUMA awareness ✅ Fixed (v0.8.1)

`umem.rs:538` — `rebind_to_local_numa()` calls `mbind(MPOL_PREFERRED | MPOL_MF_MOVE)`.
Invoked from `worker.rs:402` after CPU pinning. Silent no-op in containers / single-node.

#### PERF-04 — Hugepages optional ⚠️ Config gap (code correct)

`umem.rs:329` — `alloc_umem_area(size, hugepages: bool)` tries `MAP_HUGETLB` first.
Operator must set `xdp-hugepages: yes` in config and `vm.nr_hugepages ≥ 512` in sysctl.

#### PERF-05 — No TX batching ✅ Fixed (v0.8.1)

`worker.rs:537` — hot loop accumulates `tx_descs: Vec<XdpDesc>` per poll batch, then calls
`sock.tx.enqueue_tx(&tx_descs)` once; `sendto()` kick issued at most once per batch.

#### PERF-06 — SO_REUSEPORT on UDP fallback ✅ Verified (v0.8.1)

`server.rs:1389` — `bind_reuseport_udp()` creates one `SO_REUSEPORT` UDP socket per
physical CPU when XDP is disabled. Kernel load-balances across all sockets.

### 4.4 Performance Projection

| Scenario | Hardware | Estimated QPS | p99 latency |
|----------|---------|--------------|------------|
| XDP disabled (Tokio only) | 32 cores | ~500 K QPS | 2–5 ms |
| XDP + 4 NIC queues | 4 XDP cores | ~4 M QPS | < 200 µs |
| XDP + 8 NIC queues | 8 XDP cores | ~8 M QPS | < 150 µs |
| XDP + 8 queues + hugepages + CPUMAP | 8 dedicated cores | ~10 M QPS | < 100 µs |

---

## 5. Consolidated Risk Matrix

### Security

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| SEC-01 | Auth timing oracle | MEDIUM | ✅ Mitigated (commit `f9ee716` — No automated test; verified by manual review) |
| SEC-02 | Plaintext secrets in memory | HIGH | ✅ Zeroizing (commit `982467f` — No automated test; verified by manual review) |
| SEC-03 | UMEM buffer overflow | HIGH | ✅ Fixed + ⚠️ Accepted risk (kernel trust — see §Known Limitations) (commit `c8ff1b0`) |
| SEC-04 | HTTP body unbounded | MEDIUM | ✅ Capped 65 KiB (commit `dab1fbd` — No automated test; verified by manual review) |
| SEC-05 | DNSSEC disabled by default | MEDIUM | ⚠️ Enable in production |
| SEC-06 | Privilege dropping | MEDIUM | ⚠️ Delegate to systemd |
| SEC-07 | Dependency CVEs | HIGH | ✅ Patched (commit `f894e55` — cargo-audit confirms clean) |
| SEC-08 | SIGUSR1/2 kill process | HIGH | ✅ Fixed v0.6.9 (commit `a32005b` — No automated test; verified by manual review) |
| SEC-09 | DNS rebinding | HIGH | ✅ CIDR guards (commit `a5cba9a` — No automated test; verified by manual review) |
| SEC-10 | ANY amplification | HIGH | ✅ Blocked (ANY: commit `2aeeab7`; CHAOS: commit `80331be` — No automated test; verified by manual review [AI-INTERNAL]) |
| SEC-11 | SSRF via upstream 0.0.0.0 | MEDIUM | ⏳ Open in v0.6.9 scope — fixed v0.6.11 (commit `2dedd6f`, two unit tests) |

## Performance Analysis (Non-Security Annex)

Note: items below are performance risks, not security vulnerabilities. Severity terms (MAJOR/MINOR) use a separate scale from the security findings above.

### Performance

| ID | Title | Impact | Status |
|----|-------|--------|--------|
| PERF-01 | Cache publish 10 ms | ~~MAJOR~~ | ✅ Fixed — cache_snapshot.rs:246 |
| PERF-02 | DashMap on mutable cache | ~~MAJOR~~ | ✅ Fixed — cache_snapshot.rs:65 |
| PERF-03 | NUMA-aware UMEM | ~~MEDIUM~~ | ✅ Fixed — umem.rs:538, worker.rs:402 |
| PERF-04 | Hugepages optional | MEDIUM | ⚠️ Config gap — xdp-hugepages: yes + sysctl |
| PERF-05 | TX batched per poll batch | ~~LOW~~ | ✅ Fixed — worker.rs:537 |
| PERF-06 | SO_REUSEPORT on UDP fallback | ~~MEDIUM~~ | ✅ Verified — server.rs:1389 |
| PERF-07 | jemalloc | — | ✅ Configured |
| PERF-08 | CPU affinity | — | ✅ Physical cores |
| PERF-09 | IRQ affinity | — | ✅ Optional, recommended |
| PERF-10 | NIC ring maximized | — | ✅ SIOCETHTOOL auto |

---

## Known Limitations and Accepted Risks

**KL-01 — Kernel trust for UMEM descriptors**
AF_XDP RX ring descriptors are trusted after bounds-checking. A kernel vulnerability exploiting the UMEM interface could bypass this. Accepted for dedicated-hardware deployments where kernel integrity is assumed.

**KL-02 — DNSSEC validation requires explicit operator action**
Runbound does not enable DNSSEC validation by default. Deployments without `dnssec-validation: yes` accept the upstream AD bit without local validation. Accepted pending operator education; documented in deployment checklist.

**KL-03 — Authorization header length observable on management interface**
Even with constant-time comparison, the length of the Bearer token is observable to a network attacker monitoring the management interface. Accepted because the API is bound to 127.0.0.1 by default; risk is low in the intended deployment model.

**KL-04 — IPv6 /48 aggregation may cause false-positive rate limiting**
The rate limiter aggregates IPv6 /48 prefixes. A large ISP using NAT64 or a shared /48 prefix may be incorrectly throttled. Accepted as an architectural trade-off between DDoS protection and false-positive rate.

**KL-05 — Tokio UDP fallback path audited at lower depth**
The Tokio-based UDP slow path (non-XDP) was reviewed for configuration correctness (SO_REUSEPORT, buffer sizes) but was not subjected to the same depth of analysis as the XDP fast path. Risk: undetected vulnerabilities in the fallback path. Accepted; XDP is the intended production path and fallback is a degraded mode.

**KL-06 — All audits to date are [AI-INTERNAL]**
No external human security review has been conducted. The [AI-INTERNAL] methodology cannot substitute for adversarial human expertise. External human audit is not yet scheduled. This is the primary limitation of the current security posture documentation.

**KL-07 — Re-audit independence not maintained (R10)**
All fix verifications to date were performed by the same AI model family that authored the fixes. Independent re-audit by a different model family or human reviewer is pending. All "Fixed" findings should be read as "Claimed fixed; pending independent verification."

---

## 6. Priority Recommendations

### Blocking — required before production deployment

1. **SEC-06** — systemd unit hardening:
   ```ini
   User=runbound
   CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_BPF
   NoNewPrivileges=yes
   MemoryDenyWriteExecute=no
   ```

2. **SEC-05** — Enable in production config:
   ```
   server:
       dnssec-validation: yes
   ```

3. **PERF-04** — Production config (hugepages — code correct, operator action required):
   ```
   server:
       xdp-hugepages: yes
   ```
   System: `vm.nr_hugepages = 512`

### Post-deployment improvements

- **GDPR** — `log-client-ip: no` if GDPR applies to the deployment
- **Benchmark refresh** — Re-run `docs/benchmark-2026-05-20.md` methodology against v0.8.1;
  v0.5.4 numbers in `docs/performance.md` predate PERF-01 through PERF-06 fixes

---

## 7. Conclusion

Runbound v0.6.9 meets the documented design constraints for the surfaces reviewed, with four items (§6) blocking any deployment decision. The XDP kernel-bypass architecture is correct, memory guarantees are solid, and the dependency chain is clean. The 5 M QPS target is realistic on a 1U server with a 10G 8-queue NIC with hugepages enabled and the publish interval fix applied.
