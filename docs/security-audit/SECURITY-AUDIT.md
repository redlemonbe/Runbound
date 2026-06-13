# Runbound — Security Audit Master Document

**Current version:** v0.18.0 (Cycle J two-AI audit completed 2026-06-13; remediation pending maintainer approval — see Cycle J)  
**Last updated:** 2026-06-13  
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
| [D](#audit-status--v0944) | v0.9.43–v0.9.44 | — | — | **Covered by Cycle E/F/G** |
| [E](#cycle-e--v0946v0948-asm-hotpath--webui) | v0.9.46–v0.9.48 | 2026-05-26 | AI-INTERNAL | 0 open (2 fixed, 3 accepted, 2 info) |
| [F](#cycle-f--v0120-defense-in-depth-hardening) | v0.11.1→v0.12.0 | 2026-06-06 | [AI-ADVERSARIAL] Nexus (Gemini 2.5 Pro × Qwen3-Coder) | 5 open (enhancements); 3 disputed-false, 2 fixed, 2 accepted |
| [G](#cycle-g--v0150-two-ai-competitive-audit) | v0.13.0→v0.15.0 | 2026-06-06 | [AI-INTERNAL] Claude × [AI-ADVERSARIAL] Qwen3-Coder-30B (local) + Gemini 2.5 Pro | 2 open (2 fixed, 4 disputed) — no accepted |
| [H](#cycle-h--v0160v0164-two-ai-adversarial--rate-limitban-both-paths-dnssec-ad-persistence) | v0.16.0→v0.16.4 | 2026-06-08 | [AI-ADVERSARIAL] Claude Opus 4.8 (Red×Blue) | 0 open; 6 fixed, 3 accepted, 2 disputed |
| [I](#cycle-i--v0170--two-ai-competitive-audit-kernel-slow-path-auto-tune--full-surface-re-review) | v0.16.11→v0.17.0 | 2026-06-11 | [AI-INTERNAL] Claude Opus 4.8 × [AI-ADVERSARIAL] Gemini 2.5 Pro | 4 open (enhancement); 15 fixed, 3 accepted, 5 disputed |
| [J](#cycle-j--v0180--two-ai-competitive-audit-full-surface-re-review) | v0.17.2→v0.18.0 | 2026-06-13 | [AI-INTERNAL] Claude Opus 4.8 × [AI-ADVERSARIAL] Gemini 2.5 Pro + live pentest | 1 HIGH + 3 MEDIUM + 7 LOW open (remediation pending approval); 2 accepted, 2 disputed; 0 fixed. Pentest: SEC-J1/J2 confirmed exploitable, SEC-J4 downgraded→LOW |

---

## Current Open Findings

Through Cycle E (v0.9.50) all tracked findings were fixed, accepted, or classified as false positives. **Cycle F (v0.12.0)** opened enhancement-class findings OPEN-F1..F5. As of v0.15.0: OPEN-F2 (reproducible build + signatures), OPEN-F4 (SIEM JSON logs) and OPEN-F5 (CycloneDX SBOM) are **Fixed**; OPEN-F1 (third-party human audit, #170) remains **Open**; OPEN-F3 (strict RRL) is **not planned**. None were active vulnerabilities.

All findings have been fixed (SEC-B7, SEC-B10, SEC-B13, SEC-B16, SEC-C1, SEC-C2, SEC-C3, SEC-C4), accepted (SEC-B6, SEC-B8, SEC-B11, SEC-B15, SEC-C5, SEC-C7, PERF-C2), or classified as false positives (SEC-C6, SEC-C8).

---

## Cycle J — v0.18.0 — two-AI competitive audit (full-surface re-review)

**Date:** 2026-06-13  
**Sources:** `[AI-INTERNAL]` Claude Opus 4.8 (per-domain manual review of the relay/auth, eBPF packet parser, and config-write paths) × `[AI-ADVERSARIAL]` Gemini 2.5 Pro (independent per-file red-team on the 11 highest-risk files: `sync.rs`, `api/mod.rs`, `config/parser.rs`, `ebpf/dns_xdp.c`, `dns/xdp/worker.rs`, `upstreams.rs`, `feeds/mod.rs`, `webui/mod.rs`, `main.rs`, `dns/kernel_loop.rs`, `dns/xdp/umem.rs`). Every Gemini finding was re-verified against the source by Claude before classification; two were rejected as model hallucinations (see Disputed). Per the standing process, remediation is **not yet applied** — findings are filed Open pending a maintainer-approved plan. Live exploitation of the bypass/auth findings is validated separately (Cycle J-pentest, below when run).

**Status (post-remediation, PR #198):** 7 fixed (SEC-J1 HIGH + J2/J3/J5/J7/J13/J14), SEC-J9 closed (already mitigated, #195), SEC-J12 closed (false positive, #196), SEC-J8 deferred (eBPF/XDP datapath — cosmetic), SEC-J4 downgraded→LOW (pentest), SEC-J6/J10 accepted (defence-in-depth), 2 disputed (Gemini false positives). Not a clean sweep — SEC-J8 is deferred and J6/J10 remain accepted. The one HIGH (SEC-J1) is fixed and was confirmed exploitable pre-fix in the live pentest.

### Open

#### SEC-J1 — Config-directive injection via the split-horizon API (`name`/`subnet` not escaped) — HIGH
**Source:** [AI-ADVERSARIAL] Gemini 2.5 Pro, confirmed against code by [AI-INTERNAL] Claude  
**Severity:** HIGH **Status:** Open  
**Description:** `add_split_horizon` (`api/mod.rs`) accepts the API-supplied `name`/`subnet`, validating only non-emptiness (no character validation), then `persist_config → render_config` writes them with `format!("    name: \"{}\"\n", se.name)` at `config/writer.rs:276-277` **without `escape_str`** — unlike `local-zone` (l.121) and forward-zone `name` (l.238), which do escape. `escape_str` neutralises `"`, `\`, `\n`, `\r`; its omission here lets a `name` containing a newline inject an arbitrary directive into the regenerated `runbound.conf`. An authenticated API client can thus inject any server directive — e.g. `ui-acme-hook: "/path"`, which `hook_run` (`acme.rs:415`, `tokio::process::Command::new(script)`) later executes **as root** on the next ACME DNS-01 challenge; or `ui-cert`/`ui-key` to coerce arbitrary file reads; or directives that weaken bind/TLS. This crosses the API→OS trust boundary (an API key is not meant to grant shell-root). The hook is run directly (no shell), so it is arbitrary-binary execution, not shell-metacharacter injection — Gemini's separate "OS command injection via ACME hook" (main.rs) and "command injection via ui-acme-hook" (parser.rs) framings are the same chain, re-scoped here.  
**Fix (proposed):** wrap `se.name` and each `subnet` in `escape_str` in `render_config`; additionally reject control/newline characters in `add_split_horizon` at the API boundary.

#### SEC-J2 — WebUI falls back to default credentials `admin`/`admin` — MEDIUM
**Source:** [AI-ADVERSARIAL] Gemini 2.5 Pro, confirmed by [AI-INTERNAL] Claude  
**Severity:** MEDIUM **Status:** Open  
**Description:** `load_or_default_creds` (`webui/mod.rs:178-194`) returns `admin`/`admin` (argon2-hashed) when `webui-auth.conf` is absent, unreadable or invalid. The default is partly mitigated — `/api/webui/password-status` (l.601) exposes `default:true` for the UI to warn, the file is written on first password change (l.642), and the design intends "delete the file to reset". But a webui that is enabled and exposed without a password change is open to `admin/admin`. Conditional on `ui-enabled` + network exposure.  
**Fix (proposed):** on first boot with no creds file, generate a random one-time password, log it once, and require a change before granting access — instead of a static fallback.

#### SEC-J3 — Upstream health-probe uses a static DNS transaction ID (off-path spoofable) — MEDIUM
**Source:** [AI-ADVERSARIAL] Gemini 2.5 Pro, confirmed by [AI-INTERNAL] Claude  
**Severity:** MEDIUM **Status:** Open  
**Description:** `DNS_PROBE_PACKET` (`upstreams.rs:41`) hard-codes the DNS ID `0x0001`; the UDP/DoT probe acceptance check (`upstreams.rs:753`, `:833`) validates only `buf[0..2] == DNS_PROBE_PACKET[0..2]` — a value that is public (open-source). An off-path attacker spoofing the upstream's source IP can forge a "healthy" reply, masking a dead upstream (degrades the racing resolver / suppresses failover). Connected-UDP source filtering does not stop a spoofed source IP.  
**Fix (proposed):** randomise the probe ID per send, verify it (and the echoed question) in the response.

#### SEC-J4 — Blacklist XDP fast-path bypass (case / VLAN / compression) — MEDIUM (to confirm at pentest)
**Source:** [AI-INTERNAL] Claude + [AI-ADVERSARIAL] Gemini 2.5 Pro  
**Severity:** MEDIUM (provisional) **Status:** Open — confirm at pentest  
**Description:** The eBPF fast-block (`dns_xdp.c`) compares the raw wire QNAME against `dns_blacklist`. Three gaps make the fast-path match avoidable: (a) `extract_qname_key` (l.234) copies bytes **without lowercasing**, while `dns_qname_hash` (l.223) lowercases — so a mixed-case / DNS-0x20 query for a blacklisted name misses the map; (b) VLAN-tagged frames (l.311-345) redirect straight to XSKS, skipping the fast-block entirely; (c) a QNAME with a compression pointer changes the extracted key. **Severity hinges on whether the AF_XDP slow-path worker re-applies the blacklist** — if it does, these are fast-path-only (a perf/defence-in-depth loss); if it does not, they are real blocking bypasses. No explicit blacklist re-check was found in `worker.rs`. To be resolved empirically by the pentest (query a blacklisted name in upper-case / via VLAN and observe whether it is blocked).  
**Fix (proposed):** lowercase in `extract_qname_key`; apply the fast-block on the VLAN path; ensure the slow-path worker authoritatively enforces the blacklist.

#### SEC-J9 — Feed download is fully buffered in memory before parsing — MEDIUM
**Source:** [AI-ADVERSARIAL] Gemini 2.5 Pro  
**Severity:** MEDIUM **Status:** Open  
**Description:** `update_feed` (`feeds/mod.rs`) buffers the entire feed body in memory before parsing; a large (or attacker-influenced, if the feed URL is attacker-chosen) response can exhaust memory. Bounded only by the HTTP client defaults.  
**Fix (proposed):** stream-parse line by line with a hard size cap.

#### SEC-J12 — WebUI API-proxy path handling may reach internal endpoints — MEDIUM (to confirm)
**Source:** [AI-ADVERSARIAL] Gemini 2.5 Pro  
**Severity:** MEDIUM (provisional) **Status:** Open — needs code+pentest confirmation  
**Description:** Gemini reports the embedded WebUI proxy forwards client-controlled paths to the local API without normalisation, potentially reaching endpoints the UI should not expose. Not yet arbitrated line-by-line by Claude; flagged for confirmation and pentest.  
**Fix (proposed):** allow-list the proxied path prefixes; normalise/reject `..`.

#### SEC-J7 — TLS private keys written then `chmod` (non-atomic; brief world-readable window) — LOW
**Source:** [AI-ADVERSARIAL] Gemini 2.5 Pro  
**Severity:** LOW **Status:** Open  
**Description:** `ensure_relay_cert` (`sync.rs:173-176`) and `ensure_sync_cert` (`:586-589`) do `fs::write(key)` then `set_permissions(0o600)`; between the two the key sits at the umask default. Local-attacker TOCTOU.  
**Fix (proposed):** create with `OpenOptions::mode(0o600)` atomically.

#### SEC-J8 — ICMP rate-limiter off-by-one — LOW
**Source:** [AI-ADVERSARIAL] Gemini 2.5 Pro  
**Severity:** LOW **Status:** Open  
**Description:** `dns_xdp.c` ICMP handler uses `r->count >= cfg->rate_pps` to drop, allowing one extra packet per window vs the configured rate. Cosmetic.  
**Fix (proposed):** adjust the comparison / counter init.

#### SEC-J13 — API Unix-socket setup TOCTOU (local) — LOW
**Source:** [AI-ADVERSARIAL] Gemini 2.5 Pro  
**Severity:** LOW **Status:** Open  
**Description:** `main.rs` unlinks/creates the API Unix socket path with a TOCTOU window; a local attacker controlling the directory could influence file deletion. Socket path is admin-config.  
**Fix (proposed):** create in a root-owned dir with restrictive perms; avoid unlink-then-bind on an attacker-writable path.

#### SEC-J14 — Unbounded upstream addition via API (resource growth) — LOW
**Source:** [AI-ADVERSARIAL] Gemini 2.5 Pro  
**Severity:** LOW **Status:** Open  
**Description:** `add_upstream` (`upstreams.rs:380`) appends without a cap or dedup; a replayed/looped API call grows the upstream set and config. Authenticated only.  
**Fix (proposed):** cap the count, dedup on (addr, transport).

### Accepted (risk understood, kept this cycle)

- **SEC-J5 — Legacy header-only HMAC still accepted (`hmac_verify_with_ts`, `sync.rs:134-136`).** LOW. The body-covering MAC (SEC-I14) is verified, but the pre-v0.17.1 header-only MAC is also accepted for rolling upgrade — so body tampering is theoretically possible *if TLS is also defeated* (relay is TLS-pinned via `PinnedCertVerifier`). Defence-in-depth only. **Now removable** once the fleet is ≥ v0.17.1 — slated for SEC-J1's remediation batch. Gemini rated this HIGH assuming a cleartext MITM, which the pinned TLS layer prevents.
- **SEC-J6 — Anti-replay is a ±30 s timestamp window, no nonce cache (`sync.rs:126-130`).** LOW. Replay within 30 s is possible only behind a defeated pinned-TLS channel. Accepted as defence-in-depth; a nonce cache is a future hardening.
- **SEC-J10 — kernel slow-path TX length not re-clamped to the written length (`kernel_loop.rs`).** LOW. Gemini posited a stale-memory leak *if* a downstream builder returned a wrong length; no such bug exists, and the send already clamps `tx_lens[i].min(DNS_BUF_SIZE)`, bounding any read to the per-slot buffer. Accepted; an explicit clamp-to-written-length is cheap hardening.
- **SEC-J11 — Ring/UMEM size integer-overflow (`umem.rs`).** LOW. Sizes are admin-config and documented as validated to powers-of-two in `[64, 65536]` (l.32); within that range no overflow occurs, and the values are not network-controlled. Accepted pending a check that the bound is enforced before every size computation.

### Disputed (false positives — recorded with refuting evidence)

- **DISP-J1 — "Compressed-name parsing panic / DoS in `answer_from_cache`" (Gemini: HIGH).** Rejected. Gemini assumed `normalize_query_qname` interprets `0xC0` as a 192-byte label length and over-reads. In fact `normalize_query_qname` (`xdp/wire_builder.rs:235`) calls `simd::copy_lowercase_label`, which is a length-bounded byte copy+lowercase over the supplied slice (`src.len()`), with a scalar fallback `for &b in src {…}` — it never reads a label-length field, so `0xC0` is copied verbatim and there is no out-of-bounds access or panic. The crafted query merely cache-misses to the slow path. Model hallucination from the misleading "label" name.
- **DISP-J2 — "OS command injection via ACME hook" (Gemini: CRITICAL, main.rs/parser.rs).** Re-scoped, not a standalone finding. `hook_run` runs `Command::new(script)` directly (no shell), so there is no shell-metacharacter injection; and `ui-acme-hook` is set from the operator-controlled config file, not directly from the API. The only attacker path to control it is the SEC-J1 split-horizon config injection — tracked there as arbitrary-binary execution, not as independent command injection.

### Cycle J — live pentest validation (2026-06-13)

`[AI-INTERNAL]` Claude, against a **throwaway `xdp: no` instance** (isolated config + data dir, ports 1053/18080/18090 on a build host) — never against production. Attack vectors were taken from the `[AI-ADVERSARIAL]` Gemini code findings above; the pentest validated or refuted each empirically.

- **API authentication — solid.** `/api/stats`: no key → 401, wrong key → 401, valid key → 200.
- **SEC-J1 — CONFIRMED (HIGH stands).** `POST /api/split-horizon` with `name = "evilview\n    ui-acme-hook: \"/tmp/PWNED.sh\"\n#x"` was accepted (200) and the regenerated config contained a standalone line `    ui-acme-hook: "/tmp/PWNED.sh"` — arbitrary config-directive injection via the authenticated API, proven.
- **SEC-J2 — CONFIRMED (MEDIUM stands).** With no `webui-auth.conf`, `POST /login rb_user=admin&rb_pass=admin` returned `303 → /` with a valid `rb_session` cookie; a wrong password returned `/login?err=Invalid credentials`. Default `admin`/`admin` grants full WebUI access. Mitigations confirmed present: `HttpOnly; Secure; SameSite=Lax` cookie, CSRF token, 5/min login rate-limit.
- **SEC-J4 — DOWNGRADED MEDIUM → LOW (with evidence).** A blacklisted real domain returned `REFUSED` for **both** `example.com` and `EXAMPLE.COM` on the kernel slow path → the slow path enforces the blacklist **case-insensitively**, so the eBPF fast-path case/VLAN/compression gaps are caught downstream (a perf / defence-in-depth loss, not a blocking bypass). Side note found: a name that is also `local-data` is answered before the blacklist is consulted (local-data precedence) — minor, admin-self-contradictory config.
- WebUI session/CSRF/login-rate-limit defences: verified correct.

**Net:** the audit's one HIGH (SEC-J1) and the WebUI default-credentials MEDIUM (SEC-J2) are confirmed exploitable; SEC-J4 is downgraded with evidence; API key authentication is solid.

### Cycle J — remediation (PR #198, 2026-06-13)

Maintainer-approved; applied on `audit/v0.18-hardening` (**all changes outside the slow/fast DNS datapath**; 282 tests pass, clippy `-D warnings` clean):

- **SEC-J1 (HIGH) — Fixed.** Config writer escapes `name`/`subnet`/`local-data`; `add_split_horizon` rejects control/newline input (defence in depth).
- **SEC-J2 — Fixed.** Random one-time WebUI password (logged once, persisted) instead of `admin`/`admin`.
- **SEC-J3 — Fixed.** Random DNS transaction ID per probe, verified in the reply.
- **SEC-J5 — Fixed.** Legacy header-only HMAC fallback removed (body-covering only).
- **SEC-J7 — Fixed.** TLS private keys written atomically with mode 0600 from creation.
- **SEC-J13 — Fixed.** API Unix socket unlinked only if it is actually a socket.
- **SEC-J14 — Fixed.** `add_upstream` dedups on (addr, port, protocol) and is capped.
- **SEC-J9 — Closed, already mitigated** (#195): streaming read + 100 MiB cap.
- **SEC-J12 — Closed, false positive** (#196): `proxy_api` enforces auth + CSRF and blocks `..`.
- **SEC-J8 — Deferred:** touches the eBPF/XDP datapath (cosmetic off-by-one).
- **SEC-J6 / SEC-J10 — Accepted** (defence-in-depth, kept).

---

## Cycle I — v0.17.0 — two-AI competitive audit (kernel slow-path auto-tune + full surface re-review)

**Date:** 2026-06-11
**Sources:** `[AI-INTERNAL]` Claude Opus 4.8 × `[AI-ADVERSARIAL]` Gemini 2.5 Pro (independent per-file red-team; every Gemini finding re-verified against the source by Claude before acceptance).
**Scope:** v0.17.0 new code (kernel-UDP slow-path `sendmmsg`/auto-tune, `set_combined_queues` ioctl) plus a full re-review of the security-critical surface: `api/mod.rs`, `api/relay.rs`, `api/clients.rs`, `dns/ratelimit.rs`, `dns/kernel_loop.rs`, `config/parser.rs`, `config/writer.rs`, `webui/mod.rs`, `firewall/backend.rs`, `dns/xdp/socket.rs`.
**Method:** breadth from the adversarial model, severity calibrated against the actual defenses in the codebase (cert pinning, input control-char rejection, constant-time auth). Hallucinated or mis-rated findings are recorded as **Disputed** with the refuting evidence — not silently dropped.

### Fixed

| ID | Sev | Source | Finding | Fix |
|----|-----|--------|---------|-----|
| SEC-I1 | MEDIUM | Gemini | `verify_csrf` compared the CSRF token with `==` (timing oracle → token recovery → CSRF bypass). | `subtle::ConstantTimeEq` (webui/mod.rs). |
| SEC-I2 | LOW | Gemini | `handle_login` compared the username with `!=` (timing → admin username enumeration). | constant-time compare. |
| SEC-I3 | MEDIUM | Gemini | WebUI `/api` proxy forwarded the raw path; `reqwest` normalises `..`, escaping the `/api/` scope to other localhost endpoints. | reject paths containing `..`. |
| SEC-I4 | MEDIUM | Gemini | `render_config` embedded string values in double quotes without escaping (config-line injection at the serialization boundary). Gemini rated CRITICAL assuming RCE; **recalibrated**: the primary API vector (local-data) is already blocked by `validate_no_control_chars` (CRLF rejection), and injecting a directive needs a newline. | `escape_str` at the boundary for local-data / local-zone (belt-and-suspenders). |
| SEC-I5 | MEDIUM | Gemini | `relay_forward_handler` built the relayed path from a user segment without rejecting `..`; a slave could normalise it outside `/relay/`. Requires master-API auth (Gemini's HIGH → MEDIUM). | reject `..` in the relay path. |
| SEC-I6 | LOW | Gemini | Relay-forward error body returned `e.to_string()`, leaking the internal slave host:port. | generic body; full error stays in the WARN log. |
| SEC-I7 | MEDIUM | Gemini | `/api/clients/:ip` aggregated an unbounded per-IP domain map; remote random-subdomain flooding + an admin viewing the IP → memory exhaustion. | cap at 50 000 unique domains/IP. |
| BUG-I8 | LOW | Gemini | Rate-limiter token refill `self.rps * elapsed_ms` could overflow `u64` for an absurd configured `rps`. | `u128` math + `saturating_add`. |
| BUG-I9 | LOW | Gemini | Rate-limiter IPv4 `/0` prefix → `1u32 << 32` (debug panic; release produced the wrong mask). | explicit `/0` case + `u32::MAX << n`. |
| BUG-I10 | MEDIUM | Gemini | nftables backend passed `"proto dport port"` as a single `nft` argument → the rule never installs → port stays closed under a default-deny policy (silent availability loss). | pass `proto` / `dport` / `port` as separate tokens. |
| SEC-I11 | LOW | Gemini + Claude | v0.17.0 `sendmmsg` set `iov_len = resp_len` directly; the replaced `send_to(&buf[..n])` slice had bounds-checked it. A (hypothetical) oversized `resp_len` would make the kernel read past the frame (info leak). Confirmed as a real regression of the new code. | clamp `iov_len` to `DNS_BUF_SIZE`. |
| BUG-I12 | LOW | Gemini | `CPU_SET(core_id, …)` had no `CPU_SETSIZE` bound (stack write past `cpu_set_t` on a >1024-CPU host or an enumeration bug). | guard `core_id < CPU_SETSIZE`. |
| INFO-I13 | INFO | Gemini | `/api/clients` pagination `page * limit` could overflow `usize` (latent — immediately bounded by `.min(total)`, not reachable). | `saturating_mul` (hardening). |
| SEC-I23 | HIGH | Gemini + Claude | **Second pass.** Source-IP ACL (allow/deny/refuse) was not enforced on TCP/DoT/DoH: the per-IP-capped connection is relayed to the loopback hickory listener, so the request handler sees `127.0.0.1` — a client bypassed the ACL whenever loopback is allowed (the common default). Confirmed: `run_tcp_with_limit` applied only the connection cap, not `acl.check`. | Enforce `acl.check(src_ip)` on the real client before relaying; Deny/Refuse drop the connection (loopback follows the same ACL as UDP). |
| SEC-I24 | LOW | Gemini | **Second pass.** The slow-path auto-tune `xdp-interface` name flows into sysfs paths (`/sys/class/net/<iface>/…`) without validation; a config value like `../../tmp/x` could traverse out. Admin-config-controlled, not API — Gemini's HIGH recalibrated to LOW. | Reject path-bearing names (`/`, `..`, len>15) at the single parse choke point. |

### Accepted (risk understood, not changed this cycle)

| ID | Sev | Source | Finding | Rationale |
|----|-----|--------|---------|-----------|
| SEC-I14 | MEDIUM | Gemini | Relay HMAC signs `(method, path, ts)` but not the request body. | Mitigated by TOFU cert-pinned TLS master→slave (SEC-B1). Adding the body to the MAC is a wire-format change that breaks rolling master/slave upgrades; deferred to a versioned relay protocol. Gemini's CRITICAL (assumed cert verification disabled) is wrong — pinning is active once registered. |
| SEC-I15 | LOW | Gemini | `ufw` close-rule deletes by `port/proto`, not by comment tag. | `ufw` cannot delete by comment; nft/iptables use rule handles. Could remove a same-port admin rule on teardown — documented limitation. |
| SEC-I16 | LOW | Gemini | `write_config_atomic` uses a predictable `.tmp` filename (TOCTOU symlink). | Precondition is an attacker writable config dir = already-compromised host; dir is root-owned. |

### Open (enhancement)

| ID | Sev | Source | Finding |
|----|-----|--------|---------|
| OPEN-I17 | MEDIUM | Gemini | `/api/clients[/:ip]` scans the whole log buffer per request (CPU; localhost+auth only). Recommend background pre-aggregation. |
| OPEN-I18 | LOW | Claude | Serialization escaping (SEC-I4) was applied to local-data/local-zone; a full pass over every API-settable string field at the render boundary is recommended. Primary mitigation remains input-layer control-char rejection. |
| OPEN-I26 | LOW | Gemini→recal. | **Third pass (xdp/worker.rs).** `start_xdp_on_iface` passes the config `xdp-interface` name to `read_nic_rx_missed` (a `/sys/class/net/<iface>/…` read) without validation — same path-safety class as SEC-I24 but on the XDP setup path (the ioctls already call `sanitize_iface_name`). Gemini's HIGH "command injection" is refuted (the XDP path never shells out). Read-only, admin-config; recommend sanitizing the iface once at `start_xdp_on_iface` entry. |
| OPEN-I27 | LOW | Gemini | **Third pass.** `answer_from_cache` cache key = `hash(qname) ^ (qtype<<48)` ignores QCLASS, so a non-IN class query (e.g. CH) could match an IN entry — a correctness edge, not poisoning (the cache is filled from the server's own validated resolution). Fix requires a bilateral key change (lookup + population) + tests; deferred. |

### Disputed (false positives — recorded with refuting evidence)

| ID | Source | Claim | Refutation |
|----|--------|-------|-----------|
| DISP-I19 | Gemini (HIGH) | Arbitrary file R/W via `cfg_path` in backup/persist. | `cfg_path` is an operator-supplied startup argument, never attacker-controllable through the API — no privilege boundary is crossed. |
| DISP-I20 | Gemini (MEDIUM) | `ApiRateLimiter` doesn't update `last` every check → burst bypass. | Correct token-bucket behaviour: not advancing `last` when zero tokens accrue preserves fractional elapsed time. Updating it unconditionally (the proposed "fix") would *under*-refill and over-limit. Burst is by design. |
| DISP-I21 | Claude (suspected) | `cfg.alerts.last_mut().unwrap()` panics on a stray alert field. | Every call is preceded by the `ensure_rule` closure (parser.rs:609) that pushes a rule first; the vector is never empty. |
| DISP-I22 | Claude (suspected) | `normalize_ip` IPv6 `octets[keep_bytes+1..]` OOB for `/128`. | Guarded by `if keep_bytes < 16`. |
| DISP-I25 | Gemini (MEDIUM) | `domain_stats.inc` unbounded → OOM via random subdomains. | `DomainStats` is capped at `MAX_TRACKED = 10_000` (domain_stats.rs:16/65; test `idempotent_on_cap`). Bounded — no finding. |

### Verified-correct defenses (reviewed, no finding)

- **API bearer auth** (api/mod.rs:487): `constant_time_eq`, pre-comparison brute-force brake (sleep applied *before* the compare so it is not a timing signal), 429 lockout after 20 invalid attempts, audit events, RBAC write-gating.
- **AF_XDP `set_combined_queues` ioctl** (xdp/socket.rs): Gemini `NO_EXPLOITABLE_FINDINGS`; Claude concurs — sanitised interface name, mirrors the proven `auto_tune_nic_queues` SCHANNELS path.
- **kernel slow-path `sendmmsg` unsafe** (kernel_loop.rs): pointer lifetimes sound — pre-allocated scratch (never reallocated), ephemeral `&mut` immediately cast to raw, bounded slice/count ≤ BATCH.
- **`ratelimit::normalize_ip`**: IPv6 masking guarded (DISP-I22); IPv4 mask hardened (BUG-I9).

**Cycle I status:** 15 fixed, 3 accepted, 4 open (enhancement), 5 disputed. Three passes (security-critical files, then `server.rs`, then the untrusted-packet `xdp/worker.rs`). The one real high-impact issue (SEC-I23, ACL bypass on loopback-relayed TCP) is fixed; the third pass added two LOW correctness/defense-in-depth items (OPEN-I26/I27). Not a clean sweep — SEC-I14 (relay body MAC) is a real accepted gap, and OPEN-I17/I18 remain. Slow-path auto-tune (v0.17.0) introduced exactly one finding (SEC-I11), fixed.

### v0.17.1 — Open / Accepted remediation

The Cycle I Open and Accepted findings were revisited and fixed — all except SEC-I14 (see below):

| ID | Was | Now | Fix |
|----|-----|-----|-----|
| SEC-I16 | Accepted (LOW) | **Fixed** | `write_config_atomic` uses an unpredictable temp name + `O_EXCL` (`create_new`) — a pre-placed symlink cannot redirect the write. |
| SEC-I15 | Accepted (LOW) | **Fixed** | `ufw` close-rule deletes the exact rule (port/proto + our comment tag), falling back to the broad match on ufw versions that ignore the comment — no longer removes a same-port admin rule. |
| OPEN-I18 | Open (LOW) | **Fixed** | `escape_str` applied to every inline string field of `render_config` plus the user-facing settings (branding, block-page, webhook, tsig, acme, forward-zone, ui-tls-san), on top of local-data/local-zone. |
| OPEN-I26 | Open (LOW) | **Fixed** | `start_xdp_on_iface` validates the interface name once at entry (`sanitize_iface_name`) — the config value cannot traverse out of `/sys/class/net/`. |
| OPEN-I17 | Open (MEDIUM) | **Fixed** | `/api/clients` memoizes the sorted aggregation for 2 s — repeated authenticated requests cannot spin the CPU re-scanning the log buffer. |
| OPEN-I27 | Open (LOW) | **Fixed** | Both fast paths (`answer_from_cache`, `answer_dns_wire`) serve only class IN; a non-IN query (e.g. CH) falls through instead of getting an IN answer. |

**SEC-I14 (relay HMAC body) — Fixed (v0.17.1).** The relay HMAC now covers the request body (both receiver handlers buffer the body before verifying). Backward-compatible: a v0.17.1 verifier also accepts the legacy header-only signature, so a not-yet-upgraded peer still authenticates during a rolling upgrade (unit-tested: body coverage + tamper rejection + legacy fallback + wrong-key rejection). End-to-end relay not re-tested live (slave unreachable). **Deploy note: the relay is fully functional only once BOTH master and slave are >= v0.17.1.**

**Cycle I status (post-v0.17.1):** 22 fixed, 0 accepted, 0 open, 5 disputed.


---

## Audit status — v0.9.44

| Cycle | Scope | Auditor | Status |
|-------|-------|---------|--------|
| A | Core DNS, XDP, API | [AI-INTERNAL] Claude | Complete |
| B | Auth, relay, WebUI | [AI-INTERNAL] Claude | Complete |
| C | v0.9.3–v0.9.41 hardening | [AI-ADVERSARIAL] Claude + Gemini | Complete — 0 open findings |
| D | v0.9.43–v0.9.44 features | — | **Covered by Cycle E/F/G** — bot defense, alert hot-reload and IP SAN were audited in the later cycles |

**New attack surface since last audit (Cycle C, v0.9.41):**
- Bot defense engine (`src/webui/mod.rs`): honeypot detection, scanner trap, burst tracker — loopback/RFC-1918 self-ban fixed in v0.9.45; `burst_tracker` unbounded growth fixed in v0.9.45 (eviction every 5 min). Remaining: IP rotation attack flooding `blocked` map not yet mitigated.
- `SyncOp::AddGlobalBan` / `DeleteGlobalBan` — new relay operations; ban injection via compromised slave not evaluated
- `AlertTracker.update_rules()` — rules can now be replaced at runtime via hot-reload; concurrent modification behavior under load not audited
- `ui-tls-san` — attacker with config write access could add arbitrary SANs to the cert

Cycle D items were closed in the later cycles (E/F/G).

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


---

## Cycle E — [AI-INTERNAL] — 2026-05-26 — v0.9.58 (Webhook notifications)

**Scope:** src/webhooks.rs (WebhookDispatcher, WebhookTarget, delivery), src/api/mod.rs (AppState extension, POST /webhooks/test, reload_handler), src/config/parser.rs (webhook directives), src/main.rs (AppState construction).

### E-001 — INFO — SSRF via webhook URL: is_safe_url() validated

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Discovered** | 2026-05-26 |
| **Status** | No finding |

Description: send_once() calls is_safe_url() before any HTTP request. Rejects: non-http(s) schemes, loopback (127.x, ::1), private RFC1918 (10/8, 172.16/12, 192.168/16), link-local (169.254.x), metadata endpoints (metadata.google.internal, 169.254.169.254), .local hostnames, localhost. DNS rebinding not mitigated (no custom resolver on webhook client), but internal services are protected by IP check on initial URL parse.

Risk residual: DNS rebinding attack possible if attacker controls a domain that resolves to a private IP after the URL check. Probability: low in this deployment context.

---

### E-002 — INFO — Unbounded channel for webhook delivery queue

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **CWE** | CWE-400 (Uncontrolled Resource Consumption) |
| **Discovered** | 2026-05-26 |
| **Status** | Accepted |

Description: tokio::sync::mpsc::unbounded_channel is used for the delivery queue. If webhook targets are unreachable and many events fire (e.g., under a domain-blocking flood), the queue can grow unbounded. Each queued item is a (WebhookTarget, WebhookEvent) clone (~hundreds of bytes). Under extreme flooding: potential memory pressure.

Accepted: (a) Webhook targets are admin-configured, not user-supplied; (b) delivery task processes with retry+backoff (max 3x), not infinite retry; (c) most Runbound deployments have <10 events/min; (d) a bounded channel would drop events, which is worse UX.

---

### E-003 — INFO — config-reloaded event uses try_read()

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Discovered** | 2026-05-26 |
| **Status** | Accepted |

Description: reload_handler() fires config-reloaded webhook using s.webhook_targets.try_read(). If the lock is held (write in progress), the event is silently dropped. This is intentional to avoid blocking the reload response on webhook firing.

Accepted: Webhook delivery is best-effort by design. A missed config-reloaded notification is acceptable.

---

### E-004 — INFO — Webhook test endpoint fires with 0 targets (no auth bypass)

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Discovered** | 2026-05-26 |
| **Status** | No finding |

Description: POST /api/webhooks/test is protected by the same auth middleware as all other API endpoints (401 without valid bearer token). When no webhook targets are configured, it returns {"sent": 0}. Verified live: curl without auth -> 401, with auth and no targets -> {"sent": 0}.

---

## Findings Summary -- v0.9.58

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| E-001 | INFO | SSRF via webhook URL | No finding |
| E-002 | INFO | Unbounded delivery queue | Accepted |
| E-003 | INFO | config-reloaded silently dropped under lock | Accepted |
| E-004 | INFO | /webhooks/test without targets | No finding |


---

## Cycle F — v0.12.0 (Defense-in-depth hardening)

**Source:** [AI-ADVERSARIAL] Nexus (Gemini 2.5 Pro × Qwen3-Coder 30B), 2026-06-06.
**Scope:** documentation rigor, deployment hardening readiness, offensive attack surface.
**Maintainer review:** every *code* finding was verified against the source before classification. The raw AI report over-reported — three code findings are refuted below. The original report is preserved in git history (commit `90ef187`).

| ID | Claimed severity | Status | Finding |
|----|------------------|--------|---------|
| DOC-F1 | INFO | **Fixed** | "World's First ASM-Accelerated DNS Server" — unverifiable marketing claim removed from the README (Knot DNS has native XDP since 2020; dnsdist has DPDK). |
| DOC-F2 | LOW | **Fixed** | `SECURITY.md` and `THREAT_MODEL.md` were absent — both added. |
| SEC-F1 | HIGH | **Disputed (false)** | "DNS-over-TCP bypasses the blacklist." Refuted: the blacklist runs on the slow path (`src/dns/server.rs` local-zone lookup), shared by UDP **and** TCP — not XDP/UDP-only. |
| SEC-F2 | MEDIUM | **Disputed (false)** | "IP fragmentation bypass." Refuted: fragments are reassembled by the kernel and handled by the filtering slow path. |
| SEC-F3 | HIGH | **Disputed (false)** | "systemd hardening / privilege model missing." Refuted: the shipped `runbound.service` runs as non-root `runbound` with a scoped `CapabilityBoundingSet`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`. |
| SEC-F4 | MEDIUM | **Accepted (overstated)** | "No RRL → DNS amplifier." `ANY` queries are refused (RFC 8482) and per-IP query rate limiting exists. Strict Response Rate Limiting (RFC 5358) is tracked as an enhancement (OPEN-F3). |
| ACC-F1 | LOW | **Accepted** | The REST API uses a bearer token over localhost HTTP. Localhost-only binding mitigates; a Unix socket / localhost mTLS is tracked (roadmap). |
| OPEN-F1 | — | **Open** | No third-party human security audit yet (the AI pentester does not replace it). |
| OPEN-F2 | — | **Fixed (v0.15.0)** | Reproducible-build doc + minisign-signed releases (docs/BUILD.md, #171). |
| OPEN-F3 | — | **Open** | Strict RRL (RFC 5358) not implemented (ANY-block + per-IP limiting only). |
| OPEN-F4 | — | **Fixed** | `log-format: json` structured logs (#175). |
| OPEN-F5 | — | **Fixed (v0.15.0)** | CycloneDX SBOM generated in CI + attached to each release (#172). |

**Cryptography (documented during this cycle):** transport TLS via rustls 0.23 (TLS 1.2/1.3 only); WebUI argon2id; relay HMAC-SHA256 + anti-replay; optional HMAC-chained audit log.

Remediation items are the OPEN-F findings listed above. Verdict: real XDP performance and a sound Rust architecture; the remaining gap is trust paperwork (audit, reproducible build, SBOM), not code.

## Cycle G — v0.15.0 (Two-AI competitive audit)

**Date:** 2026-06-06
**Sources:** `[AI-INTERNAL]` Claude (Opus 4.8) · `[AI-ADVERSARIAL]` Qwen3-Coder-30B (local, on-GPU; no cloud — private repo never left the LAN) · `[AI-ADVERSARIAL]` Gemini 2.5 Pro (cloud, maintainer-authorised; critical files only)
**Method:** Independent passes (each model audited the source without seeing the other's output) followed by an adversarial cross-refutation round. Auditor #2 (Qwen) swept all 52 source files; Auditor #1 (Claude) reviewed the security-critical paths and then adjudicated every Auditor-#2 finding against the code and the BPF-verifier guarantees.

### Method outcome (recorded for honesty)

Auditor #2 produced **181 raw findings** (4 CRITICAL, 103 HIGH, 46 MEDIUM, 4 LOW, 24 INFO). After adversarial adjudication, the overwhelming majority were **false positives**: the model repeatedly (a) missed bounds/guards that already exist, (b) misread safe Rust idioms (`unwrap_or_else`, `str::get`, `String::into_bytes`) as panics/UB, (c) did not account for the **eBPF verifier**, which statically rejects any unbounded packet access, and (d) ignored existing access control. This is the expected high-recall / low-precision profile of an LLM auditor and is exactly why the second (refutation) pass exists. The genuine findings below are few and all low-impact.

> Per these conventions, non-security items surfaced by Auditor #2 (e.g. a low-resolution synthetic-SOA serial in `axfr.rs`) are **excluded** from this security audit as code-quality/correctness, not security.

### Findings

| ID | Severity | Location | Finding | Status |
|----|----------|----------|---------|--------|
| SEC-G1 | LOW | `src/dns/axfr.rs:30` | `cidr_matches`: for an AXFR-allow entry with prefix `/0`, `1u32 << (32 - 0)` = `1u32 << 32` — panics in a debug build, and in release the shift is masked so a `/0` matches **nothing** instead of everything (a fail-closed config foot-gun). | **Fixed** (clamp `prefix == 0 → mask 0`) |
| SEC-G2 | LOW | `src/api/relay.rs:35` | Relay TLS uses a `NoCertVerifier` (accepts any cert). Surfaced by both auditors (Qwen rated HIGH "MITM"). | **Open** (harden: offer out-of-band cert-fingerprint pinning to close the TOFU bootstrap window) |
| SEC-G3 | INFO | `src/sync.rs:101` | `hmac_verify_with_ts` compares content in constant time (`subtle::ConstantTimeEq`); the `zip` iterates the shorter length, a theoretical timing signal on **length only** — but the expected length is fixed (64 hex) and the result is a constant `false`. | **Disputed** (not exploitable) |
| SEC-G4 | LOW | `ebpf/dns_xdp.c:108` | ICMP-echo per-source-IP rate-limit LRU (65 536) can be churned by spoofed source IPs, evicting legitimate entries. | **Disputed** (opt-in, LRU-bounded, flood-ban map — bounded DoS of an optional feature, no meaningful impact) |
| SEC-G5 | INFO | `src/dns/hasher.rs:69`, `src/dns/simd.rs` | Hand-written `asm!` / raw-pointer SIMD kernels. Equivalence to a scalar reference is enforced by tests for all input lengths; the generic `unsafe` risk is a future caller passing a mis-sized buffer. | **Disputed** (asm/scalar equivalence exhaustively test-verified — not a vulnerability) |

#### SEC-G2 rationale (Open hardening item, not HIGH)

Auditor #2 rated the `NoCertVerifier` a HIGH MITM risk. Adjudication: it is **not** blanket MITM. Command **authenticity** is HMAC-SHA256 over `method\npath\nts` with a pre-shared sync key and a ±30 s anti-replay window (`src/sync.rs:101`, constant-time verify); after registration the relay client **pins the slave certificate fingerprint** (`pinned_client_config`, `src/api/relay.rs:240`), and the `/sync/cert` bootstrap endpoint is rate-limited (10/60 s/peer, `src/sync.rs:268`). The only residual exposure is the classic **TOFU first-contact window** — and even there a MITM cannot forge or replay commands without the HMAC key. Tracked as an **Open** hardening item: offer an out-of-band fingerprint pin so the first-contact window can be closed; state the bootstrap assumption in operator docs.

### Disputed (false positives from `[AI-ADVERSARIAL]` Qwen — representative)

| Reported | Severity (Qwen) | Why disputed |
|----------|-----------------|--------------|
| `ebpf/dns_xdp.c:253/310/415/424` "OOB read/write", "IP-options overflow", "IPv6 len" | CRITICAL | The BPF verifier rejects unbounded packet access; the checks already exist (`(void*)(dns+1) > data_end` at `:254`, `(icmp+1) > data_end` at `:311`, `(ip->ihl & 0xF) != 5 → XDP_PASS` at `:413` handles IP options, fixed 40-byte IPv6 at `:424`). |
| `ebpf/dns_xdp.c:481` "unbounded hash modulo → bad CPU routing" | HIGH | Explicit `if (cpu >= 64) return XDP_PASS;` guard at `:488`. |
| `src/api/mod.rs:1376` "TTL cast wraps, bypasses limits" | HIGH | `req.ttl < 0 || req.ttl > 2_147_483_647` is rejected **before** `as u32` (RFC 2181 §8). |
| `src/cpu.rs:155` "CPU_SET UB ≥ 1024" | HIGH | `if cpu_id >= 1024 { return; }` guard already present. |
| `src/dns/axfr.rs:56/108/128` "panics via unwrap" | HIGH | These are `unwrap_or_else` (the panic-free fallback), not `unwrap`. |
| `src/dns/axfr.rs:111` "unbounded AXFR allocation" | HIGH | Server's own zone data; gated by `is_transfer_allowed` (axfr-allow CIDR) first. |
| `src/api/mod.rs:1830` "schedule time OOB" | HIGH | `valid_hhmm` uses bounds-safe `str::get(..2)`/`get(3..5)` (SEC-AGV-02). |
| `src/audit.rs:171` "HMAC key UTF-8 panic" | HIGH | `String::into_bytes()` is infallible (a Rust `String` is always valid UTF-8). |
| `src/alerts.rs:120` "`epoch - now_epoch` overflow" | HIGH | `if epoch <= now_epoch { continue }` guard immediately above. |
| `src/blockpage.rs:61` "HTTP over-read/injection" | HIGH | Bounded `[u8; 4096]` read, `from_utf8_lossy`, slice `[..n]`. |

### Cycle G — two-model tally (Claude × Qwen; see three-model final tally below)

5 genuine findings, all LOW/INFO: **1 Fixed** (SEC-G1), **3 Disputed** (SEC-G3/G4/G5), **1 Open** (SEC-G2). **No Accepted** — residual items are either disputed as non-vulnerabilities or tracked Open for hardening. No CRITICAL/HIGH/MEDIUM confirmed. ~10 representative Auditor-#2 CRITICAL/HIGH findings explicitly **Disputed** as false positives. No active vulnerability identified in this cycle.

### Third auditor — Gemini 2.5 Pro (added)

A third independent adversarial pass was run with **`[AI-ADVERSARIAL]` Gemini 2.5 Pro** (cloud, maintainer-authorised, **critical files only** to bound exposure of the private repo). It was markedly more precise than Auditor #2: **18 findings** (1 CRITICAL, 5 HIGH, 8 MEDIUM, 4 LOW), **zero false eBPF bounds findings** (it was told the BPF verifier statically proves packet bounds). It **independently corroborated SEC-G2** (relay TLS, rated CRITICAL), strengthening the case to close the TOFU bootstrap window. It surfaced three items the other passes missed:

| ID | Severity | Location | Finding | Status |
|----|----------|----------|---------|--------|
| SEC-G6 | LOW | `src/dns/xdp/wire_builder.rs` (fast path) | A TSIG-signed A/AAAA query is answered by the wire fast path without TSIG validation. | **Disputed** — Runbound authorises queries by source-IP ACL, not TSIG (TSIG gates AXFR/updates, handled off the fast path); answering a public A record while ignoring an attached TSIG grants nothing beyond the ACL. Defensive note: fall back to hickory when a non-OPT additional record (e.g. TSIG, type 250) is present. |
| SEC-G7 | LOW | `src/sync.rs:306` (`record_slave`) | `connected_slaves` map has no eviction → slow unbounded growth. | **Open** — HMAC-gated (only authenticated slaves; keyed by IP, so bounded by distinct slave IPs) and the live view already filters to last-seen ≤ 5 min, but the backing map is never pruned. Harden: drop entries older than the window. |
| SEC-G8 | MEDIUM | `src/api/mod.rs` (`backup_import_handler`) | `std::fs::write(tmp, …)` follows a symlink pre-planted at the predictable tmp path → arbitrary file overwrite (precondition: write access to the service data dir + admin-authenticated import). | **Fixed** — tmp is now opened with `create_new` (`O_CREAT\|O_EXCL`); a planted symlink makes the write fail instead of being followed. Verified by build + manual review. |

The `axfr` "unbounded allocation" (raised by Auditors #2 and #3) remains **Disputed**: the buffered data is the server's own operator-loaded zone, and AXFR is gated by the `axfr-allow` CIDR list — not attacker-controlled in size.

### Cycle G final tally (three models)

8 genuine findings: **2 Fixed** (SEC-G1, SEC-G8), **4 Disputed** (G3, G4, G5, G6), **2 Open** (G2, G7). **No Accepted** (per maintainer convention: residuals are tracked Open or disputed as non-vulnerabilities, never "accepted"). No CRITICAL/HIGH stands after adjudication — the single CRITICAL (relay TLS) is the documented TOFU bootstrap window, tracked **Open** (SEC-G2). Recall vs precision: Qwen 181 raw → ~5 genuine; Gemini 18 raw → 3 net-new genuine; Claude adjudicated all and confirmed the critical-path defenses (constant-time key/HMAC compares, TOFU pinning, path-traversal guards, fast-path rate-limit + ACL, 4096 inflight cap).

---

## Cycle H — v0.16.0→v0.16.4 (two-AI adversarial — rate-limit/ban both-paths, DNSSEC AD, persistence)

**Date:** 2026-06-08
**Version audited:** v0.16.4
**Sources:**
- [AI-ADVERSARIAL: Claude Opus 4.8] — intra-model Red-team vs Blue-team "fighter" exchange, reasoned separately from implementation.

> **Honesty note (convention: re-audit = different model/session).** This cycle is a
> single-model Red/Blue adversarial exchange, **not** an independent second model. The
> empirical findings are grounded in live probing of the running master/slave + bench
> (auth, HMAC relay, input fuzzing, DNS malformed-input handling, resource limits). A genuinely
> independent model/human pass on the Open items below is still recommended (tracked with
> OPEN-F1, #170).

**Scope:** the attack surface added/changed in v0.16.x — per-source rate-limit on the
kernel slow path, banned-IP enforcement on both datapaths + the `/api/protection/banned`
+ blacklist API + master→slave propagation, persistent IP blacklist, the DNSSEC AD flag,
and the new `recvmmsg`/`sockaddr` unsafe receive path.

### SEC-H1 — `/health` is unauthenticated and discloses the exact version
**Severity:** LOW
**Source:** [AI-ADVERSARIAL: Claude Opus 4.8]
**File:** `src/api/mod.rs` (health route), live: `GET /health → 200`
**Status:** ✅ Fixed in v0.16.5 (version dropped from unauthenticated /health)
**⚔️ Red:** `GET /health` (no auth) returns `{"version":"0.16.4","cache_entries":42,"uptime_secs":362,"upstreams_total":4,"xdp_active":false,...}`. I fingerprint the exact build to target version-specific bugs and read operational state (cache size, uptime, upstream count) without credentials.
**🛡️ Blue:** `/health` is the only unauthenticated route (every `/api/*` and `/metrics` returns 401, verified). It exposes no secrets, keys, query data or client IPs — only liveness/operational counters, by design for load-balancer probes.
**Verdict:** Real but low-value disclosure. **Remediation proposed:** drop `version` (and detailed counters) from the unauthenticated `/health`, or gate them behind auth, keeping a bare `{"status":"ok"}` for probes.
**Residual risk:** Version fingerprinting via behavioural differences remains possible regardless.

### SEC-H2 — API bearer key timing side-channel
**Severity:** —
**Source:** [AI-ADVERSARIAL: Claude Opus 4.8]
**File:** `src/api/mod.rs:509,590`
**Status:** ⛔ Disputed (false positive)
**⚔️ Red:** Byte-by-byte `==` on the bearer token leaks length/prefix via response timing → recover the key.
**🛡️ Blue:** The comparison is `constant_time_eq(auth, expected)` backed by `subtle::ConstantTimeEq` (`ct_eq`). No early-exit; timing is independent of the match position.
**Verdict:** Not vulnerable. Red's premise refuted by code review.

### SEC-H3 — Relay TLS TOFU: first-connection MITM
**Severity:** MEDIUM
**Source:** [AI-ADVERSARIAL: Claude Opus 4.8]
**File:** `src/api/relay.rs` (TOFU cert fingerprint pinning)
**Status:** 🔵 Accepted (defense-in-depth mitigates)
**⚔️ Red:** Relay TLS pins the slave cert on first sight (TOFU). If I MITM the very first master↔slave handshake, I pin my own cert and become the relay channel.
**🛡️ Blue:** Even a MITM'd TLS session cannot forge relay operations: every relay request also carries an `HMAC-SHA256(sync_key, method+path+ts)` with a ±30 s replay window, verified constant-time (`hmac_verify_with_ts`). The attacker does not hold `sync_key`, so the TLS layer being compromised does not yield command injection — only observation of already-authenticated traffic.
**Verdict:** Accepted residual: a first-contact MITM can observe relay traffic but not forge it. **Remediation (optional):** out-of-band fingerprint provisioning to remove the TOFU window.
**Residual risk:** Confidentiality (not integrity) of relay traffic during a first-contact MITM.

### SEC-H4 — Forge / replay of relay commands (ban poisoning, config injection)
**Severity:** —
**Source:** [AI-ADVERSARIAL: Claude Opus 4.8] — empirical
**File:** `src/sync.rs:103,1592` (`hmac_verify_with_ts`), slave relay listener `:8082`
**Status:** ⛔ Disputed (false positive — empirically rejected)
**⚔️ Red:** POST forged `/relay/alerts/blocked/<ip>` to the slave to ban arbitrary IPs (DoS legit clients) or push config. Tried: no headers, forged sig, replayed old timestamp, empty sig, plain-HTTP.
**🛡️ Blue (measured on the live slave):** no headers → 401; forged `x-runbound-sig` → 401; replay (ts=1e9) → 401; empty sig → 401; plain HTTP on `:8082` → connection refused (TLS required). The forged IP **never** appeared in the slave's `/api/protection/banned` (`count:0`).
**Verdict:** Not vulnerable. All forge/replay vectors rejected.

### SEC-H5 — Rate-limit / ban table exhaustion via spoofed-source flood
**Severity:** LOW
**Source:** [AI-ADVERSARIAL: Claude Opus 4.8]
**File:** `src/dns/ratelimit.rs` (MAX_RATE_LIMIT_BUCKETS), `ebpf/dns_xdp.c` (`icmp_banned` LRU 65536)
**Status:** 🔵 Accepted (bounded)
**⚔️ Red:** Flood from a huge set of spoofed source IPs to inflate the per-source rate-limit bucket map and the ban map → memory exhaustion, or eviction of legitimate clients' buckets.
**🛡️ Blue:** Rate-limit buckets are capped (`MAX_RATE_LIMIT_BUCKETS`) with aggressive idle-eviction *before* refusing a new IP, and a time-based GC retains only buckets seen in the last 60 s. The ban map is a fixed `BPF_MAP_TYPE_LRU_HASH` (65536). Memory is bounded by design.
**Verdict:** Accepted. Bounded memory; under an extreme spoofed-IP flood a transient eviction of cold buckets is possible (a deliberate availability-over-fairness trade-off).

### SEC-H6 — DNSSEC AD flag never set (validation not signalled to clients)
**Severity:** MEDIUM
**Source:** [AI-ADVERSARIAL: Claude Opus 4.8]
**File:** `src/dns/server.rs` (forward response builder)
**Status:** ✅ Fixed in v0.16.3
**⚔️ Red:** You advertise `dnssec-validation: yes` and return RRSIGs, but the response header never sets `AD`. A DNSSEC-aware client cannot distinguish validated data from spoofed/insecure data → silent downgrade.
**🛡️ Blue:** Fixed v0.16.3 — the forward path now sets `authentic_data` when validation is on **and** the answer is `Secure` (hickory per-record proof; Bogus already SERVFAILs). Verified live: `ietf.org` → `ad`; unsigned `google.com` → no `ad`; a node with validation off correctly omits it.
**Verdict:** Fixed. AD now faithfully reflects validation state.

### SEC-H7 — Rate-limit and bans not enforced on the kernel slow path (xdp:no)
**Severity:** HIGH (pre-fix)
**Source:** [AI-ADVERSARIAL: Claude Opus 4.8]
**File:** `src/dns/kernel_loop.rs`, `src/dns/xdp/worker.rs` (shared `rl_should_drop`), `src/icmp.rs` (`is_banned`)
**Status:** ✅ Fixed in v0.16.2
**⚔️ Red:** In `xdp: no` (the production mode), the kernel fast loop served cache hits through the wire/cache responder without consulting the rate-limiter *or* the ban set. A single source floods cached answers unthrottled (1000 queries → 928 served at `rate-limit:200`), and a "banned" IP keeps being served (ban evasion / DoS).
**🛡️ Blue:** Fixed v0.16.2/v0.16.4 — a shared `rl_should_drop` gate and `icmp_stats.is_banned()` are now called on **both** datapaths driven by the same `RateLimiter`/ban set (one mechanism, two routes, like the blacklist). Verified: 1000 → ~100–200 served; banned source's `dig` → dropped; unban → restored. Zero per-packet cost when disabled (atomic short-circuit).
**Verdict:** Fixed. This was the most serious finding of the cycle; it predated v0.16 (rate-limit) and was XDP-only for bans.

### SEC-H8 — New `unsafe` receive path (`recvmmsg` + `sockaddr` parse)
**Severity:** LOW
**Source:** [AI-ADVERSARIAL: Claude Opus 4.8]
**File:** `src/dns/kernel_loop.rs` (recvmmsg batch, `sockaddr_to_std`)
**Status:** ✅ Fixed in v0.16.5 (parse edge-case tests; full cargo-fuzz follow-up)
**⚔️ Red:** v0.16.1 added `unsafe` libc `recvmmsg` + raw `sockaddr_storage` parsing on the hot path. A crafted/edge source address or short message could trigger UB or a panic-DoS.
**🛡️ Blue:** Review found no exploitable path: buffers are fixed `DNS_BUF_SIZE`, `iov_len` bounds the copy, `sockaddr_to_std` accepts only `AF_INET`/`AF_INET6` (else `None` → datagram skipped), and `MSG_WAITFORONE` avoids partial-batch stalls. No attacker-controlled length reaches beyond the buffer.
**Verdict:** No proven vulnerability, but it is new `unsafe` surface. **Remediation proposed:** add a fuzz target (cargo-fuzz) and a MIRI run over `sockaddr_to_std` + the batch loop.
**Residual risk:** Unreviewed `unsafe` edge cases until fuzzed.

### SEC-H9 — Persistent IP blacklist file permissions / growth
**Severity:** LOW
**Source:** [AI-ADVERSARIAL: Claude Opus 4.8]
**File:** `src/icmp.rs` (`persist_blacklist` / `load_blacklist`, `<base>/ip-blacklist.json`)
**Status:** ✅ Fixed in v0.16.5 (file 0600 + 100k entry cap)
**⚔️ Red:** The blacklist is written with default permissions (world-readable 0644) and reloaded at boot — a local unprivileged user can read the ban list; an API caller can blacklist unbounded IPs growing the file; a local writer could inject bans.
**🛡️ Blue:** Writing requires the `runbound` user (local), and entries are validated IPs parsed on load (no injection of arbitrary content). It is not a remote vector beyond the already-authenticated API.
**Verdict:** Low. **Remediation proposed:** write the file `0600`, and cap the persisted entry count.
**Residual risk:** Local read of the ban list; file growth under sustained authenticated blacklisting.

### SEC-H10 — Slave runs without DNSSEC validation
**Severity:** INFO
**Source:** [AI-ADVERSARIAL: Claude Opus 4.8]
**File:** slave `runbound.conf` (no `dnssec-validation`)
**Status:** ✅ Fixed in v0.16.5 (slave dnssec-validation: yes — matches master)
**⚔️ Red:** The slave forwards without validating; it can serve spoofed-upstream data and never sets `AD`.
**🛡️ Blue:** Configuration choice; the slave forwards to validating DoT upstreams. Enable `dnssec-validation: yes` on the slave for end-to-end validation + `AD`.
**Verdict:** Accepted; operator action recommended.

### SEC-H11 — L3 flood saturating the NIC (PCIe-2.0 RX)
**Severity:** INFO
**Source:** [AI-ADVERSARIAL: Claude Opus 4.8]
**Status:** 🔵 Accepted (out of application scope)
**⚔️ Red:** A raw packet flood saturates the X520 RX (PCIe 2.0 ceiling ~10 M pps) and legitimate queries are dropped at the NIC before any app logic runs.
**🛡️ Blue:** Per-source rate-limit and bans shed abusive *DNS* sources, but a network-layer volumetric flood is mitigated upstream (filtering / DDoS scrubbing), not by the resolver.
**Verdict:** Accepted; network-layer concern outside the DNS application.

### Cycle H summary
| Status | Findings |
|--------|----------|
| ✅ Fixed | SEC-H6 (DNSSEC AD), SEC-H7 (rate-limit/ban both-paths) |
| 🔵 Accepted | SEC-H3 (relay TOFU), SEC-H5 (table exhaustion), SEC-H10 (slave DNSSEC), SEC-H11 (L3 flood) |
| ✅ Fixed (v0.16.5) | SEC-H1 (health version), SEC-H8 (recvmmsg parse tests), SEC-H9 (blacklist 0600+cap), SEC-H10 (slave DNSSEC=master) |
| ⛔ Disputed (false) | SEC-H2 (key timing — constant-time), SEC-H4 (relay forge/replay — rejected) |

No CRITICAL or HIGH finding is open. The two pre-existing serious issues (SEC-H6, SEC-H7) were fixed in v0.16.2/v0.16.3. Three LOW Open items have proposed remediations awaiting maintainer approval. Strengths confirmed by probing: constant-time bearer auth, HMAC+TLS relay (forge/replay rejected), least-privilege systemd unit (non-root `runbound` user, minimal capabilities, `NoNewPrivileges`/`ProtectSystem=strict`), bounded rate-limit/ban tables, and only `/health` unauthenticated.

### Cycle H — independent second-model pass (Qwen3-Coder-30B, local)

**Date:** 2026-06-08
**Source:** [AI-ADVERSARIAL: Qwen3-Coder-30B-A3B — local, llama.cpp on an RTX 5080], independent of the Claude implementation/audit. Fed the `v0.16.0..HEAD` diff of the security-sensitive files; five findings, each cross-checked against the code by [AI-INTERNAL: Claude Opus 4.8] (every claim verified, not taken at face value).

| Qwen finding | Qwen sev | Cross-check verdict |
|---|---|---|
| Q1 — unsafe `recvmmsg` sockaddr parse | HIGH | Overstated. `ss_family` is validated (`AF_INET`/`AF_INET6` else `None`) and the path is fuzzed (1M iters, SEC-H8). Accepted as generic `unsafe`, not HIGH. |
| Q2 — `load_blacklist` has no entry cap | MEDIUM | **Valid (LOW) → Fixed v0.16.6.** The write path was capped (100k) but the load path was not; load now also caps at 100k. Independent model caught a real defense-in-depth gap. |
| Q3 — `banned_present` atomic race | MEDIUM | Accepted (benign): a sub-microsecond fail-open window; worst case one query from a just-banned IP slips through before the flag settles. |
| Q4 — blacklist file permissions | LOW | Already handled: `set_permissions(0o600)` runs after the write (verified `-rw-------`). |
| Q5 — `is_banned` logic error | MEDIUM | Disputed (false): `banned_present && contains_key` is correct — the flag is a fast-skip hint, the map is authoritative. |

**Outcome:** the independent model **confirmed SEC-H8** and surfaced **one genuine gap (Q2)**, fixed in v0.16.6. The other four were overstated, already-handled, or false on cross-check — consistent with the known local-model false-positive rate; every claim was verified against the code and the live system, none accepted blindly.
