# Runbound — Double-pass security audit round 2 (2026-07-07)

**Cycle label:** `[AI-ADVERSARIAL]`
**Target:** branch `v0.9.2`, HEAD `2fc1bd2` (pre-fix); fixes landed in this cycle.
**Scope:** re-audit after the auto-ban hardening, the live-editable DNS rate limiter (AtomicU64),
the alert per-rule refactor, and the optimisation pass (serve-stale eviction, `AlertTracker::record`,
`feeds` count). Four independent adversarial AI auditors on disjoint surfaces
(memory-safety/crash/DoS, DNSSEC integrity/cache-poisoning/ban-bypass, injection/RCE/SSRF,
auth/authz/relay), each required to produce a concrete reproducible trigger; every candidate
re-verified at the source before acceptance. Prior cycles (`SECURITY-AUDIT.md`,
`AUDIT-2026-07-07-double-pass.md`, `QMIN-231`, `PENTEST-2026-07-06`) read first, their
Fixed/Accepted/Disputed items excluded.

No CRITICAL or HIGH finding. Data-path fuzzed again (`Message::parse` 4,752,246 exec / 0 crash;
name decompression 520,047 / 0 crash). One MEDIUM ban-enforcement gap and two hardening items.

---

## Findings

### SEC-2026-07-O — MEDIUM — Alert-rule `block` ban not mirrored into `icmp_stats` (bypassed on cache hits under `xdp: no`) — **Fixed**

`AlertTracker::trigger()` `"block"` arm (`src/alerts.rs`) inserted into `alert_tracker.blocked` and
called `xdp_push()` (a no-op when `xdp: no`) but did **not** add the IP to `icmp_stats.banned`. The
kernel-UDP fast path (`kernel_loop.rs:358`) and the XDP cache-hit path only consult
`icmp_stats.is_banned()`, not `alert_tracker`. So on an `xdp: no` node (the production master), an IP
banned by an operator's `action: block` alert rule was still served for any cached name (the bulk of
a resolver's UDP traffic); the ban only bit on cache-miss (slow-path fallback) and on DoT/DoH/DoQ.

- **Trace:** node `xdp: no`; rule `metric=client-qps window_s=10 threshold=100 action=block`; attacker
  IP X floods >100 q/10s with a valid server DNS cookie (verified=true) → banned in `alert_tracker`
  only → X then queries a cached name → kernel-loop fast-path B answers (checks only `icmp_stats`) →
  served.
- **Why MEDIUM:** partial bypass of an explicitly-configured abuse mitigation; no DNSSEC-integrity
  impact; gated on the operator having a `block` rule. The manual / bot / relay ban paths already
  double-write both systems (SEC-H7 lineage); this one automatic path was missed.
- **Fix:** wire `icmp_stats` into `AlertTracker` (unconditional `set_icmp_stats`, OnceLock) and, in the
  `block` arm, `icmp_stats.ban(ip, BanSource::Bot)` after the `blocked.insert` — same as the bot path.
  Idempotent; no-op when no rule fires.

### SEC-2026-07-P — LOW — Live `rate-limit-burst: 0` (rps>0) refuses all non-loopback traffic — **Fixed**

`RateLimiter::set_limits` stored `burst` verbatim. `PATCH /api/config {"rate_limit":N,"rate_limit_burst":0}`
(N>0) left every non-loopback bucket at `tokens=0` forever (tokens never refill above `burst`) → a
self-inflicted DoS. Authenticated (admin bearer, RBAC-gated — see SOLID below), so an operator
foot-gun, not an unauthenticated vector. Fixed by clamping `burst.max(1)` when `rps>0` in `set_limits`.

### SEC-2026-07-Q — LOW — `Role::may_write` prefix match grants `/api/dns*` beyond `/api/dns/` — **Fixed**

`path.starts_with("/api/dns")` also matches `/api/dnssec*` / `/api/dns-*`. Inoffensive today
(`/api/dnssec/ds` is GET-only, never `may_write`-checked; no write-only admin route begins with
`/api/dns`), but a latent trap: a future write endpoint under `/api/dnssec` would be reachable by the
`Dns` role by accident. Fixed to a segment-aware match (`path == base || path[base..].starts_with('/')`)
for dns/zones/blacklist/feeds. Defence-in-depth, zero runtime cost.

---

## Accepted (understood residual)

- **INFO-1 — PROXY-v2 header-sized allocation** (`server.rs:2157`): `read_proxy_v2` allocates a peer-
  controlled `u16` length (≤64 KiB/connection, bounded by `TCP_CONN_PER_IP_MAX`). `proxy-protocol` is
  off by default and, when on, the peer is a trusted L7 proxy in front — not an arbitrary client.
  Optional hardening (validate `len` against expected AF sizes) not taken. Accepted.
- **INFO — `add_split_horizon` does not validate `local_data.rr`** (the writer escapes it, proven
  non-exploitable by the injection lane); aligning input validation across the three fields is a
  defence-in-depth nicety, not a finding. Accepted as-is.

## Disputed (candidate refuted at source)

- **"CPU-DoS via `parse_opt_rr` arcount"** — refuted. The EDNS option loop is O(1) per iteration (a few
  bounds-checked reads) and `pos += 10 + rdlen` overruns immediately on a truncated packet, so a forged
  large arcount yields ~65k trivial sub-microsecond ops, not a DoS. Recorded with the refuting analysis.

---

## Verified solid (attacked, no bypass)

- **Memory safety:** all wire parsers length-checked (fuzzed 4.75 M exec, 0 crash); recursor budgeted;
  DNSSEC denial/verify bounds-checked and fail-closed (NSEC3 iterations capped); rkyv cache load is the
  validating path; DoQ/DoH bounded; SIMD asm guarded; ACL free of shift UB.
- **DNSSEC / poisoning:** Bogus never served (except CD=1) and **never cached** (all 4 sites); AD only
  on Secure+DO; compact-denial NODATA→NXDOMAIN gated on a validated in-bailiwick NSEC; serve-stale
  eviction now the true-oldest and only filled from a real upstream Answer.
- **Ban integrity:** every ban path routes through a central insert with loopback/unspecified exemption
  + caps (`MAX_BANNED=100k`, `MAX_BLOCKED_ENTRIES=50k`, `MAX_CLIENT_BUCKETS=100k`); `record()` escalates
  only verified sources → an off-path spoofer cannot get a victim IP banned; relay ban/unban is
  HMAC-verified (forge/replay/stale-ts all 401 in live tests) with TOFU cert-pinning (re-pin rejected).
- **Injection/RCE/SSRF:** config-injection blocked by three layers (control-char reject → `escape_str`
  → write-then-reparse gate, parser line-based); `Command::new` sites shell-free with validated argv;
  path traversal blocked (backup/feed/config `O_EXCL`); feeds + webhooks + relay SSRF-safe
  (HTTPS-only, anti-rebinding re-resolve, private-IP blocklist, 100 MiB cap).
- **Auth/authz:** RBAC allowlist fail-closed, measured across 4 roles — `PATCH /api/config`
  (rate-limit), ban/unban, blacklist, rotate-key, users, backup all admin-only (403 for Read/Dns/Op);
  bearer constant-time + 20→429 brake; WebUI CSRF bound to server session (constant-time), argon2
  always-run; no secret leaked by `/api/system` or `/api/config`.

## Validation

Build clean, `cargo clippy --release` zero warnings, `cargo test --release` 468 passed / 0 failed.
Hot path untouched; no re-bench required for this cycle.
