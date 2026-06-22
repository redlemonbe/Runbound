# de-hickory feature-parity review — v0.22.0 (`feat/dehickory`) — 2026-06-22

**Source:** [AI-INTERNAL] Claude Opus 4.8 — triggered by a dead-code / optimization pass
(`cargo clippy`). The 21 default-build dead-code warnings turned out to be **symptoms**:
several features lived only in the (default-disabled) `recursor` handler and were never
ported to the wire serving path (`serve_wire`), so they were **silently inactive in the
shipped binary** (`default = ["xdp"]`, no `recursor`).

Method: compared the default and `--features recursor` warning sets; every symbol unread in
default but read in recursor was traced to its consumer; consumers were all inside
`#[cfg(feature = "recursor")]` methods (`record_query`, `resolve_upstream`).

| ID | Severity | Status | Finding |
|---|---|---|---|
| PAR-1 | HIGH | ✅ Fixed | **Query logging dead in the default build.** `log_buffer.push_query` was called only by the recursor `record_query`; `serve_wire` emitted nothing, so the webui Logs panel / `GET /api/logs` were **always empty** in the shipped binary. Fixed: `serve_wire` now logs every resolved query (Local / Forwarded / Cached / Nxdomain / Servfail) via a wire-native `log_query_wire` (sanitised name, MED-06). ACL/RRL/cookie refusals are intentionally **not** logged on the hot path (one alloc per spoofed packet under flood). **Live-proven:** `dig` → `/api/logs` returns the queries (was empty before). |
| PAR-2 | MEDIUM | ✅ Fixed | **serve-stale (#108, RFC 8767) dead in the default build.** `stale_cache` was hickory-typed, fed and served only by the recursor; `serve_wire` returned SERVFAIL on a transient upstream failure without consulting it. Fixed: added a wire-native `stale_cache_wire`, populated on every successful forward and served (TTL→`stale_answer_ttl`) on a transient `Servfail` when `serve-stale: yes`. The hickory `stale_cache` is now `#[cfg(feature = "recursor")]`. |
| PAR-3 | MEDIUM | ✅ Fixed | **resolv.conf emergency fallback (#94) never activated by default.** The recovery loop runs unconditionally, but the *activation* trigger (`all_non_temporary_unhealthy` → `add_resolv_fallback` → pool rebuild) lived only in the recursor path, so a total-upstream-outage was never rescued in the shipped binary. Fixed: ported the wire-native activation block (CAS-guarded, off-hot-path spawn, `rebuild_and_swap`) into `serve_wire`'s `Servfail` arm. |
| PAR-4 | LOW | ✅ Fixed | **`racing_wins` metric (#33) not recorded by default.** Racing itself works (inside `ForwardPool`), but `serve_wire` discarded the winner. Fixed: the winning upstream is now recorded. |
| PAR-5 | LOW | ✅ Fixed | **top-domains (#5) missed slow-path queries.** `domain_stats.inc` ran only in the kernel loop (XDP hits) and the recursor; noxdp forwarded/local queries were absent from `GET /api/stats/top-domains`. Fixed: `serve_wire` now counts every resolvable query. |
| PAR-6 | LOW | 🟡 Open | **prefetch is an incomplete feature (not a de-hickory regression).** `PrefetchTracker::increment` is called only on the recursor path and **no executor anywhere drains it** (`take_hot` is test-only) — prefetch counts but never pre-resolves, in *both* builds. Not ported (porting `increment` alone would still pre-resolve nothing). Needs a prefetch loop before it does anything. Marked `allow(dead_code)`. |
| PAR-7 | INFO | 🟡 Open | **DDR (#204, RFC 9462) not ported.** `DdrInfo::svcb_records` returns hickory records; the `_dns.resolver.arpa` SVCB synthesis is recursor-only. Porting needs a wire-native SVCB builder. Marked `allow(dead_code)`. |
| PAR-8 | INFO | 🟡 Open | **Forward-path DNSSEC AD tracking + slow-path negative caching not ported.** `dnssec_enabled` (forward AD/validation tracking) and `ResolveResult::neg_ttl` (negative cache) are recursor-only on the slow path. Local signed zones (`zone_signer`) and the XDP negative cache are unaffected. Marked `allow(dead_code)`. |

**Dead-code cleanup (the original task):** of 21 default-build warnings, 1 was truly dead
(`parse_local_data` import — removed), 1 was test-only (`is_ksk` → `#[cfg(test)]`); the rest
were recursor-only consumers, now either revived by the ports above or marked with the
codebase's existing convention `#[cfg_attr(not(feature = "recursor"), allow(dead_code))]`
(DNSSEC stat methods follow the `inc_dnssec_bogus` precedent: `#[cfg(feature = "recursor")]`).
Result: **0 dead-code/unused warnings** in both the default and the `recursor` build.

**Verification.** `cargo clippy` clean (both builds); `cargo test --release --bin runbound`
**410 passed / 0 failed**; live `dig` against the default binary populates `/api/logs`
(PAR-1 proven) and resolves (`example.com`, `cloudflare.com`). XDP/eBPF datapath untouched.
