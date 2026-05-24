# Numerical Performance Claims — Review Checklist

Audit date: 2026-05-24  
Scope: all files in `docs/*.md` and `README.md`  
Purpose: track status of every numerical performance claim (QPS, latency, throughput, %) — backed, theoretical, or unverified.

---

## Status key

| Tag | Meaning |
|-----|---------|
| ✅ MEASURED | Backed by a linked benchmark report with raw data |
| (theoretical) | Derived from instruction counts / hardware specs — no end-to-end measurement |
| [UNVERIFIED] | Plausible but not yet measured; planned for v0.8 benchmark |

---

## docs/benchmark-2026-05-20.md

All numbers in the raw results tables are ✅ MEASURED (dnsmark 0.4.5 output, AMD Threadripper PRO 5995WX / Emulex be2net client, 2026-05-20).

| Claim | Value | Status | Action |
|-------|-------|--------|--------|
| QPS ceiling — all three servers | 128 000 QPS | ✅ MEASURED | Leave |
| Runbound sustained p99 | 0.232 ms | ✅ MEASURED | Leave |
| BIND9 sustained p99 | 0.210 ms | ✅ MEASURED | Leave |
| Unbound sustained p99 | 0.078 ms | ✅ MEASURED | Leave |
| Runbound stress p99 | 0.232 ms | ✅ MEASURED | Leave |
| BIND9 stress p99 | 0.225 ms | ✅ MEASURED | Leave |
| Unbound stress p99 | 0.170 ms | ✅ MEASURED | Leave |
| Consumer router QPS ceiling | 1 000 QPS, 12.02% loss | ✅ MEASURED | Leave |
| Consumer router vs bare metal latency ×390 / ×145 | derived from measured data | ✅ MEASURED | Leave |
| AF/XDP "Expected range: 500 000 – 14 000 000 QPS" | future benchmark | [UNVERIFIED] | Annotated |

---

## docs/performance.md

Same underlying benchmark data as above — summary view.

| Claim | Value | Status | Action |
|-------|-------|--------|--------|
| All QPS / latency results tables | Same as benchmark-2026-05-20.md | ✅ MEASURED | Leave |
| AF/XDP "Expected range: 500 000 – 14 000 000 QPS" | future benchmark | [UNVERIFIED] | Annotated |
| "14.88 M 64-byte packets/second" wire speed | 10GbE physical limit | (theoretical — physics) | Leave (context is clear) |
| Verbosity 2 p99 13× multiplier | "p99 rises from 0.23 ms to 3.01 ms under stress" | ✅ MEASURED (benchmark-2026-05-20.md §verbosity) | Leave |

---

## docs/internals.md

| Claim | Value | Status | Action |
|-------|-------|--------|--------|
| Timing budget per stage (~50–200 ns) | theoretical | (theoretical) — section intro labels them | Leave (already labeled) |
| Total hot-path ~930 ns ≈ 1 µs/query | theoretical | (theoretical) — section 6 labeled | Leave |
| 1 M QPS/core | theoretical | (theoretical) — section 7 labeled | Leave |
| 7.6 M QPS with 8 workers | theoretical | (theoretical) — section 7 labeled | Leave |
| 25 M QPS with wire-format cache (planned) | theoretical | (theoretical) — section 7 labeled | Leave |
| 14.88 M packets/s wire speed | 10GbE physical limit | (theoretical — physics) | Leave |
| IRQ affinity gain: 1–3% throughput | estimated | (theoretical) | Annotated |
| IRQ affinity gain: −1–5 µs latency variance | estimated | (theoretical) | Annotated |
| NUMA gain: −30–40 ns/packet | estimated | (theoretical) | Annotated |
| TX batching gain: +10–15% throughput | estimated | (theoretical) | Annotated |
| Wired-format cache planned hot path: <300 ns | future/planned | (theoretical) — in planned section | Leave |
| NIC ring at 10 M QPS → 51 µs tolerance | derived calculation | (theoretical) | Leave (derivation shown inline) |

---

## docs/xdp.md

| Claim | Value | Status | Action |
|-------|-------|--------|--------|
| XDP fast path latency "<1 ms (below dnsmark resolution)" | corrected claim | (architectural) | Leave |
| VM virtio: ~500k–1M QPS | estimated | (theoretical) — already labeled "(theoretical)" in file | Leave |
| Bare metal Intel 10GbE: TBD | pending | [UNVERIFIED] | Already labeled TBD |
| 14.88M 64-byte packets/s wire speed | 10GbE physical limit | (theoretical — physics) | Leave |
| NIC ring at 10 M QPS → 51 µs tolerance | derived | (theoretical) | Leave |

---

## docs/security-audit.md

| Claim | Value | Status | Action |
|-------|-------|--------|--------|
| "5 M QPS target is achievable" | executive summary claim | [UNVERIFIED] | Annotated |

---

## README.md

| Claim | Value | Status | Action |
|-------|-------|--------|--------|
| AF/XDP throughput | "TBD — benchmark in progress" | [UNVERIFIED] | Already corrected |
| XDP fast path latency | "<1 ms (below dnsmark resolution)" | (architectural) | Already corrected |
| "scales linearly with cores" (SO_REUSEPORT mode) | architectural design | (theoretical) | Mentioned without numbers — leave |

---

## Summary

| Category | Count |
|----------|-------|
| ✅ MEASURED — backed by benchmark-2026-05-20.md | ~15 values |
| (theoretical) — labeled or annotated | ~12 values |
| [UNVERIFIED — pending v0.8 benchmark] — annotated | 3 values |

All `[UNVERIFIED]` annotations were added in commit `docs: audit numerical performance claims across docs/`.  
Tracked in GitHub issue [#101](https://github.com/redlemonbe/Runbound/issues/101): Bare-metal AF/XDP performance measurement plan — v0.8.
