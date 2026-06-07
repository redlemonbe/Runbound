# 08 — Performance

> **Status: draft outline** — governed by `docs/benchmark/README.md` (the methodology) and
> the per-run reports under `docs/benchmark/`.

This chapter will hold **only measured numbers produced under the documented methodology**.
Until a run is completed under that methodology at the current version, this chapter states
the methodology and the known ceilings, and explicitly says **"I cannot confirm this"** for
any figure not yet re-measured.

## Methodology (summary — see docs/benchmark/README.md)
- Generator: dnsmark. Warmup + ramp to saturation, then a sustained **hold** = the stable
  figure (not the ramp peak). Corpus: Tranco top-10 000, random order.
- **Truth is the NIC hardware counters** (`ethtool -S`: `rx_packets`, `rx_missed_errors`),
  not the generator's self-reported round-trip — in zero-copy mode the software counters do
  not reflect the datapath.
- Governor pinned `performance`; Ethernet flow control off; RSS spread; verify `:53`
  ownership before each run; compare back-to-back only (one variable at a time).

## Known ceilings (context, not a claim of current performance)
- On dual Xeon E5-2690 v2 + X520, the XDP path is limited by the **PCIe/NIC bus served by
  a NUMA node**, not by Runbound CPU — Runbound CPU stayed low while throughput plateaued.
  The exact figure is a function of that rig, not of the software; it is documented in the
  benchmark reports, not asserted here.
- The naïve hickory slow path measured **1.78× Unbound's instructions/query** — the reason
  the fast paths exist (§1.2).

## Slow path vs fast path — measured (v0.15.3, 5995WX, single X520, warm cache)

The kernel slow path (`xdp: no`) runs the **same** SIMD/ASM `answer_from_cache` wire
responder as the AF_XDP fast path — only the I/O source differs (kernel UDP socket vs
AF_XDP ring). On the same host and NIC, no local-data:

| path | served QPS | p50 | p99 | receiver CPU |
|------|-----------:|----:|----:|-------------:|
| AF_XDP fast path (`xdp: yes`) | ~8.8 M | ~0.2 ms | - | 8 % |
| kernel slow path (`xdp: no`)  | ~6.1 M | 0.565 ms | 0.783 ms | 45 % |

Same order of throughput, the same sub-millisecond latency; the paths differ in **CPU
cost, not served rate or latency** — the slow path pays the per-packet kernel-UDP syscall
the fast path avoids. Both are bounded by the X520 PCIe 2.0 RX (~10 M received, ~1 M
`rx_no_dma_resources`), not by Runbound (the slow path keeps 55 % CPU headroom) — a NIC
without that bus cap would scale both far higher. Reports:
[fast path](../benchmark/RUNBOUND-v0.15.3-threadripper-single-2026-06-07.md),
[slow path](../benchmark/RUNBOUND-v0.15.3-threadripper-single-noxdp-2026-06-07.md).

> The slow path serves from cache only since the #183 fix: the racing resolvers were built
> cache-less and the cache snapshot was built for `xdp: yes` only, leaving `xdp: no`
> forwarding every query since v0.6.12. The "1.78x hickory" note below is the *fallback*
> path (cache misses, CNAME/MX/TSIG); cache hits now take the shared ASM responder.

## To expand
- The official v0.15.0 benchmark report once run under supervision.
