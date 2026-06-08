# 08 — Performance

> **Status: current (v0.16.6)** — governed by `docs/benchmark/README.md` (the methodology) and
> the per-run reports under `docs/benchmark/`.

This chapter holds **only measured numbers produced under the documented methodology**.
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

## Slow path vs fast path — measured (v0.16.6, 5995WX, single X520, warm cache)

The kernel slow path (`xdp: no`) runs the **same** SIMD/ASM cache wire responder as the
AF_XDP fast path — only the I/O source differs (kernel UDP socket vs AF_XDP ring). Measured
back-to-back on the same host and NIC (Intel X520 / 82599, PCIe 2.0 x8), warm cache, no
local-data, with only the `xdp:` line changed. Throughput is the receiver NIC PHY counter
(`tx_pkts_nic`), not the generator round-trip.

| path | max served | NIC drops at max | receiver CPU | latency (low load) |
|------|-----------:|-----------------:|-------------:|--------------------|
| AF_XDP fast path (`xdp: yes`) | **~10.1 M** | 0 (NIC line-rate limited) | **~11 %** (8 M served @ 10.6 %) | p50 0.062 ms / p99 0.088 ms (ramp, AF_XDP RTT) |
| kernel slow path (`xdp: no`)  | **~7.3 M**  | ~4.6 M (`rx_no_dma` + `rx_missed`) | ~70 cores busy | p50 0.065-0.089 ms (ramp, no-loss region) |

The fast path tracks offered load 1:1 with **zero drops** up to the X520 line rate (8 M
served at 6.7 % CPU), then answers ~10.1 M of the ~10.7 M the NIC can receive, at ~21 %
CPU — bounded by the X520 PCIe 2.0 **RX** path, not by Runbound (~79 % CPU idle at the
maximum). The slow path reaches the same order of magnitude (~6.9 M served) but pays the kernel-UDP
syscall cost; batched `recvmmsg` receive (§4.0) keeps it efficient (~54 % CPU at 7 M
offered, ~70 cores engaged), ~5 M packets dropped at the NIC under the same
firehose, and an earlier latency knee — its rate under a sub-millisecond median SLO is
~4.6 M served (p50 0.746 ms). A NIC without the PCIe 2.0 RX cap would scale both higher;
the magnitude of that headroom is not measured here. Reports:
[fast path](../benchmark/RUNBOUND-v0.16.1-threadripper-5995wx-x520-xdp-2026-06-07.md),
[slow path](../benchmark/RUNBOUND-v0.16.1-threadripper-5995wx-x520-noxdp-2026-06-07.md).

> The slow path serves from cache only since the #183 fix: the racing resolvers were built
> cache-less and the cache snapshot was built for `xdp: yes` only, leaving `xdp: no`
> forwarding every query since v0.6.12. The "1.78x hickory" note below is the *fallback*
> path (cache misses, CNAME/MX/TSIG); cache hits now take the shared ASM responder.

## Independent cross-validation (dnsperf)

The same `xdp: no` receiver was measured by an independent third-party tool — `dnsperf
2.14.0` (DNS-OARC) — to confirm the figures are not a generator artifact. NIC-confirmed:
served = received with **zero drops**, 99.85 % NOERROR, ~0.09–0.12 ms latency, at **3.4 %
receiver CPU**. dnsperf plateaus at **~238 k QPS** regardless of added clients/threads — a
closed-loop, kernel-UDP, single-process generator is bounded there, exercising only ~3–4 %
of the AF_XDP-measured ceiling while the receiver is far from saturation. The tools agree on
correctness, latency and NIC-truth; dnsperf is generator-bound, as expected — which is why
an open-loop AF_XDP generator is needed to reach the receiver's actual saturation point.
Full report in the dnsmark repository (`docs/cross-validation-dnsperf.md`).

## To expand
- The official v0.15.0 benchmark report once run under supervision.
