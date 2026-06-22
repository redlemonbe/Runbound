# 08 — Performance

> **Status: current as of v0.22.0 (benchmark figures from 2026-06-15)** — governed by `docs/benchmark/README.md`
> (the methodology) and the per-run reports under `docs/benchmark/`. The suite was re-run on
> a new rig (Threadripper PRO 5995WX receiver; dual Xeon E5-2690 v2 generator; direct 10 GbE
> DACs Intel X710/i40e + X510/ixgbe; dnsmark v2.3.0; warm cache; NIC `tx_packets` truth); the
> dual-link runs and the latency were refreshed at **v0.20.0** (DNS datapath byte-identical to
> v0.18.1). Headline measured results (per-run reports in `docs/benchmark/`, indexed in
> `docs/benchmark/INDEX.md`):
>
> | v0.20.0 | served (NIC) | receiver CPU | limited by |
> |---|---|---|---|
> | `xdp: yes` **dual-link** X510+X710 | **~20.3 Mqps** | ~24 % (steady) | the two 10 G links (server not saturated) |
> | `xdp: yes` single link X710 | ~10.14 Mqps | ~10.5 % (steady) | 10 G link response direction |
> | `xdp: yes` dual-link X710 (1 gen card) | ~13.5 Mqps | ~12 % | generator's single X710 card |
> | `xdp: no` kernel slow path X710 | ~3.71 Mqps | ~19 % | kernel-UDP RX + generator |
>
> **Latency** (fast-path wire RTT, capped sub-saturation; AF_XDP can't be tcpdump-anchored):
> i40e **p50 0.073 / p95 0.203 / p99 0.245 ms**, ixgbe p50 0.188 / p99 0.256 ms. Slow path
> (closed-loop, kernel-UDP): p50 0.066 / p95 0.207 / p99 0.371 ms. The closed-loop `--xdp`
> *completion %* under-counts (generator-side accounting, HW-proven: server emits ~all
> responses; the matched-sample RTT is the valid figure) — see the per-run reports.
>
> In no run did Runbound reach its own CPU ceiling (≤24 %). Same-rig kernel-UDP references:
> unbound 1.22.0 ~2.09 M, BIND 9.20.23 ~1.84 M. The older v0.16.11 (X710) and v0.17.0
> sections below are superseded by the v0.18.1 reports but kept for the datapath history.

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

## X710 10 GbE — earlier detail (v0.16.11, superseded by the v0.20.0 table above)

Measured on the documented rig (receiver: 5995WX + Intel X710-DA2; generator: dual Xeon
E5-2690 v2 + X710, direct DACs; dnsmark 2.2.1, XDP zero-copy both sides, NIC-counter
truth):

- **Single link** *(v0.16.11 — detailed report archived, in git history pre-`6ff6ae4`)*:
  offered reaches the 10 G line rate (~13.0 M qps of 78-byte queries); **served capped at
  10.09 M** by the *response-direction* line rate (answers are larger than queries) — a
  link property, not a server one.
- **Dual link** *(v0.16.11 — detailed report archived, in git history pre-`6ff6ae4`)*:
  one XDP program + 32 zero-copy XSK workers per port, no bonding. **Served peak
  13.15 M qps** (port balance 49.9/50.1 %) under 13.18 M offered — **99.8 % answered at
  peak, at ~11 % receiver CPU**. The ceiling is the generator (~13.2 M pps total whether
  flooding one NIC or two); **Runbound's own ceiling on this rig was not reached.**
  p50 stayed in the 0.04–0.30 ms band from 0.4 M to ~12.8 M qps total.
- **Kernel slow path (`xdp: no`), v0.17.0 auto-tune** (§4.5): the queue/IRQ retune is
  applied only when a NIC is explicitly named (`xdp-interface:` — a channel change must
  never hit a management NIC), so out of the box, with no named NIC, the kernel slow path
  is **not** retuned ([#190](https://github.com/redlemonbe/Runbound/issues/190)). The
  i40e/X710 kernel slow path is **highly tuning-sensitive** — three measured figures, three
  conditions:
  - **~3.71 M qps served at ~19 % CPU** — the canonical benchmark
    (`RUNBOUND-v0.18.1-…-x710-noxdp`): NIC tuned (RSS `udp4 sdfn`, node-local queues/IRQs,
    RX ring 4096), 63 `SO_REUSEPORT` workers, a kernel-UDP generator (~4.6 M offered), p99
    0.371 ms — ~2× BIND/unbound on the same rig. **This is the slow-path number.**
  - **~1.5 M qps** (best ~1.59 M) — **out of the box, NOT retuned** (no named NIC), i40e
    NAPI-bound ([#190](https://github.com/redlemonbe/Runbound/issues/190)/[#165](https://github.com/redlemonbe/Runbound/issues/165)).
  - **~7.3 M** — historical **ixgbe/X520** (a different datapath, see the table below), **not
    reproducible on i40e**.
  A mis-tuned setup (e.g. NIC RX queues spread cross-NUMA away from the card's node) collapses
  below even the out-of-box figure — the lever is node-local queues/IRQs (#165). The AF_XDP fast path is unaffected by any
  of this (re-verified at the 10 G link ceiling — **~10.1–11.2 M qps** single link,
  run-to-run; the v0.18.1 per-run report records **~10.12 M** sustained served).

## Slow path vs fast path — measured (historical: v0.16.6, 5995WX, single X520, warm cache)

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
the magnitude of that headroom is not measured here. (v0.16.1 X520 fast-path and slow-path
reports archived — in git history pre-`6ff6ae4`; the current round is in [benchmark/INDEX.md](../benchmark/INDEX.md).)

> The slow path serves from cache only since the #183 fix: the racing forwarders were built
> cache-less and the cache snapshot was built for `xdp: yes` only, leaving `xdp: no`
> forwarding every query since v0.6.12. The "1.78× hickory" figure above is historical — it
> measured the pre-v0.22 hickory `ServerFuture` fallback (cache misses, CNAME/MX); as of
> v0.22 even the fallback is the wire-native `serve_wire` handler, and cache hits take the
> shared ASM responder. The DNS datapath is byte-identical across the de-hickory work, so the
> measured throughput/latency numbers in this chapter are unchanged.

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

## Bottleneck analysis & scaling headroom

At the 2026-06-13 ceiling — **~20.28 M qps served, dual-link (X510 + X710)** — the limit is
**the aggregate link line rate, not Runbound and not the CPU.** Each 10 GbE link carries
~10.1 M small-DNS responses/s (its *response-direction* line rate); both links run at line
rate at once, with **~0 NIC drops** and the receiver (a single AMD Threadripper PRO 5995WX,
a PCIe-3.0 / 2013-class Xeon-v2 generator on the other end) at **~24 % CPU**. Single link:
~10.12 M served at **~11 % CPU**. In no run did Runbound reach its own CPU ceiling — ~76 % of
the machine was idle at the maximum.

So the wall is **bandwidth**, hit in this order as each is removed: link line rate → NIC
RX / PCIe path → CPU / memory. On this rig the **links saturated first** — PCIe 3.0 (X710)
still had headroom, so the run is *not* PCIe-bound. The only demonstrably *bus*-bound result
is the archived dual-Xeon-v2 / **X520** set: PCIe 2.0 x8 capped the RX path at ~10 M while
Runbound stayed < 25 % CPU — a property of that 2013-era NIC/bus, not of the software.

**Scaling projections — architectural, `[UNVERIFIED — awaiting hardware]`.** Because Runbound
is link/bandwidth-bound and far from CPU-bound, served throughput should track the NIC line
rate as long as CPU, PCIe and memory keep pace:

| platform (projected) | link | projected served | basis |
|---|---|---:|---|
| PCIe 4.0 + 2×25 G (mlx5 zero-copy) | 50 G | **~50 M qps** | line-rate-bound; ≈ 60 % CPU by linear extrapolation from 20 M @ 24 % |
| PCIe 5.0 + 100 G (mlx5 / ice zero-copy) | 100 G | **~100–200 M qps** | needs a many-core Zen5 / EPYC Turin (AVX-512); multi-variable |

> **These are projections, not measurements.** They assume: (a) an **AF_XDP zero-copy** NIC —
> Mellanox `mlx5` or Intel `ice` / `i40e`, **not** Broadcom `bnxt` (no zero-copy in any kernel
> → copy-mode only); (b) PCIe and memory bandwidth that keep pace with the link; (c) NIC RSS
> queues pinned to physical cores (the [#165](https://github.com/redlemonbe/Runbound/issues/165)
> lever). They have **not** been run on the target hardware. The measured, reproducible fact is
> the one above: **20.28 M served at ~24 % CPU, link-bound** — the server was never the wall.

## To expand
- A v0.17.x run under the documented methodology (the v0.16.11 dual-link report's open
  item — a stronger generator or a third link — still stands to find the receiver's true
  ceiling). The full run index is in [docs/benchmark/INDEX.md](../benchmark/INDEX.md).
