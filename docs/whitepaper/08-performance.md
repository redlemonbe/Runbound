# 08 — Performance

> **0.9.2 hot-path note.** The per-source DNS rate limiter now reads its rps/burst as
> `AtomicU64` in the hot path (`check()` / `rl_should_drop`, `worker.rs`) so the limits can be
> edited live. On x86 a relaxed atomic load is a plain `mov`, so this is expected to be
> perf-neutral, but the hot path was touched and has **not yet been re-benched on baremetal** —
> the 0.9.0 figures below predate this change.

> **Status: current (0.9.0), measured 2026-07-03** under the documented methodology
> (dnsmark 1.0 + dnsperf 2.14.0, 100k-name real corpus). Recursion + DNSSEC validation
> run in-house; the fast path's hot loop is the SIMD/ASM cache wire responder. Governed by
> `docs/benchmark/README.md` (the methodology) and the per-run reports under
> `docs/benchmark/`, indexed in `docs/benchmark/INDEX.md`. Every throughput figure below is
> **cross-checked against the receiver NIC hardware counters** (`tx_packets`, agreement
> 0.1–1.0 %), not dnsmark's self-reported round-trip. The served rate is the open-loop flood
> NIC-rx (the service ceiling): for the fast path it is line-bound; for the kernel path it is
> the open-loop rate (Runbound/unbound do not livelock; BIND does).
>
> | 0.9.0 (2026-07-03) | served (NIC) | host CPU (128 c) | limited by |
> |---|---|---|---|
> | `xdp: yes` **dual-link** X710+X520 | **~20.3 Mqps** (ramp) / 19.4 M (flood) | ~24.4 % | 99 % of the aggregate 20 G link — server not saturated |
> | `xdp: yes` single link X710 | ~9.85 Mqps | ~10.1 % | 10 G link (103 B responses → line-bound) |
> | `xdp: yes` single link X520 | ~9.81 Mqps | ~8.2 % | 10 G link response direction (line-bound) |
> | `xdp: no` kernel slow path X710 | ~2.86 Mqps | ~17.7 % | kernel-UDP RX path (no livelock, 99.96 % NOERROR) |
> | `xdp: no` kernel slow path X520 | ~2.18 Mqps | ~17.1 % | kernel-UDP RX path |
>
> **Latency**: fast-path wire latency (dnsmark `--wire-latency`, server+link) p50 **31 µs**
> (X710) / **34 µs** (X520); dual-link p50 **30 µs**. Kernel slow-path cache-hit latency
> (tcpdump → tshark `dns.time`, pure server service time) p50 **24.6 µs** (X710) /
> **25.2 µs** (X520). The host-CPU column is whole-machine `mpstat` utilisation across all
> 128 cores during the flood (softirq/NIC cost included, VM `%guest`/`%steal` excluded).
>
> On the single 10 G link the wall is the *response* direction: 103-byte replies cap a
> single link at ~9.85 M/s, so a bigger single-link figure is not reproducible with this
> corpus. In no run did Runbound reach its own CPU ceiling. Same-rig kernel-UDP references:
> unbound 1.22.0 ~1.91 M (X710) / ~1.46 M (X520); BIND 9.20.23 ~1.49 M (X710) and it
> **livelocks** into 33 % SERVFAIL under the X520 flood.

This chapter holds **only measured numbers produced under the documented methodology**.

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

## Slow path vs fast path

The kernel slow path (`xdp: no`) runs the **same** SIMD/ASM cache wire responder as the
AF_XDP fast path — only the I/O source differs (kernel UDP socket vs AF_XDP ring). The fast
path tracks offered load 1:1 with **zero drops** up to the link line rate, bounded by the NIC
RX/PCIe path, not by Runbound. The slow path reaches a lower rate because it pays the
kernel-UDP syscall cost; batched `recvmmsg` receive (§4.0) keeps it efficient. The
`xdp: no` kernel slow path serves from cache: cache hits take the shared ASM responder, and
even the fallback path is the wire-native `serve_wire` handler. Measured figures for both
paths, per NIC, are in the table at the top of this chapter and in the per-run reports under
[benchmark/INDEX.md](../benchmark/INDEX.md).

## Independent cross-validation (dnsperf)

The `xdp: no` receiver was measured by an independent third-party tool — `dnsperf 2.14.0`
(DNS-OARC) — to confirm the figures are not a generator artifact. Closed-loop, NIC-confirmed
(`RUNBOUND-v0.9-threadripper-5995wx-x710-noxdp-2026-07-03.md`, the canonical `xdp: no`
report): dnsperf sustains the receiver NIC `tx_packets` rate with a high completion / NOERROR
fraction — several times the reference resolvers (BIND, unbound) in the same closed-loop
test, and consistent with the `xdp: no` ramp figures above. dnsperf is a closed-loop,
single-process generator, so it does not itself reach the AF_XDP-measured ceiling; it
corroborates correctness and NIC-truth rather than pushing the receiver to saturation —
which is why an open-loop AF_XDP generator is needed to reach the receiver's actual
saturation point. Full report:
`docs/benchmark/RUNBOUND-v0.9-threadripper-5995wx-x710-noxdp-2026-07-03.md`.

## Bottleneck analysis & scaling headroom

At the current campaign's dual-link ceiling — **~20.3 M qps served (ramp) / 19.4 M (flood),
dual-link (X710 + X520)** — the limit is **99 % of the aggregate 20 G link line rate, not
Runbound and not the CPU.** Each 10 GbE link carries ~9.85 M small-DNS responses/s (its
*response-direction* line rate, 103-byte replies); both links run at line rate at once, with
the receiver (a single AMD Threadripper PRO 5995WX, a 2013-class Xeon-v2 generator on the
other end) at **~24.4 % host CPU** of 128 cores. Single link: ~9.85 M served (X710) at
**~10.1 % host CPU** / ~9.81 M (X520) at **~8.2 %**. In no run did Runbound reach its own CPU
ceiling — the machine was overwhelmingly idle at the maximum.

So the wall is **bandwidth**, hit in this order as each is removed: link line rate → NIC
RX / PCIe path → CPU / memory. On this rig the **links saturated first** — PCIe 3.0 (X710)
still had headroom, so the run is *not* PCIe-bound. A demonstrably *bus*-bound result appears
on the dual-Xeon-v2 / **X520** rig, where PCIe 2.0 x8 caps the RX path while Runbound stays
low on CPU — a property of that 2013-era NIC/bus, not of the software.

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
> queues pinned to physical cores (the [#190](https://github.com/redlemonbe/Runbound/issues/190)
> lever). They have **not** been run on the target hardware. The measured, reproducible fact is
> the one above: **~20.3 M served at ~24 % CPU, link-bound** — the server was never the wall.

## To expand
- A run with a stronger generator or a third link still stands to find the receiver's true
  ceiling: on the dual-link run the wall was the aggregate link line rate, not Runbound. The
  full run index is in [docs/benchmark/INDEX.md](../benchmark/INDEX.md).
