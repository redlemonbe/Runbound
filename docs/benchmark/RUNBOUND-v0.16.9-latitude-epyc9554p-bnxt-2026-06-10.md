# Runbound Benchmark — v0.16.9 — Latitude rs4.metal.xlarge (EPYC 9554P / Broadcom BCM57508 100G) — 2026-06-10

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."**

## 1. Executive Summary

The AF_XDP fast-path ceiling **could not be measured** on this rig, and no QPS
figure is claimed. The Broadcom BCM57508 NIC (`bnxt_en` driver) **does not support
AF_XDP zero-copy** — every `XDP_ZEROCOPY` socket bind returns `EOPNOTSUPP`
(errno 95), on the physical interface, on every queue, with TPA/GRO/LRO disabled,
and the mainline `bnxt_xdp.c` contains none of the zero-copy infrastructure.
Without zero-copy, both generator and resolver fall back to AF_XDP copy mode and
the fast path collapses (receiver NIC counter frozen during the `--xdp` phases,
**0 NIC drops** throughout — Runbound is never the limiting component). What *was*
established: the full **802.1Q VLAN-aware fast path** added for this rig (Runbound
#188, dnsmark #7) is functionally correct — a `dig` over the tagged VLAN returns
`NOERROR` with the right answer. Sustained real QPS, p95/p99 latency, and receiver
CPU at saturation: **I cannot confirm this.** (NIC-limited, not measurable here.)

## 2. Objective

Measure the QPS at which Runbound's AF_XDP fast path saturates ("the bombardier
number") on a powerful, **public, reproducible** bare-metal SKU — NIC hardware
counters as truth, cross-validated against the generator's egress. Secondary: a
clean reproducible rig writeup for provenance.

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD EPYC 9554P, 64c/128t, 1.5 TiB DDR5-3600; NIC
  Broadcom **BCM57508 100G** (`bnxt_en` 6.12.90, fw 227.0.131.0), 32 combined
  channels; kernel **6.12.90+deb13.1**; runbound **v0.16.9**, `xdp: yes`,
  `xdp-interface: eno2`, `rate-limit: 0`, env `RUNBOUND_XDP_VLAN=2126`; governor
  `performance`.
- **Generator (dnsmark):** second identical host; dnsmark VLAN-aware build; exact
  command in §6. `DNSMARK_VLAN=2126` (inject 802.1Q tag + bind physical parent).
- **Link:** eno2 ↔ eno2, 100 Gb/s, flow-control off, FEC RS(528,514). Path is the
  **Latitude private network, 802.1Q VID 2126** (`eno2.2126`, 10.8.0.1 ↔ 10.8.0.2,
  0.12 ms, 0 % loss). The public `/31` links are point-to-point routed (no shared
  L2); an untagged private delivery un-bridges the hosts (ARP `INCOMPLETE`), so the
  tagged VLAN is the only L2-adjacent path.
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt`, 10 000 names, random
  read (`-d corpus_a.txt`, dnsperf "name A" format).
- **Procedure:** warmup (default-UDP) to fill the cache; AF_XDP `--ramp` then
  unlimited `-Q 0`; receiver `ethtool -S eno2` sampled at 1 Hz; saturation =
  receiver NIC `rx`/`tx` plateau with drops, or generator egress plateau.

**VLAN engineering required (and why):** a tagged VLAN breaks an AF_XDP path both
ways — AF_XDP zero-copy is unsupported on a VLAN *sub-interface* (generation must
bind the physical parent and inject the tag), and the XDP reply is emitted via
AF_XDP TX which bypasses `tx-vlan-offload` (the reply leaves untagged → dropped;
measured before the fix: 45 qps, 93 % loss). Fixes: Runbound **#188** (eBPF
`ETH_P_8021Q` branch + `parse_l2()` + TX tag re-insertion gated on
`RUNBOUND_XDP_VLAN`, needed because bnxt strips the RX tag in HW and
`rx-vlan-offload` cannot be turned off), dnsmark **#7** (802.1Q tag in the frame
template, RX tag-skip, physical-parent AF_XDP bind). The untagged hot path is left
byte-for-byte unchanged.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Max sustained real QPS (AF_XDP) | **I cannot confirm this.** (NIC has no zero-copy; copy-mode collapses) | receiver `ethtool -S` |
| AF_XDP zero-copy availability | **Unavailable — `EOPNOTSUPP` (errno 95)**, physical eno2, every queue | dnsmark XSK bind; reproduced |
| ZC unaffected by TPA/GRO/LRO off | Confirmed (still errno 95, `dmesg` silent) | `ethtool -K eno2 gro/lro/rx-gro-hw off` |
| Mainline driver ZC support | **None** (`xsk_pool`/`XDP_ZEROCOPY`/`MEM_TYPE_XSK_BUFF_POOL` absent) | torvalds `bnxt_xdp.c`, master 2026-06 |
| Copy-mode `--xdp` throughput | Collapses: receiver `rx_ucast` frozen during `--xdp` phases (+774 pkts / 29 s) | receiver `ethtool -S`, 1 Hz |
| NIC drops | **0** throughout (warmup + bombardier) | receiver `ethtool -S` |
| VLAN fast path correctness | `dig @10.8.0.1 google.com` → `NOERROR`, correct A record | functional round-trip |
| Latency p50 / p95 / p99 | **I cannot confirm this.** | — |
| Receiver CPU at saturation | **I cannot confirm this.** (never saturated; 0 drops) | — |
| (reference, off-rig) kernel-UDP generation | ≈10.3 M qps received, 0 drops, **generator-limited** | public eno1, earlier run |

## 5. Interpretation

- **The CPU is not the limit.** Runbound showed 0 NIC drops at every point; nothing
  in Runbound saturated. The EPYC class is irrelevant to the result here.
- **The NIC is the limit, and it is a driver-feature gap, not hardware and not
  fixable by updating.** `bnxt_en` has never implemented AF_XDP zero-copy in any
  Linux kernel (verified against current mainline source). A newer kernel/driver
  will not change it; only a different NIC will.
- **No record-class figure is obtainable on this rig**, and none is quoted. The
  only high figure seen (≈10.3 M, reference) is **kernel-UDP generator-limited** and
  says nothing about the fast-path ceiling.
- The VLAN-aware code is validated for correctness (round-trip `NOERROR`) but its
  full-rate AF_XDP path is **not** throughput-validated here, because zero-copy is
  unavailable: **I cannot confirm this** for the VLAN fast path at line rate.
- **Recommendation:** re-run on a zero-copy-capable NIC — Intel `ice` (E810) /
  `i40e` (X710) / `ixgbe` (X520), or Mellanox/NVIDIA ConnectX (`mlx5`). Keep the
  EPYC class; change only the NIC. **AF_XDP zero-copy requires bare metal** (cloud
  VMs lack the flow-steering); insist the provider specifies the NIC model.

## 6. Appendix — exact commands & configuration

```bash
# --- Receiver (.53, EPYC 9554P, Runbound v0.16.9) ---
#   systemd drop-in: Environment=RUNBOUND_XDP_VLAN=2126   # re-tag XDP replies (bnxt strips RX tag in HW)
ip link add link eno2 name eno2.2126 type vlan id 2126 ; ip addr add 10.8.0.1/24 dev eno2.2126
ethtool -K eno2 gro off lro off rx-gro-hw off            # attempt to drop the agg/jumbo ring (no effect on ZC)
# config: server: { xdp: yes ; xdp-interface: eno2 ; access-control: 10.8.0.0/24 allow ; rate-limit: 0 }
cat /proc/cpuinfo | grep -c processor ; cpupower frequency-set -g performance

# --- Generator (.43, dnsmark, AF_XDP, VLAN) ---
ip link add link eno2 name eno2.2126 type vlan id 2126 ; ip addr add 10.8.0.2/24 dev eno2.2126
DNSMARK_VLAN=2126 dnsmark -s 10.8.0.1 -p 53 -d corpus_a.txt -l 12 -Q 200000 --no-tui   # warmup (default-UDP)
DNSMARK_VLAN=2126 dnsmark -s 10.8.0.1 -p 53 -d corpus_a.txt --xdp --ramp -l 30 --no-tui
#   DNSMARK_VLAN → inject 802.1Q tag + bind physical parent for AF_XDP

# --- Truth (receiver) ---
while :; do ethtool -S eno2 | awk '/rx_ucast_packets:|tx_ucast_packets:|discard|drop|error|missed/{print}'; sleep 1; done

# --- Zero-copy availability check (any host with a peer) ---
DNSMARK_VLAN=2126 dnsmark -s <peer> --xdp -l 2 --no-tui   # "ZERO-COPY" = supported ; "os error 95" = not
#   bnxt result here: bind AF_XDP (ifindex=4, q=0, zerocopy=true): Operation not supported (os error 95)

# --- Mainline driver check (off-host) ---
#   torvalds/linux drivers/net/ethernet/broadcom/bnxt/bnxt_xdp.c → grep xsk_pool|XDP_ZEROCOPY → none
```
