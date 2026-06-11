# Benchmark rig — Latitude.sh `rs4.metal.xlarge` (fra2 / Frankfurt)

Two **identical** bare-metal servers rented from **[Latitude.sh](https://www.latitude.sh/)**,
region **fra2 (Frankfurt)**, SKU **`rs4.metal.xlarge`**, used as a two-box DNS benchmark
fabric.

| Role | Hostname | Public IP (`eno1`) | Software (2026-06-11 runs) |
|------|----------|--------------------|----------------------------|
| **Generator** (émetteur) | `emetteur` | `109.94.96.43` | dnsmark v2.2.1 (release musl, SHA256 verified) |
| **Receiver** (récepteur) | `recepteur` | `109.94.96.53` | Runbound v0.17.2 (release gnu, SHA256 verified) |

> **Reproducibility anchor:** rent the same `rs4.metal.xlarge` on Latitude.sh **fra2** to
> replicate this rig. The two units are spec-identical apart from one NVMe model (see below).

> **2026-06-11 — both machines reinstalled** (was Debian 13 / kernel 6.12.90 on
> 2026-06-10): now **Ubuntu 24.04.4 LTS**, kernel **6.8.0-124-generic**, user `ubuntu`.
> Hardware unchanged (re-verified: dmidecode, ethtool, lscpu). Sections below updated
> accordingly; the 2026-06-10 storage/PCIe details still apply.

---

## Common specification (both machines)

### CPU
- **AMD EPYC 9554P** (Genoa, Zen 4) — 1 socket
- **64 cores / 128 threads**, max **3.764 GHz**, min 1.5 GHz
- Caches: **L1d** 2 MiB (64×32 KiB) · **L1i** 2 MiB (64×32 KiB) · **L2** 64 MiB (64×1 MiB) · **L3 256 MiB** (8×32 MiB)
- **1 NUMA node**
- SIMD: SSE4.2 · AES · AVX2 · **AVX-512** (F/DQ/BW/VL/CD/IFMA/VBMI/VBMI2/VNNI/BF16/BITALG/VPOPCNTDQ) · VAES · VPCLMULQDQ · SHA-NI · GFNI

### Memory
- **1.5 TiB DDR5** — 24 × 64 GB **Micron** DIMMs @ **3600 MT/s** (2 DIMMs/channel)

### Motherboard / BIOS
- **ASUSTeK K14PA-U24 Series**
- BIOS: American Megatrends Inc. **v1401** (2024-02-23)

### Network
- **Broadcom BCM57508 NetXtreme-E** — driver **`bnxt_en`**, firmware **227.0.131.0 / pkg 227.1.111.0**
  - **2 × 100 GbE**: `eno1`, `eno2` — both link up @ 100000 Mb/s — PCIe `81:00.0` / `81:00.1`
- Intel **I350** 1 GbE — driver `igb` — down (onboard/mgmt)

### Storage (NVMe)
- 2 × Micron **7400** 894 GB — `MTFDKBG960TDZ`, fw `E1MU23BC` (root, md0 RAID)
- Micron **7450** 7.68 TB — `MTFDKCC7T6TFR`, fw `E2MU110` — ×4 on receiver, ×3 on generator
- generator also has 1 × Micron **7500** 7.68 TB — `MTFDKCC7T6TGP`, fw `E3MQ000`

### OS / kernel (since 2026-06-11)
- **Ubuntu 24.04.4 LTS**, kernel **6.8.0-124-generic**, user `ubuntu`
- CPU governor default: ⚠️ not `performance` — pin it before any measurement
- `systemd-resolved` active (stub on 127.0.0.53/54 only — does not conflict with a
  bench bind on a test IP; check `ss -ulpn | grep :53` anyway, methodology rule 5)

---

## Per-machine notes

- **`emetteur` (109.94.96.43)** — generator (dnsmark). One NVMe is a Micron **7500** instead of a 7450.
- **`recepteur` (109.94.96.53)** — receiver (Runbound), run as root from `/home/ubuntu`
  for the 2026-06-11 bench (no systemd unit).

## Network topology (important for the bench)

- The "2×100G" are the **two ports of the single BCM57508** on each machine.
- **Latitude private network, 802.1Q VID 2126**, delivered **tagged on `eno2` only**
  (tested 2026-06-11: `eno1.2126` = 100 % ARP/ping loss). Sub-interfaces
  `eno2.2126`: 10.21.26.1 (generator) ↔ 10.21.26.2 (receiver), ping RTT 0.37 ms,
  0 % loss. **Lossless at ≥10.5 M pps** in the 2026-06-11 runs.
- The public `eno1` /31s are **routed** (1 hop, TTL 63, ~0.24 ms). Usable as a second
  load path, but the fabric dropped **~8 %** of a ~10.5 M pps generator flood before
  the receiver NIC (measured 2026-06-11) — prefer the VLAN for measurement.
- An **untagged** private delivery un-bridges the hosts (ARP `INCOMPLETE`) — the
  tagged VLAN is the only clean L2-adjacent path (2026-06-10 finding, still true).

## XDP / AF_XDP on this NIC — measured verdicts

- `bnxt_en` supports **native XDP (DRV mode)** — Runbound attaches and serves.
- **AF_XDP zero-copy: NOT supported** — `XDP_ZEROCOPY` bind → `EOPNOTSUPP` (errno 95)
  on every queue. Verified on Debian 13 / kernel 6.12.90 (2026-06-10, incl. mainline
  `bnxt_xdp.c` source check) **and re-verified on Ubuntu 24.04 / kernel 6.8.0-124**
  (2026-06-11). Driver-feature gap; only a different NIC lifts it (Intel
  `ice`/`i40e`/`ixgbe`, Mellanox `mlx5`).
- AF_XDP **copy mode works and is usable on the receiver side**: Runbound v0.17.2
  served 7.85 M qps single-port / 9.07 M dual-port (see the 2026-06-11 reports).
  Copy mode is **not usable for generation** (dnsmark `--xdp` → ~10 k qps).
- **802.1Q on this kernel:** `ethtool -K eno2 rxvlan off` is **accepted** on
  6.8.0-124 (it was refused on 6.12.90) — with it, the #188 per-packet tag-preserve
  path works and `RUNBOUND_XDP_VLAN` is not needed, including mixed
  tagged+untagged dual-port attach.
- **Counter names differ across kernels** (truth source for every report):
  - kernel 6.12 (2026-06-10): `rx_ucast_packets` / `tx_ucast_packets`
  - kernel 6.8 (2026-06-11): **`rx_ucast_frames` / `tx_ucast_frames`** (port-level HW),
    drops in `rx_total_ring_discards` / `rx_stat_discard`
- dnsmark's wire-truth PHY guard does not resolve bnxt counter names (reports
  "0 qps confirmed" while traffic flows) — generator egress must be cross-checked
  against the receiver NIC counters.

---

## Benchmark tuning

Re-apply after every reboot — none of these persist. Part of the reproducible setup
(`tune-common.sh` in the 2026-06-11 session).

### CPU + memory (both machines)
```bash
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
echo 4096 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages   # 8 GiB for AF_XDP UMEM
sudo sysctl -w net.core.rmem_max=67108864 net.core.wmem_max=67108864 net.core.netdev_max_backlog=250000
sudo systemctl stop irqbalance     # already inactive by default on this image
```

### NIC (per test port)
```bash
sudo ethtool -A <nic> rx off tx off          # flow control (off by default here — verify)
sudo ethtool -N <nic> rx-flow-hash udp4 sdfn
sudo ethtool -G <nic> rx 2047 tx 2047        # max on this fw; bounces the link
# rings on 6.8: RX max 2047 (+ jumbo 8188), TX max 2047 — both machines
# channels: combined 32 active / 74 max
```

### Operational warnings
- **Latitude's edge protection rate-limits SSH**: repeated short-lived TCP
  connections to :22 (e.g. aborted host-key mismatches) get the source IP
  **temporarily banned at the fabric level** (local firewall is empty). Use SSH
  `ControlMaster`/`ControlPersist` multiplexing; reach the second box via
  `ProxyJump` through the first. Bans observed to last ~15–45 min.
- Attaching XDP to `eno1` (the SSH port) is safe in practice (non-DNS traffic is
  XDP_PASSed) but do it behind a **dead-man's switch**:
  `systemd-run --on-active=480 --unit=deadman bash -c 'pkill -x runbound; ip link set eno1 xdp off'`.

---

_Hardware captured 2026-06-10 (`lscpu` · `dmidecode` · `smartctl` · `ethtool` · `lspci`);
OS/topology/XDP sections re-verified 2026-06-11 on the Ubuntu reinstall._
