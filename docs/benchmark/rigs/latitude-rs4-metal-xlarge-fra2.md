# Benchmark rig — Latitude.sh `rs4.metal.xlarge` (fra2 / Frankfurt)

Two **identical** bare-metal servers rented from **[Latitude.sh](https://www.latitude.sh/)**,
region **fra2 (Frankfurt)**, SKU **`rs4.metal.xlarge`**, used as a two-box DNS benchmark
fabric.

| Role | Hostname | Public IP (`eno1`) | Software |
|------|----------|--------------------|----------|
| **Generator** (émetteur) | `emetteur` | `109.94.96.43` | dnsmark v2.1.4 |
| **Receiver** (récepteur) | `recepteur` | `109.94.96.53` | Runbound v0.16.9 |

> **Reproducibility anchor:** rent the same `rs4.metal.xlarge` on Latitude.sh **fra2** to
> replicate this rig. The two units are spec-identical apart from one NVMe model (see below).

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
- Intel **I350** 1 GbE — driver `igb` — `eth1`/`eth3`, down (onboard/mgmt) — PCIe `01:00.0` / `01:00.1`

### Storage (NVMe)
- 2 × Micron **7400** 894 GB — `MTFDKBG960TDZ`, fw `E1MU23BC`
- Micron **7450** 7.68 TB — `MTFDKCC7T6TFR`, fw `E2MU110` — **×4 on receiver**, ×3 on generator
- generator also has 1 × Micron **7500** 7.68 TB — `MTFDKCC7T6TGP`, fw `E3MQ000`

### OS / kernel
- **Debian GNU/Linux 13 (trixie)**
- Kernel **6.12.90+deb13.1-amd64**
- CPU governor: **`schedutil`** ⚠️ — set to **`performance`** before any measurement (governor is the #1 benchmark confounder)

---

## Per-machine notes

- **`emetteur` (109.94.96.43)** — generator (dnsmark). One NVMe is a Micron **7500** instead of a 7450.
- **`recepteur` (109.94.96.53)** — receiver (Runbound). Installed via the repo `install.sh`
  (systemd unit with `CAP_PERFMON`/`CAP_BPF`); `systemd-resolved` disabled to free `:53`.

## Network topology (important for the bench)

- **No direct private link** between the two boxes. The "2×100G" are the **two ports of the
  single BCM57508** on each machine — not a cable between the servers.
- Benchmark traffic therefore runs over the **public `eno1` IPs** (`109.94.96.43` → `109.94.96.53`).
  Measured path: **1 hop (ttl 63), ~0.25 ms RTT** — both units sit on the same Latitude fra2
  fabric, so the inter-box path is expected to be full line-rate (to be confirmed at the NIC counters).

## XDP / AF_XDP caveat

- `bnxt_en` supports **native XDP**; **AF_XDP zero-copy on `bnxt_en` must be validated** on this
  kernel before trusting any fast-path number — Broadcom's ZC path is less battle-tested than
  mlx5 / ice / ixgbe. Confirm the ZC bind succeeds (loader logs + `dmesg`) on the first run.

---

_Captured 2026-06-10 with `lscpu` · `dmidecode` · `smartctl` · `ethtool` · `lspci` on both hosts._

---

## Benchmark tuning

Re-apply after every reboot — none of these persist. Part of the reproducible setup.

### CPU (both machines)
```bash
# Governor -> performance (scaling driver: acpi-cpufreq). The #1 benchmark confounder.
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```
Verified: all 128 logical CPUs report `performance`.

### Memory (both machines)
```bash
# 8 GiB of 2 MiB hugepages for the AF_XDP UMEM.
echo 4096 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```
Verified: `HugePages_Total: 4096`.

### NIC `eno1` (Broadcom BCM57508, `bnxt_en`)
- **Flow control: off by default** (`ethtool -a eno1` → RX/TX off) — confirmed, no pause frames.
- **irqbalance: inactive** on both — IRQs are pinned manually for the run, not reshuffled.
- **Rings** (`ethtool -g eno1`):
  - `recepteur`: RX max **8191** (already at max), TX **2047** (at max)
  - `emetteur`: RX **511 / 2047**, TX **511 / 2047** → raise to max for generation
- **Queues** (`ethtool -l eno1`): current **Combined 32**; max Combined 37 (`recepteur`) / 74 (`emetteur`).
  The combined-queue count caps the number of AF_XDP RX sockets / XDP workers.

### Pending — link-resetting or access-sensitive (applied inside the run window)
```bash
# Generator: max the rings (this bounces the eno1 link)
sudo ethtool -G eno1 rx 2047 tx 2047
# Pin NIC IRQs off the Runbound worker cores (single NUMA node here, so straightforward)
# Attach Runbound XDP on eno1 — eno1 also carries SSH, and bnxt_en AF_XDP ZC is less
# battle-tested, so this is done behind a dead-man's-switch: an `at` job detaches XDP +
# stops runbound after N minutes unless cancelled, so a mis-behaving fast path cannot
# lock anyone out of the box.
```

### Network / Runbound bench config
- Traffic over the public `eno1` path: `109.94.96.43` (generator) → `109.94.96.53` (receiver).
- Receiver config: `xdp-interface: eno1`, bind the public IP, `access-control: 109.94.96.43/32 allow`,
  `rate-limit: 0`, `xdp: yes`.
