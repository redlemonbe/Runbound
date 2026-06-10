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
