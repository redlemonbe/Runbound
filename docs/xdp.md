# XDP Kernel-Bypass Fast Path

Runbound v0.4.14+ includes an AF_XDP fast path, enabled by default (the `xdp`
feature is part of the default feature set since v0.4.16).

## License

The AF/XDP fast path requires the **commercial license**.

Open-source builds (AGPL v3) include the XDP code path but it is disabled at
runtime — the server self-tests at startup and falls back automatically to the
standard `SO_REUSEPORT` kernel UDP path if no commercial license is present.

To enable the AF/XDP fast path in production, contact the maintainer for a
commercial license.

## Disabling XDP

There are four ways to disable the XDP fast path, depending on the context:

| Method | When to use |
|---|---|
| `xdp: no` in `unbound.conf` | Persistent disable — survives restarts |
| `runbound --no-xdp [config]` | One-shot disable without editing config |
| `RUNBOUND_DISABLE_XDP=1` env var | Emergency — host unreachable after XDP attach, no config access |
| `cargo build --release --no-default-features` | Build-time disable — removes the code entirely |

**Config file (`unbound.conf`):**

```
server:
    xdp: no
```

**Command line:**

```bash
runbound --no-xdp /etc/runbound/unbound.conf
```

Config file and CLI produce the same log line:

```
INFO runbound: XDP fast path disabled (xdp: no / --no-xdp)
```

The env var produces:

```
INFO runbound::dns::xdp::worker: XDP disabled via RUNBOUND_DISABLE_XDP environment variable
```

The server then runs on the standard `SO_REUSEPORT` kernel path with no capability
requirements beyond `CAP_NET_BIND_SERVICE`. All security features (ACL, rate limiting,
blacklist, DNSSEC) remain fully active.

**Typical use cases for runtime disable:**

- Containers or VMs without `CAP_NET_ADMIN` / `CAP_BPF` / `AF_XDP`
- Troubleshooting suspected XDP issues (compare behaviour with/without)
- Cloud providers that block AF_XDP (AWS Nitro, GCP, Azure by default)
- Temporary disable during NIC driver updates

---

**Build flags:**

| Goal | Command |
|---|---|
| Default (XDP enabled) | `cargo build --release` |
| Disable XDP at build time | `cargo build --release --no-default-features` |

## What it does

An eBPF XDP program attaches to the NIC at startup. UDP/port-53 packets are
intercepted at the driver level before reaching the kernel network stack:

- **Local zones** → answered entirely in user space (zero syscalls, **<1 ms** latency (below dnsmark resolution))
- **Recursive / forwarded / unknown** → `XDP_PASS` to normal hickory-server path
- **Rate-limited clients** → silently dropped at NIC level
- **ACL deny** → silently dropped; ACL refuse → REFUSED response crafted in XDP path

## SIMD acceleration in the XDP worker (v0.9.46)

The XDP worker thread (`src/dns/xdp/worker.rs`) uses SIMD intrinsics on the hot path.
CPU feature level is detected once at startup via `src/dns/simd.rs`:

| Operation | Scalar | SSE2 | AVX2 |
|-----------|--------|------|------|
| QNAME label lowercase | 1 B/cycle | 16 B/cycle | 32 B/cycle |
| QNAME wire parse | 2-pass | 1-pass (fused) | 1-pass (fused) |
| Cache key equality | byte loop | `pcmpeqb`+mask | `vpcmpeqb`+mask |
| Domain hash | FNV-1a ~80 ns | CRC32c ~20 ns | CRC32c ~20 ns |

Dispatch is resolved at init — no per-packet branch overhead. On CPUs without SSE2
(rare; all x86_64 cores have SSE2 by spec) the scalar fallback is used transparently.


## Local-zone wire fast path (v0.9.66, #156)

For local-zone **A / AAAA** answers, the XDP worker bypasses `hickory_proto`
entirely: `answer_dns_wire()` parses the query and writes the response straight
into the UMEM TX frame — no `Message` parse/serialize, no heap allocation.

Measured on an X520 10 GbE link (same `a.bench.test A` query, dnsmark v1.2.1,
controlled back-to-back A/B, 5 runs each, medians):

| | hickory | wire builder | gain |
|---|---|---|---|
| Throughput (median) | ~3.80 M qps | ~4.63 M qps | **+21 %** |
| p50 latency | 0.52 ms | 0.34 ms | **−35 %** |

*(Micro-benchmark; generator Xeon E5-2690 v2 — see [benchmark/](benchmark/) for the full rig.)*

(The p50 latency improvement is the most consistent metric; absolute throughput
is CPU-frequency / host-state dependent, so the back-to-back ratio is the
reliable figure.)

> These are component-level micro-benchmarks. End-to-end numbers follow the formal
> methodology in [benchmark/README.md](benchmark/README.md).

Everything the wire builder does not cover — NXDOMAIN, NODATA, **wildcard
local-data**, CNAME/MX/TXT, EDNS (OPT), ACL Deny, ANY, malformed — transparently
**falls back to hickory**, so behaviour is unchanged outside the A/AAAA answer case.
See [benchmark/](benchmark/) for the current benchmark methodology.

## domain-routing (CPUMAP) and zero-copy (v0.9.66, #155)

`xdp-domain-routing` (CPUMAP per-domain CPU affinity) is **mutually exclusive
with zero-copy**: a CPUMAP redirect leaves the driver ZC ring, so it is forced
OFF once zero-copy is confirmed on an interface (it would otherwise collapse
throughput ~40×). It remains available in SKB/copy mode for cache locality.


## Requirements

| Item | Details |
|---|---|
| Kernel | Linux 5.10+ (6.x recommended) |
| Capabilities | `CAP_NET_RAW`, `CAP_NET_ADMIN`, `CAP_BPF` |
| Address family | `AF_XDP` in `RestrictAddressFamilies` |
| Locked memory | `LimitMEMLOCK=infinity` |
| NIC (optimal) | Intel ixgbe / i40e / ice / igc (native zero-copy) |
| NIC (supported) | virtio, any NIC with XDP copy-mode support |

### NIC note: Intel X520 / 82599 (ixgbe) — works, but not recommended for high-rate XDP

The X520 (82599 controller, `ixgbe` driver) runs the XDP fast path correctly, but
several hardware-level limitations make it a poor choice when XDP throughput — or
*measuring* that throughput — matters:

- **Zero-copy counters are blind.** Under `XDP_REDIRECT` -> AF_XDP zero-copy the
  standard `ethtool -S` netdev counters (`rx_packets`, `rx_missed_errors`,
  `tx_packets`/`tx_bytes`) do not advance — their delta reads 0 under load, so
  served throughput cannot be observed from them. Only `rx_no_dma_resources`
  (drops) and the per-socket `XDP_STATISTICS` (getsockopt `SOL_XDP` /
  `XDP_STATISTICS`, surfaced by Runbound in `/api/system`) are reliable in ZC mode.
- **PCIe 2.0.** The 82599 is a PCIe 2.0 device; its effective host bandwidth sits
  below PCIe 3.0+ NICs of the same nominal 10 GbE line rate.
- **16-queue RETA cap.** RSS is capped at 16 queues in hardware regardless of core
  count. On a dual-socket host the *useful* queue count is further limited by
  cross-NUMA / QPI cost, capping practical throughput well under what the CPU could
  serve.

For new deployments prefer Intel **i40e** (X710/XL710), **ice** (E810) or **igc**:
they expose valid zero-copy counters and avoid the 82599 PCIe 2.0 / 16-queue
limits. The X520 stays perfectly fine for ordinary (non-XDP or low-rate)
DNS serving.

All requirements are configured automatically by `install.sh`.

## Startup log

```
INFO runbound::dns::xdp::loader: XDP program attached iface=eth0 link_id=...
INFO runbound::dns::xdp::worker: Starting XDP workers iface=eth0 queues=N
INFO runbound: XDP kernel-bypass fast path active iface=eth0
```

**virtio-net MTU warning** — emitted when `MTU > 3506` (virtio-net single-buffer limit).
DRV mode falls back to SKB mode automatically; no action required unless lower latency is needed:

```
WARN runbound::dns::xdp::worker: MTU exceeds virtio-net single-buffer XDP limit —
     DRV mode unavailable, falling back to SKB mode (higher latency).
     Reduce MTU to ≤3506 or accept SKB-mode operation. iface=eth0 mtu=9000 limit=3506
```

**Single-queue warning** — emitted on virtio-net VMs with a single RX queue and multiple CPUs.
XDP workers share queue 0 in locked TX mode. To improve throughput, set `queues=<N>` in the VM NIC config:

```
WARN runbound::dns::xdp::worker: virtio-net single-queue detected — XDP workers share queue 0
     in locked TX mode. For multi-queue performance set queues=<N> in the VM NIC config.
```

If XDP is unavailable, Runbound continues normally on the SO_REUSEPORT path:

```
WARN runbound: XDP disabled: <reason> — server running normally on SO_REUSEPORT path
```

## Shutdown and restart

The XDP program is attached via `BPF_LINK_CREATE` (fd-backed link). It is detached in two cases:

- **Graceful shutdown** (SIGTERM / `systemctl stop`) — Runbound's `Drop` implementation explicitly
  calls `Xdp::detach()` before the process exits. This prevents a race window during hot-restarts.
- **Crash / SIGKILL** — the kernel closes the link file descriptor on process exit, which
  automatically removes the XDP attachment. DNS traffic resumes on the kernel UDP stack immediately.

In both cases `bpftool prog list` and `ip link show` will show no XDP program after exit.

## Manual service file configuration

If not using `install.sh`, add to `/etc/systemd/system/runbound.service`:

```ini
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_XDP
MemoryDenyWriteExecute=false
ProtectKernelModules=false
LimitMEMLOCK=infinity
```

Then: `systemctl daemon-reload && systemctl restart runbound`

## IPv4 notes

The XDP program assumes a standard IPv4 header (IHL = 20, no options). Packets
with IP options are passed to the kernel via `XDP_PASS` — correct behavior,
transparent to clients.

## Virtual interfaces and XDP

AF_XDP binds to a physical NIC queue. It cannot attach to virtual interfaces
(bridge, bond, veth, ipvlan, macvlan, tun/tap) directly.

| Interface type | XDP support | Notes |
|---|---|---|
| Physical NIC (eth0, enp3s0) | ✅ native | Direct attachment |
| VLAN sub-interface (eth0.10, bond0.10) | ✅ via parent | Treated as physical |
| Bond slave / active-backup | ✅ via parent | Runbound auto-detects parent |
| Bridge port (vmbr0 port) | ✅ via port | Runbound resolves a physical bridge port |
| Bridge interface itself (vmbr0) | ⚠️ auto-retry | Runbound picks a physical port |
| veth pair | ❌ no parent NIC | Falls back to SO_REUSEPORT UDP |
| Loopback (lo) | ❌ | XDP not supported on loopback |

**Automatic parent resolution:** if Runbound detects the configured interface is
virtual, it searches for a physical parent in this order:

1. `lower_*` sysfs entries (ipvlan, macvlan)
2. `master` symlink (bond slave or bridge port)
3. `brif/` directory (ports of a bridge)

If a physical parent is found, XDP attaches there with a warning:

```
WARN runbound::dns::xdp::worker: XDP: virtual interface detected — retrying on parent virt=vmbr0 parent=eth0
INFO runbound: XDP active on parent interface parent=eth0
```

If no physical parent is found:

```
WARN runbound::dns::xdp::worker: XDP: virtual interface with no detectable parent — disabling XDP, falling back to UDP
```

**Proxmox / vmbr note:** attaching Runbound to a Proxmox bridge interface (`vmbr0`)
or an ipvlan will not break DNS — Runbound detects the virtual interface, resolves
a physical bridge port (e.g. `eth0`), and attaches XDP there. If the bridge has no
physical port (internal-only bridge), XDP is silently disabled and DNS continues on
the standard UDP path.

**Explicit fix:** to avoid the auto-detection overhead, bind Runbound directly to the
physical NIC or VLAN sub-interface:

```
server:
    interface: eth0          # physical NIC
    # or:
    interface: bond0.10      # VLAN sub-interface (XDP-capable)
```

## Proxmox / bare metal

Running Runbound on a Proxmox host requires extra care when the physical NIC
is enslaved to a bridge (`vmbr0`). In that configuration the kernel's bridge
`rx_handler` intercepts all incoming frames before XDP can see them — DNS traffic
arrives but is never delivered to the AF_XDP socket.

**Quick summary of required steps:**

1. Remove the physical bond from `vmbr0` (`ip link set bond0 nomaster`)
2. Use a dedicated IP for Runbound on a veth pair (not the Proxmox management IP)
3. For ixgbe / igc NICs, steer UDP/53 to queue 0 with `ethtool -N`

Full details, reference architecture, and troubleshooting: [docs/proxmox.md](proxmox.md)

## IRQ affinity

By default, the kernel distributes NIC interrupts across any available core. If queue N's IRQ fires on a different core than the XDP worker handling queue N, the packet data arrives in the wrong L1/L2 cache — guaranteed cache miss on every RX.

Runbound automates IRQ pinning at startup with `xdp-irq-affinity: auto`:

```
server:
    xdp-irq-affinity: auto    # default: off
```

When enabled, after spawning XDP workers Runbound reads `/proc/interrupts` to locate the IRQ numbers for the active NIC, then writes the matching core mask to `/proc/irq/<N>/smp_affinity_list` — queue N's IRQ → core N's XDP worker.

Requires `CAP_NET_ADMIN` (already required for XDP). Silent no-op if `/proc/irq/` is not writable (containers).

**Verify:**

```bash
# Queue 0 IRQ pinned to core 0
cat /proc/irq/$(grep -m1 eth0 /proc/interrupts | cut -d: -f1 | tr -d ' ')/smp_affinity_list
# → 0
```

---

## CPU governor pinning (`xdp-cpu-governor`, #158)

By default, Linux uses `schedutil` or `powersave` governors which ramp CPU frequency
up/down based on utilisation. DNS traffic is inherently bursty at microsecond scale —
the frequency ramp-up latency (~50–200 µs depending on the platform) adds measurable
jitter to the first packets of each burst, visible as p99 spikes.

`xdp-cpu-governor: performance` pins each XDP worker core to the `performance` governor
for the lifetime of the process and restores the original governor on clean shutdown:

```
server:
    xdp-cpu-governor: performance   # none (default) | performance
```

**Behaviour:**
- Reads `/sys/devices/system/cpu/cpuN/cpufreq/scaling_governor` for each worker core,
  saves the value, writes `performance`.
- On shutdown (clean or signal), the original governor is restored via `Drop`
  (same discipline as XDP program detach).
- **Silent no-op** when `cpufreq` sysfs is absent (KVM/VMs without host CPU pass-through,
  containers). A `WARN` is emitted but startup continues normally.
- Requires root or `CAP_SYS_ADMIN` to write `scaling_governor`. Individual cores that
  cannot be pinned are skipped with a `WARN`; others are pinned normally.

**Verify:**
```bash
# While Runbound is running — should show 'performance' on XDP cores:
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
# → performance

# After shutdown — restored to original:
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
# → schedutil
```

**When to use:** bare-metal deployments with variable load where `schedutil` is the default.
Not useful in VMs (no cpufreq control) or when the host is already pinned to `performance`
via a system-level tuning profile (e.g. `tuned -p throughput-performance`).

---

## NIC ring buffer auto-sizing

Intel ixgbe cards (X520, X540, X710) ship with a default RX ring of **512 descriptors**.
At 10 M QPS that represents only 51 µs of tolerance before the hardware FIFO overflows —
packets are dropped silently before the XDP program ever sees them
(`rx_no_buffer_count` increments in `ethtool -S`, zero Runbound log).

At startup, Runbound calls `SIOCETHTOOL` (kernel ioctl, no libnetlink dependency) to:

1. **GET** `ETHTOOL_GRINGPARAM` — read `rx_max_pending` / `tx_max_pending` from the driver
2. **SET** `ETHTOOL_SRINGPARAM` — apply the maximum supported ring depth before XDP attach

```
[INFO]  xdp: NIC ring ens18 rx 512→4096 tx 256→4096
[INFO]  xdp: fill ring 4096 · rx ring 4096 · tx ring 4096
```

If the resize fails (insufficient privileges, virtual NIC, cloud hypervisor):

```
[WARN]  xdp: ring resize failed on ens18 — Operation not permitted
```

The server continues normally with the driver default — performance degrades under extreme
load but the service remains functional.

**Verify post-startup:**

```bash
ethtool -g enp4s0 | grep "RX:"               # → 4096
ethtool -S enp4s0 | grep rx_no_buffer_count  # → 0 under load
```

**Monitor via API:**

```bash
curl -s -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/system \
  | python3 -c "import sys,json; s=json.load(sys.stdin); \
    print(f'ring {s[\"nic_rx_ring\"]}/{s[\"nic_rx_ring_max\"]}  dropped {s[\"nic_rx_dropped\"]}')"
```

Config override — force a specific ring size:

```
server:
    xdp-ring-size: 4096    # default: auto
```

---

## Automatic queue scaling (#169, v0.11.0)

Before attaching XDP, Runbound sets the NIC's `combined` queue count so the workers
spread across the available CPU cores — no manual `ethtool -L` required.

- **Modern CPUs** — the queue count is raised to the NIC hardware maximum
  (`ETHTOOL_SCHANNELS`), capped by the number of physical cores and the AF_XDP /
  XSKMAP per-NIC budget.
- **Xeon v2 + X520** (Ivy Bridge-EP + Intel 82599) — the `ixgbe` driver default
  (~16) is kept. This platform is PCIe-bus-bound at roughly 16 cores; adding more
  queues there only adds cross-core contention without raising throughput.
  Detection is automatic (CPU family 6 / model 62 + the `ixgbe` driver).

The change is applied once at startup, before the XDP program is attached (a queue
change resets the NIC). If the driver does not support `ETHTOOL_SCHANNELS`, Runbound
leaves the queue count untouched and continues.

## Expected QPS

| Hardware | Mode | Estimated peak |
|---|---|---|
| VM virtio (Proxmox/KVM) | copy mode | ~500k–1M QPS (theoretical) |
| Bare metal Intel 10GbE | native zero-copy | **~10.1 M QPS measured** (single X520, PCIe-2.0 RX-bound) — see [benchmark/INDEX.md](benchmark/INDEX.md) |

Wire speed on 10GbE = ~14.88M 64-byte packets/second (physical limit, not yet validated end-to-end).

---

## ICMP echo responder

When XDP is active, Runbound can respond to ICMP echo requests (ping) at the driver layer —
before the packet reaches the kernel network stack. This is controlled by the `icmp` block
in `runbound.conf`.

### How it works

```
NIC → XDP program → ICMP echo? → rate limit check → swap MACs/IPs → XDP_TX
                                                    ↓ (over limit)
                                                  XDP_DROP
```

The XDP program intercepts IPv4 ICMP echo requests (type 8). It:
1. Validates IP header (IHL=5, no options — packets with IP options pass to kernel)
2. Looks up the source IP in a per-CPU LRU rate-limit map
3. If under burst/rate limit: modifies the packet in-place (swap MACs/IPs, set type=0, update checksum) and returns `XDP_TX`
4. If over limit: drops with `XDP_DROP`, increments `rate_limited` counter

No system calls, no kernel IP stack, no userspace context switches.

### Configuration

```
icmp {
    enable:           yes
    rate-limit:       20     # pings/s per source IP
    rate-limit-burst: 8      # initial burst tokens for new IPs
}
```

### BPF maps

| Map | Type | Max entries | Purpose |
|---|---|---|---|
| `icmp_cfg` | ARRAY (1 entry) | 1 | Live config: enabled, rate_pps, burst |
| `icmp_stats` | PERCPU_ARRAY | 4 counters | handled/replied/dropped/rate_limited |
| `icmp_rate_limit` | LRU_HASH | 65536 | Per-source-IP token bucket state |

Stats and config are accessible via REST API (see [api.md](api.md)).

---

## Multi-interface XDP (`xdp-interface: nic2,nic3` / `auto`)

Runbound can bind AF_XDP simultaneously on N independent NICs. Each interface
gets its own socket set, UMEM regions, and worker thread pool.

### Configuration

```yaml
server:
    xdp-interface: nic2,nic3   # explicit list (comma-separated, no spaces)
    # or
    xdp-interface: auto        # enumerate all eligible physical interfaces
```

### Auto-detection eligibility

`auto` mode enumerates `/sys/class/net/` and binds all interfaces that are:
- **UP** (IFF_UP flag set)
- **Physical** (has `/sys/class/net/<iface>/device` symlink)
- **Not excluded**: `lo`, `vmbr*`, `br*`, `tap*`, `veth*`
- **Not bonded** (master bond or slave) — AF_XDP is incompatible with bonding;
  a WARN is logged: `skipping bonded interface X — XDP incompatible with bonding`

### Bonding incompatibility

XDP zerocopy requires direct access to the NIC's RX ring queues. A bond master
virtualises these queues, making AF_XDP ZC impossible. Use independent physical
NICs, never a bond master, for multi-interface XDP.

### Logs

```
INFO  XDP active on 2 interface(s) interfaces=["nic2", "nic3"]
INFO  XDP fast path active iface=nic2 mode=Drv
INFO  XDP fast path active iface=nic3 mode=Drv
WARN  XDP auto: skipping bonded interface bond0 — XDP incompatible with bonding
```

---

## #162 — Kernel path scaling and RPS guidance (X520/ixgbe)

### Kernel path (xdp: no) — no XDP caps applied

When running without XDP (`xdp: no`), Runbound uses Tokio's multi-thread
runtime with one thread per physical core (HT excluded). No queue cap derived
from XDP is applied to the kernel path — it scales to all available cores.

### RSS hardware limit on X520/82599

The Intel X520 (82599 chip) supports a maximum of **16 RSS RX queues** in
hardware. In XDP mode, Runbound auto-detects this and binds up to 16 XSK
sockets (one per queue). No manual configuration is required.

On other NICs (e.g. Intel E810, Mellanox CX-5, AMD) with more than 16 queues,
Runbound scales automatically to the available queue count.

### RPS must NOT be enabled on X520 (kernel path)

**Measured regression: −46% throughput (1.33M → 720k qps) when RPS is active
on X520.**

RPS (Receive Packet Steering) is a software mechanism to distribute RX softirqs
across CPUs. On X520, the hardware RSS already distributes packets efficiently
across 16 queues — adding RPS introduces IPI (inter-processor interrupts) and
cache-bounce overhead without benefit, because the softirq processing was not
the bottleneck.

```bash
# Verify RPS is OFF on X520 (all queues should show 0 or 00000000)
cat /sys/class/net/<iface>/queues/rx-*/rps_cpus
# Expected: 00000000 (or 0) for all queues — DO NOT set to fff...
```

If RPS was previously enabled:
```bash
for f in /sys/class/net/<iface>/queues/rx-*/rps_cpus; do echo 0 > $f; done
```

### cpu-affinity default changed to 'no' (#163)

Measured on Xeon E5-2690 v2 + X520 (kernel path, 5-run medians):
- `cpu-affinity: yes` (old default): **630k qps**
- `cpu-affinity: no` (new default):  **874k qps** (+39%)
- `taskset 0-19` (physical):         **713k qps**

The floating scheduler (OS-managed) outperforms naive thread pinning on this
architecture because Tokio's work-stealing adapts to load imbalance dynamically.
The new default is `cpu-affinity: no`.

### #164 — NIC/bus-bound detection (rx_missed_errors)

On Xeon v2 + X520, XDP can saturate at ~16 cores while still showing
significant CPU headroom. This is a **NIC/PCIe-bus ceiling**, not a software
limit. The indicator is `rx_missed_errors` rising while CPU stays below 60%.

Runbound exposes these counters in `/api/system`:
```json
{
  "nic_rx_missed": 5700000,
  "nic_rx_no_dma": 0,
  "nic_rx_dropped": 5700000
}
```

A WARN is logged every 60 seconds when `rx_missed_errors > 0`:
```
WARN [XDP-HEALTH] NIC dropping frames — likely NIC/PCIe-bus-bound
     iface=nic3 rx_missed=5700000/60s rx_no_dma=0/60s
```

At startup on Xeon v2 + X520:
```
WARN host likely NIC/PCIe-bus-bound (Xeon v2 + X520 ~16-core bus ceiling) —
     CPU headroom is expected; rx_missed_errors is the real throughput wall.
```
