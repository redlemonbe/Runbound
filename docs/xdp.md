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

## Requirements

| Item | Details |
|---|---|
| Kernel | Linux 5.10+ (6.x recommended) |
| Capabilities | `CAP_NET_RAW`, `CAP_NET_ADMIN`, `CAP_BPF` |
| Address family | `AF_XDP` in `RestrictAddressFamilies` |
| Locked memory | `LimitMEMLOCK=infinity` |
| NIC (optimal) | Intel ixgbe / i40e / ice / igc (native zero-copy) |
| NIC (supported) | virtio, any NIC with XDP copy-mode support |

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

## Expected QPS

| Hardware | Mode | Estimated peak |
|---|---|---|
| VM virtio (Proxmox/KVM) | copy mode | ~500k–1M QPS (theoretical) |
| Bare metal Intel 10GbE | native zero-copy | TBD — benchmark in progress (results coming in v0.8) |

Wire speed on 10GbE = ~14.88M 64-byte packets/second (physical limit, not yet validated end-to-end).
