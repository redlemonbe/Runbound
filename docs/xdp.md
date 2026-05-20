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

There are three ways to disable the XDP fast path, depending on the context:

| Method | When to use |
|---|---|
| `xdp: no` in `unbound.conf` | Persistent disable — survives restarts |
| `runbound --no-xdp [config]` | One-shot disable without editing config |
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

Both produce the same log line at startup:

```
INFO runbound: XDP fast path disabled (xdp: no / --no-xdp)
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

- **Local zones** → answered entirely in user space (zero syscalls, 0 ms latency)
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

If XDP is unavailable, Runbound continues normally:

```
WARN runbound: XDP disabled: <reason> — server running normally on SO_REUSEPORT path
```

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

## Expected QPS

| Hardware | Mode | Estimated peak |
|---|---|---|
| VM virtio (Proxmox/KVM) | copy mode | ~500k–1M QPS |
| Bare metal Intel 10GbE | native zero-copy | ~14M QPS (wire speed) |

Wire speed on 10GbE = ~14.88M 64-byte packets/second.
