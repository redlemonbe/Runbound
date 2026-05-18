# XDP Kernel-Bypass Fast Path

Runbound v0.4.14+ includes an AF_XDP fast path active by default in all binaries.

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

## Expected QPS

| Hardware | Mode | Estimated peak |
|---|---|---|
| VM virtio (Proxmox/KVM) | copy mode | ~500k–1M QPS |
| Bare metal Intel 10GbE | native zero-copy | ~14M QPS (wire speed) |

Wire speed on 10GbE = ~14.88M 64-byte packets/second.
