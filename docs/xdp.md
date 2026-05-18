# XDP Kernel-Bypass Fast Path

Runbound includes an AF_XDP fast path that bypasses the Linux kernel network
stack entirely. On supported hardware, DNS queries are handled at the NIC
driver level with zero syscalls on the hot path.

Estimated peak QPS on a 10 GbE Intel NIC: **~14 million** (wire speed for 64-byte DNS packets).

---

## Requirements

| Requirement | Details |
|---|---|
| Hardware | Intel NIC with native XDP support (ixgbe, i40e, ice, igc, igb drivers) |
| Kernel | Linux 5.10+ (6.x recommended) |
| Privileges | `CAP_NET_RAW`, `CAP_NET_ADMIN`, `CAP_BPF` |
| Address family | `AF_XDP` must be allowed in systemd service |
| Build | `--features xdp` (all official binaries include this) |

---

## Not supported

- VMs with virtio NICs (Proxmox, KVM, VMware) — AF_XDP socket creation fails
- Broadcom / Realtek NICs — no native XDP driver support
- Containers without `CAP_NET_ADMIN`

---

## What XDP changes

Without XDP, Runbound already uses SO_REUSEPORT with one UDP socket per
physical core. XDP goes further — UDP/port-53 packets are redirected to
userspace before they enter the kernel network stack.

**With SO_REUSEPORT only:** kernel stack → UDP socket → Tokio → response  
**With XDP:** NIC driver → UMEM ring → Runbound worker → response (zero kernel involvement)

---

## Performance

| Mode | Throughput | Latency (avg) |
|---|---|---|
| SO_REUSEPORT (standard) | 200k – 500k q/s | 1–5 ms |
| AF/XDP (driver mode) | **500k – 14M+ q/s** | < 0.5 ms |

Driver mode requires a native-XDP Intel NIC. On any other hardware the binary
falls back to SO_REUSEPORT automatically — no crash, no silent failure.

---

## Service file changes

The `install.sh` script enables XDP capabilities automatically when an Intel
NIC is detected at install time. For manual installs, add to
`/etc/systemd/system/runbound.service`:

```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_XDP
MemoryDenyWriteExecute=false
ProtectKernelModules=false
```

Then reload:

```bash
systemctl daemon-reload && systemctl restart runbound
```

---

## Verifying XDP is active

```bash
journalctl -u runbound | grep XDP
# Expected: INFO runbound: XDP kernel-bypass fast path active iface=eth0
```

If you see:

```
WARN runbound::dns::server: XDP not available (continuing without): ...
```

Check: correct NIC driver, capabilities granted, `AF_XDP` in `RestrictAddressFamilies`.

---

## Troubleshooting

**`EPERM` on startup:**
```bash
# Grant required capabilities (alternative to systemd unit changes)
setcap 'cap_net_admin,cap_bpf=eip' /usr/local/sbin/runbound
```

**Falls back to SO_REUSEPORT instead of XDP:**
Check that your NIC driver supports native XDP:
```bash
ethtool -i eth0 | grep driver
# Look for: i40e, ixgbe, ice, igc, igb
```

**Poor performance in VM:**
VMs typically get SKB/copy mode, not driver mode. For driver-mode performance,
use bare metal or pass through the NIC with SR-IOV.

---

## Security in XDP mode

The XDP fast path applies the **same ACL and rate-limiting rules** as the
standard path. ACL `deny` → silent drop; ACL `refuse` → REFUSED response
crafted directly in the XDP worker. There is no security bypass.
