# Proxmox / Bare-Metal XDP Setup

This guide covers production deployment of Runbound with AF/XDP on Proxmox hosts
with LACP bonding (ixgbe / igc NICs). The same principles apply to any bare-metal
setup with a complex virtual network topology.

---

## 1. The Proxmox bridge conflict

### Problem

A typical Proxmox network looks like this:

```
NIC (ixgbe) → bond0 LACP → vmbr0 (bridge, bridge-ports bond0)
```

When `bond0` is a bridge port of `vmbr0`, the kernel installs a `rx_handler` on
`bond0`. This handler intercepts **all** incoming Ethernet frames on `bond0` —
including VLAN-tagged frames destined for `bond0.10` — and redirects them to the
bridge. **AF/XDP never sees the packets.** The XDP program attaches successfully,
but DNS traffic never arrives at the AF_XDP socket.

### Fix

Remove `bond0` from `vmbr0`:

```bash
# Runtime (immediate, no reboot):
ip link set bond0 nomaster
```

In `/etc/network/interfaces`, set `bridge-ports none` for the Proxmox bridge:

```
auto vmbr0
iface vmbr0 inet static
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    address 192.168.10.201/24
    gateway 192.168.10.1
```

After this change, Proxmox VMs still use `vmbr0` for their virtual network — only
the physical bond is no longer enslaved to the bridge.

---

## 2. Why a dedicated IP is required

**Do not use the Proxmox host management IP** (e.g. `.201` on `vmbr0`) for Runbound.

When two interfaces share the same `/24` subnet, the kernel's routing table maps
the subnet to the first interface it finds (typically the one with the lower
interface index). Runbound's interface auto-detection reads the routing table and
may select the wrong interface — `vmbr0` instead of `veth-rb`, for example.

Using a dedicated IP on a dedicated interface eliminates the routing ambiguity:

- Proxmox host management: `vmbr0` → `192.168.10.201/24`
- Runbound: `veth-rb` → `192.168.10.250/24` (separate interface)

Runbound's `iface_for_ip()` uses `getifaddrs()` to find exactly the interface that
carries the configured IP, bypassing the routing table entirely.

---

## 3. Working reference architecture

```
Physical NIC (ixgbe / igc)
  └── bond0  (LACP / active-backup)
        └── bond0.10  (VLAN 10, no IP assigned)
              └── br-rb  (bridge, bridge-ports bond0.10)
                    ├── veth-bnd  ↔  veth-rb  (IP .250/24)  ← Runbound XDP here
                    └── br-rb itself (IP .201/24) ← Proxmox management / BIND9 / Unbound
```

`unbound.conf` for Runbound:

```
server:
    interface: 192.168.10.250
    port: 53
```

Runbound resolves `192.168.10.250` to `veth-rb` via `getifaddrs()` and attaches
XDP there. `veth-rb` is a virtual interface, so the automatic parent resolution
finds `bond0.10` (VLAN sub-interface on a physical NIC) and attaches AF/XDP
on `bond0.10`.

BIND9 / stock Unbound can listen on `br-rb` (`.201`) simultaneously for
comparison benchmarks — they are unaffected.

---

## 4. XDP on VLAN sub-interfaces — known limitation

AF/XDP **generic mode** on `bond0.10` or on an `ipvlan` device silently drops
packets after a failed `xsk_generic_rcv` call. The kernel does `kfree_skb` on
the packet, and **`XDP_PASS` fallback is NOT honoured** — the packet is gone.

**Symptom:** XDP attaches successfully, no errors in logs, but DNS queries
sent to port 53 receive no response.

**Workaround:** use a `veth` pair attached to a bridge port of the VLAN
sub-interface (as shown in the reference architecture above). `veth` devices
support the full AF/XDP path including proper `XDP_PASS` fallback.

To check which XDP mode is active:

```bash
ip link show veth-rb
# look for "xdp" in the output — "xdpgeneric" means generic mode (avoid),
# "xdp" alone means driver/native mode (preferred)
```

---

## 5. ethtool flow steering (recommended for ixgbe / igc)

By default, the NIC distributes incoming packets across all RX queues using RSS.
DNS traffic (UDP port 53) can land on any queue, but Runbound's XDP worker is
pinned to queue 0 for lowest latency.

Steer all UDP/port-53 traffic to queue 0:

```bash
# Enable ntuple filters
ethtool -K enp33s0f0 ntuple on

# Steer UDP dst-port 53 to queue 0
ethtool -N enp33s0f0 flow-type udp4 dst-port 53 action 0
```

Replace `enp33s0f0` with your physical NIC name (not the bond or VLAN interface).

**Why this matters:** ensures all DNS queries land on the single XDP worker thread
without inter-queue wakeups, maximising zero-copy throughput on single-queue setups.

To verify the rule was applied:

```bash
ethtool -n enp33s0f0
# Filter for driver: ntuple is supported and rule is active
```

To make it persistent across reboots, add it to `/etc/network/if-up.d/` or a
`@reboot` cron job.

---

## 6. RLIMIT_MEMLOCK

AF/XDP requires a large locked memory region (UMEM). If `RLIMIT_MEMLOCK` is
limited, the `mmap(MAP_LOCKED)` call fails silently and XDP is disabled.

**Manual startup (testing):**

```bash
ulimit -l unlimited
runbound /etc/runbound/unbound.conf
```

**Systemd service (production):**

`install.sh` sets `LimitMEMLOCK=infinity` automatically. For manual installs, add:

```ini
[Service]
LimitMEMLOCK=infinity
```

**Verify:**

```bash
# While Runbound is running:
cat /proc/$(pgrep runbound)/limits | grep -i memlock
# Expected: Max locked memory   unlimited
```

`runbound --check-config` checks `RLIMIT_MEMLOCK` and reports `[WARN]` if it is
limited and you are running under systemd (where the service file limit applies).
Outside systemd it reports `[INFO]` — the shell limit does not reflect what the
service file provides at runtime.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| XDP attaches but DNS gets no response | `bond0` enslaved to bridge (`rx_handler`) | `ip link set bond0 nomaster` |
| XDP attaches on wrong interface | Two interfaces on same subnet | Use specific IP in `interface:` directive |
| `XDP_PASS` drops instead of forwarding | Generic mode on VLAN/ipvlan | Use veth pair as in reference architecture |
| UMEM mmap fails | `RLIMIT_MEMLOCK` too low | `ulimit -l unlimited` or `LimitMEMLOCK=infinity` |
| XDP program verifier rejected | Missing `CAP_BPF` | `setcap cap_net_raw,cap_net_admin,cap_bpf+eip $(which runbound)` |

See also: [xdp.md](xdp.md), [hardening.md](hardening.md).
