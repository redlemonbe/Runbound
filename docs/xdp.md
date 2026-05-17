# AF/XDP Fast Path

Runbound includes an optional AF/XDP (kernel-bypass) networking path that delivers
**500,000 – 1,000,000+ queries per second** on bare-metal servers with compatible NICs.

---

## What is AF/XDP?

AF/XDP (Address Family eXpress Data Path) allows Runbound to receive and send UDP
packets directly from userspace, bypassing the kernel network stack entirely.
No syscalls per packet, no socket overhead, no interrupt processing.

The XDP path is completely optional. On hardware that doesn't support it, or when
the `xdp` feature is not compiled in, Runbound falls back to standard UDP sockets
automatically.

---

## Requirements

- Linux kernel **5.4+** (6.x recommended)
- NIC with XDP driver support (Intel i40e, ixgbe, mlx5, virtio-net in recent kernels)
- Running as **root** or with `CAP_NET_ADMIN` + `CAP_BPF`
- Build with `--features xdp`

**Compatible NICs (XDP driver mode — maximum performance):**
- Intel X710 / XXV710 / E810 (i40e / ice driver)
- Intel 82599 / X540 / X550 (ixgbe driver)
- Mellanox ConnectX-4/5/6 (mlx5 driver)
- virtio-net (recent kernels, QEMU/KVM)

**Fallback (SKB/generic mode — slower but universally supported):**
Any NIC with a kernel driver. Performance is lower than driver mode but still
better than standard sockets on high-traffic interfaces.

---

## Build with XDP support

```bash
# Prerequisites
apt-get install -y clang llvm libelf-dev linux-headers-$(uname -r)

# Build
cargo build --release --features xdp

# Install
sudo install -m 755 target/release/runbound /usr/local/bin/runbound
```

---

## Configuration

No config file changes needed. XDP activates automatically on supported hardware
when the binary is built with `--features xdp`.

To force XDP mode (fail if not available):

```bash
runbound --config /etc/runbound/runbound.conf --xdp-required
```

To disable XDP explicitly (fall back to standard sockets):

```bash
runbound --config /etc/runbound/runbound.conf --no-xdp
```

---

## Performance benchmark

Test environment: bare-metal server, Intel X710 10GbE, 16 cores, Linux 6.8.

```bash
# Install dnsperf
apt-get install -y dnsperf

# Generate query file
python3 -c "
for i in range(10000):
    print(f'host{i}.internal. A')
" > /tmp/queries.txt

# Run benchmark
dnsperf -s 10.0.0.1 -p 53 -d /tmp/queries.txt -l 60 -c 50 -Q 2000000
```

| Mode | Throughput | Latency (avg) |
|---|---|---|
| Standard sockets | ~80,000 q/s | 1–5 ms |
| AF/XDP (SKB mode) | ~200,000 q/s | < 1 ms |
| AF/XDP (DRV mode) | **500k – 1M+ q/s** | < 0.5 ms |

---

## Security in XDP mode

The XDP fast path applies the **same ACL and rate-limiting rules** as the standard
path. ACL `deny` → silent drop; ACL `refuse` → REFUSED response crafted directly
in the XDP worker. There is no security bypass.

---

## Verify XDP is active

```bash
# Check logs at startup — XDP activation is logged there
journalctl -u runbound | grep -i xdp
# → XDP fast path active on eth0 (driver mode)

# Throughput verification: XDP will push the /stats total counter much faster
# than standard sockets under the same load
curl -s http://localhost:8081/stats -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

---

## Troubleshooting

**`EPERM` on startup:**
```bash
# Grant required capabilities
setcap 'cap_net_admin,cap_bpf=eip' /usr/local/bin/runbound
```

**Falls back to SKB mode instead of driver mode:**
Check that your NIC driver supports native XDP:
```bash
ethtool -i eth0 | grep driver
# Look for: i40e, ixgbe, mlx5_core, virtio_net
```

**Poor performance in VM:**
VMs typically get SKB mode. For driver-mode performance, use bare metal or
pass through the NIC with SR-IOV.
