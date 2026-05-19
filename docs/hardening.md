# Security Hardening Guide

This document lists every security-sensitive parameter in Runbound's systemd
service file and explains what breaks silently if it is missing or misconfigured.

**Quick check:** run this after every install or update:

```bash
runbound --check-config /etc/runbound/unbound.conf
```

---

## Capabilities

| Parameter | Effect if missing |
|---|---|
| `CAP_NET_BIND_SERVICE` | Cannot bind to port 53 — server fails to start |
| `CAP_NET_RAW` | XDP disabled silently — server runs normally on SO_REUSEPORT fallback |
| `CAP_NET_ADMIN` | XDP disabled silently |
| `CAP_BPF` | XDP disabled silently |

The recommended way to grant capabilities to the binary (without running as root):

```bash
sudo setcap cap_net_bind_service,cap_net_raw,cap_net_admin,cap_bpf+eip $(which runbound)
```

Or via systemd unit:

```ini
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF
```

---

## Address families

| Parameter | Effect if missing |
|---|---|
| `AF_INET AF_INET6` | Server cannot open UDP/TCP sockets — fails to start |
| `AF_UNIX` | API socket unavailable |
| `AF_XDP` | XDP disabled silently — server runs normally without it |

Correct `RestrictAddressFamilies` line for a server with XDP:

```ini
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_XDP
```

---

## Locked memory

| Parameter | Effect if missing |
|---|---|
| `LimitMEMLOCK=infinity` | AF/XDP UMEM allocation fails — XDP disabled silently |

```ini
[Service]
LimitMEMLOCK=infinity
```

This is required because the AF/XDP UMEM region is a large shared memory area
that the kernel must pin (lock) in RAM. Without this limit, `mmap(MAP_LOCKED)`
fails with `ENOMEM` and the XDP path is silently skipped.

---

## eBPF / kernel hardening

| Parameter | Value needed for XDP | Effect if wrong value |
|---|---|---|
| `MemoryDenyWriteExecute` | `false` | eBPF JIT compilation blocked — XDP disabled silently |
| `ProtectKernelModules` | `false` | eBPF program loading blocked — XDP disabled silently |

```ini
[Service]
MemoryDenyWriteExecute=false
ProtectKernelModules=false
```

These two directives are commonly set to `true` in hardened systemd profiles.
They must be relaxed for the eBPF XDP program to load. All other kernel hardening
directives (`ProtectKernelTunables`, `ProtectKernelLogs`, `ProtectClock`, etc.)
can remain enabled.

---

## Configuration file

| Parameter | Effect if misconfigured |
|---|---|
| `rate-limit: 0` | Rate limiting disabled — all source IPs have unlimited query rate |
| `rate-limit: 200` | Recommended default for home / residential resolvers |
| `rate-limit: 5000` | Recommended for shared or production resolvers |

> **Version note:** in v0.4.6 and below, `rate-limit: 0` set the bucket to 0 tokens
> and refused every query. Fixed in v0.4.7 — `0` now correctly means unlimited.

---

## Verifying security at startup

Check the following lines appear in logs after every install or update:

```bash
journalctl -u runbound | grep -E "XDP|affinity|cache|socket|rate"
```

Expected output:

```
INFO runbound: CPU affinity enabled — physical cores (HT excluded) cores=N
INFO runbound::dns::server: cache size auto-sized from MemAvailable cache_size=N
INFO runbound::dns::server: DNS UDP listening (SO_REUSEPORT) addr=0.0.0.0:53 sockets=N
INFO runbound: XDP kernel-bypass fast path active iface=ethX
INFO runbound::dns::server: rate limiting disabled   ← or: rate limiting enabled limit=N
```

**If `XDP kernel-bypass fast path active` is absent**, check the following in order:

1. `runbound --check-config /etc/runbound/unbound.conf` — will identify the exact missing parameter
2. Capabilities: `cat /proc/$(pgrep runbound)/status | grep CapEff`
3. `AF_XDP` in `RestrictAddressFamilies`
4. `LimitMEMLOCK=infinity` in the service file
5. `MemoryDenyWriteExecute=false` and `ProtectKernelModules=false`

---

## Complete hardened service file (with XDP)

```ini
[Unit]
Description=Runbound DNS Server
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/runbound /etc/runbound/unbound.conf
Restart=on-failure
RestartSec=5

User=runbound
Group=runbound

# Capabilities — port 53 + XDP kernel-bypass
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF
NoNewPrivileges=yes

# XDP requires AF_XDP + unlocked memory + eBPF JIT
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_XDP
LimitMEMLOCK=infinity
MemoryDenyWriteExecute=false
ProtectKernelModules=false

# General hardening (compatible with XDP)
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
```

---

See [security.md](security.md) for the full security model and audit findings.
