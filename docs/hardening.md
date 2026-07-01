# Security Hardening Guide

This document lists every security-sensitive parameter in Runbound's systemd
service file and explains what breaks silently if it is missing or misconfigured.

**Quick check:** run this after every install or update:

```bash
runbound --check-config /etc/runbound/runbound.conf
```

---

## Capabilities

**Out of the box (v0.23.10, PENT-3 revised):** `xdp: yes` is the shipped default, so the
shipped `runbound.service` and `install.sh` grant the wider capability set by default —
`CAP_NET_RAW`/`CAP_NET_ADMIN`/`CAP_BPF`/`CAP_PERFMON` in addition to
`CAP_NET_BIND_SERVICE`. This doesn't enlarge the *lasting* blast radius: `CAP_BPF`/
`CAP_PERFMON` are only checked by the kernel at load time (see below) and are dropped
again right after XDP attaches, before the server answers a single query. A NIC/driver
that can't do AF_XDP (virtio-net, missing kernel support) falls back to the kernel path
on its own — no capability tuning needed for that case. The minimal
`CAP_NET_BIND_SERVICE`-only set is available as a **commented alternative** in the unit
file for deployments that explicitly set `xdp: no` and `firewall-manage: no`.

| Parameter | When needed | Effect if missing |
|---|---|---|
| `CAP_NET_BIND_SERVICE` | always (bind :53) | Cannot bind to port 53 — server fails to start |
| `CAP_NET_RAW` | XDP only | XDP disabled silently — server runs normally on SO_REUSEPORT fallback |
| `CAP_NET_ADMIN` | XDP + firewall-manage | XDP / firewall-manage disabled silently |
| `CAP_BPF` | XDP only, load-time only | XDP disabled silently |
| `CAP_PERFMON` | XDP only, load-time only | eBPF load may fail — XDP disabled silently |

**`CAP_BPF`/`CAP_PERFMON` are dropped right after XDP setup completes.** These two
are only required for the one-time `BPF_MAP_CREATE`/`BPF_PROG_LOAD` sequence at
startup — every runtime BPF operation afterwards (ICMP ban/unban, blacklist reload,
XSKMAP registration) goes through an fd the process already holds, which the kernel
does not re-check against capabilities. Runbound drops both from
Effective/Permitted/Inheritable/Ambient immediately after XDP load/attach, before the
server starts answering queries (`src/caps_drop.rs`) — so even if the process is
later remote-code-executed, CAP_BPF/CAP_PERFMON are no longer available to it or any
child process for the rest of its lifetime. Look for
`CAP_BPF/CAP_PERFMON dropped post-XDP-setup` in the logs to confirm. This is a
best-effort defence-in-depth step (never fatal if the drop fails) and does not
replace granting the capabilities correctly at startup — see the table above.

**Default (XDP + firewall-manage) — what the shipped unit uses:**

```ini
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF CAP_PERFMON
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF CAP_PERFMON
```

**No XDP, no firewall-manage — switch to the minimal set instead:**

```ini
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

To grant the XDP capabilities to the binary directly (without running as root):

```bash
sudo setcap cap_net_bind_service,cap_net_raw,cap_net_admin,cap_bpf,cap_perfmon+eip $(which runbound)
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
journalctl -u runbound | grep -E "XDP|CPU placement|cache|rate"
```

Expected output:

```
INFO runbound: CPU placement: automatic (OS scheduler + XDP NUMA-local pin) cores=N
INFO runbound::dns::server: cache size auto-sized from MemAvailable cache_size=N
INFO runbound::dns::xdp::worker: XDP fast path active (core block assigned) iface=ethX mode=... core_base=N queue_count=N cores=[...]
INFO runbound::dns::server: rate limiting disabled (rate-limit: 0)   ← or: DNS rate limiter configured rps=N burst=N
```

**If `XDP fast path active` is absent**, check the following in order:

1. `runbound --check-config /etc/runbound/runbound.conf` — will identify the exact missing parameter
2. Capabilities: `cat /proc/$(pgrep runbound)/status | grep CapEff`
3. `AF_XDP` in `RestrictAddressFamilies`
4. `LimitMEMLOCK=infinity` in the service file
5. `MemoryDenyWriteExecute=false` and `ProtectKernelModules=false`
6. `xdp: no` not set in `runbound.conf` and `--no-xdp` not passed on the command line

**Virtual interfaces (Proxmox vmbr, ipvlan, veth):** attaching Runbound to a Proxmox
bridge interface (`vmbr0`) or an ipvlan will not silently break DNS — Runbound detects
virtual interfaces at startup, resolves a physical parent where possible (e.g. the first
physical port of `vmbr0`), and attaches XDP there. If no physical parent is found, XDP
is disabled gracefully and DNS continues on the `SO_REUSEPORT` path. No capability
changes or config edits are required. See [xdp.md](xdp.md) for details.

**To deliberately disable XDP** (containers, restricted VMs, troubleshooting) without touching
systemd capabilities, add to `runbound.conf`:

```
server:
    xdp: no
```

Or pass `--no-xdp` on the command line. The server logs
`INFO runbound: XDP fast path disabled (xdp: no / --no-xdp)` and continues on the
`SO_REUSEPORT` path. No capability changes needed.

---

## Complete hardened service file (with XDP)

This is the **actual shipped `runbound.service`** (repo root), exactly as installed —
the XDP capability lines are the default, not an opt-in. The narrower
`CAP_NET_BIND_SERVICE`-only set (for `xdp: no` / `firewall-manage: no` deployments) is
present as a commented alternative in the shipped file — swap the two
`AmbientCapabilities`/`CapabilityBoundingSet` lines below for that if you want it.

```ini
[Unit]
Description=Runbound DNS Server
Documentation=https://github.com/redlemonbe/Runbound
After=network-online.target
Wants=network-online.target
ConditionFileNotEmpty=/etc/runbound/runbound.conf

[Service]
Type=simple
User=runbound
Group=runbound
EnvironmentFile=-/etc/runbound/env
# Huge pages for the XDP/AF_XDP UMEM: reserved once at boot (needs root via
# ExecStartPre=+), consumed unprivileged by the runbound user. 0 = disabled.
Environment=RUNBOUND_HUGEPAGES_2M=0
ExecStartPre=+/bin/sh -c '[ "${RUNBOUND_HUGEPAGES_2M:-0}" = 0 ] || echo "${RUNBOUND_HUGEPAGES_2M}" > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages 2>/dev/null || true'
ExecStart=/usr/local/sbin/runbound /etc/runbound/runbound.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s

# Capabilities — port 53 + XDP kernel-bypass (the shipped default).
# NOTE: for an xdp:no / firewall-manage:no deployment, use the narrower
# CAP_NET_BIND_SERVICE-only set instead (see the Capabilities section above).
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF CAP_PERFMON
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF CAP_PERFMON

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes

# XDP requires AF_XDP + unlocked memory + eBPF JIT
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_XDP
MemoryDenyWriteExecute=false
ReadWritePaths=/etc/runbound /var/lib/runbound
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```

The shipped unit deliberately does **not** set `ProtectKernelModules`,
`ProtectKernelLogs`, `ProtectClock`, `ProtectControlGroups`, `RestrictRealtime`,
`RestrictSUIDSGID`, or `LockPersonality`. `ProtectKernelModules=false` would be needed
if you add it, since `true` blocks eBPF program loading (see the eBPF / kernel
hardening section above); the others are optional extensions you can layer on
top — verify each doesn't break XDP before enabling it in production.

---

See [security.md](security.md) for the full security model and audit findings.

See [proxmox.md](proxmox.md) for Proxmox bare-metal XDP setup, bridge conflict resolution, and ethtool flow steering.
