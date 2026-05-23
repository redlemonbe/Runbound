# Systemd Setup

Production-hardened systemd unit for Runbound.

---

## Service file

Create `/etc/systemd/system/runbound.service`:

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
EnvironmentFile=/etc/runbound/env
ExecStart=/usr/local/sbin/runbound /etc/runbound/unbound.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s

# Capabilities — CAP_NET_ADMIN + CAP_BPF required for XDP attach
# CAP_NET_RAW required for AF_XDP socket
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF

# AF_XDP socket family
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_XDP

# Hardening
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=no        # eBPF JIT requires kernel module access
ProtectControlGroups=yes
ReadWritePaths=/etc/runbound /var/log/runbound
MemoryDenyWriteExecute=no      # required for eBPF JIT compilation
LimitNOFILE=131072             # 32× SO_REUSEPORT sockets + XDP sockets + DoT connections
LimitNPROC=4096                # cap on XDP worker threads (max 64) + tokio pool
LimitMEMLOCK=infinity          # required for AF_XDP UMEM mmap

# Optional: pre-allocate hugepages before Runbound starts (recommended in production)
# Uncomment and adjust the count to match xdp-hugepages in runbound.conf
# ExecStartPre=/usr/sbin/sysctl -w vm.nr_hugepages=512

[Install]
WantedBy=multi-user.target
```

---

## Setup

> **Recommended:** use `install.sh` — it handles all of the steps below automatically
> (user creation, directories, API key generation, service installation).
> The manual procedure below is for deployments that cannot use the installer.

```bash
# 1. Create the system user
useradd -r -s /sbin/nologin -d /etc/runbound runbound

# 2. Create directories
mkdir -p /etc/runbound /var/log/runbound
chown runbound:runbound /etc/runbound /var/log/runbound
chmod 750 /etc/runbound

# 3. Create the environment file (API key — never in the config file)
echo "RUNBOUND_API_KEY=$(openssl rand -hex 32)" > /etc/runbound/env
chmod 640 /etc/runbound/env
chown runbound:runbound /etc/runbound/env

# 4. Install the binary
install -o root -g root -m 755 runbound /usr/local/sbin/runbound

# 5. Install the config (the file may be named runbound.conf or unbound.conf)
cp /path/to/unbound.conf /etc/runbound/unbound.conf
chown runbound:runbound /etc/runbound/unbound.conf
chmod 640 /etc/runbound/unbound.conf

# 6. Install the service
cp runbound.service /etc/systemd/system/
systemctl daemon-reload

# 7. Enable and start
systemctl enable --now runbound

# 8. Check status
systemctl status runbound
journalctl -u runbound -f
```

---

## Hot reload

Runbound supports zone reload without dropping any DNS connections.
Both methods re-read the config file and rebuild all in-memory DNS data atomically.
In-flight queries are not interrupted — they finish against the old snapshot.

```bash
# Via systemd (SIGHUP) — preferred for scripted use
systemctl reload runbound

# Via REST API — same effect as SIGHUP
curl -X POST http://localhost:8080/api/reload \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
# → {"status":"ok","cfg_path":"/etc/runbound/runbound.conf","local_zones":5,"local_data":12}
```

### What gets reloaded

| Component | Reloaded? | Notes |
|---|:---:|---|
| `local-zone` / `local-data` from config | ✅ | Re-parsed from disk |
| Persisted DNS entries (`POST /dns`) | ✅ | Read from `dns_entries.json` |
| Blacklist entries (`POST /blacklist`) | ✅ | Read from `blacklist.json` |
| Feed block-list entries | ✅ | Last cached version — fetch is not triggered |
| `access-control` ACL rules | ❌ | Restart required — ACL is built once at startup |
| `forward-zone` upstream resolvers | ❌ | Restart required |
| `interface` / `port` | ❌ | Socket rebind requires restart |
| `rate-limit` | ❌ | Restart required |
| `tls-service-pem` / `tls-service-key` | ❌ | Restart required |
| `api-port` / `api-key` | ❌ | Restart required |
| `log-retention` / `log-client-ip` | ❌ | Restart required — ring buffer is allocated once at startup |

**Tip:** To force an immediate feed refresh:

```bash
# Feed domains are active immediately after this call — no reload needed
curl -X POST http://localhost:8080/api/feeds/update \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

If you also edited `runbound.conf` at the same time, follow up with a reload:

```bash
systemctl reload runbound
```

### Confirming reload succeeded

```bash
# Look for this log line after reload:
journalctl -u runbound -n 20 | grep "Hot-reload complete"
# → INFO Hot-reload complete local_zones=5 local_data=12
```

---

## Signal handling

| Signal | Effect |
|--------|--------|
| `SIGHUP` | Hot-reload zones and config (same as `POST /api/reload`). In-flight queries finish on the old snapshot. |
| `SIGTERM` | Graceful shutdown — XDP detached, connections drained, process exits cleanly. |
| `SIGUSR1` | Dump live stats to the log: total queries, forwarded, blocked, 1-minute QPS, cache hit rate, uptime. |
| `SIGUSR2` | Ignored (reserved for future use). |

```bash
# Reload zones
systemctl reload runbound          # sends SIGHUP

# Dump live stats to journal
kill -USR1 $(systemctl show -p MainPID --value runbound)
journalctl -u runbound -n 5        # look for the stats line
```

---

## Disable Unbound before starting Runbound

Both listen on port 53 — they cannot run simultaneously.

```bash
systemctl stop unbound
systemctl disable unbound
systemctl enable --now runbound
```

---

## Logs

```bash
# Follow live logs
journalctl -u runbound -f

# Last 100 lines
journalctl -u runbound -n 100

# Since last boot
journalctl -u runbound -b

# Filter by level
journalctl -u runbound -p err
```

If you prefer a log file over journald, set `logfile: /var/log/runbound/runbound.log`
in `runbound.conf` and add a logrotate rule:

```
/var/log/runbound/runbound.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        systemctl reload runbound
    endscript
}
```
