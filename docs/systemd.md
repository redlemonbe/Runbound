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
ExecStart=/usr/local/bin/runbound --config /etc/runbound/runbound.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s

# Give runbound access to port 53 without running as root
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Hardening
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadWritePaths=/etc/runbound /var/log/runbound
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

---

## Setup

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
install -o root -g root -m 755 runbound /usr/local/bin/runbound

# 5. Install the config
cp /path/to/runbound.conf /etc/runbound/runbound.conf
chown runbound:runbound /etc/runbound/runbound.conf
chmod 640 /etc/runbound/runbound.conf

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

Runbound supports configuration reload without dropping any DNS connections:

```bash
# Via API (preferred)
curl -X POST http://localhost:8081/reload \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"

# Via signal
systemctl reload runbound
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
