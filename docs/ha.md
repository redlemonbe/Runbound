# High Availability — Master / Slave DNS

Runbound has built-in active/passive DNS replication. A **master** node
records every configuration change in a delta journal; one or more **slave**
nodes poll the master and apply changes automatically — with no downtime, no
file transfers, and no external tooling.

---

## Architecture

```
                    ┌──────────────────────────────┐
  DNS clients  ───► │  LOAD BALANCER / round-robin  │
  (or round-robin)  │  (keepalived / systemd / DNS) │
                    └──────────┬──────────┬─────────┘
                               │          │
                  port 53      ▼          ▼      port 53
              ┌────────────────┐     ┌────────────────┐
              │  MASTER node   │     │  SLAVE node    │
              │                │     │                │
              │  DNS :53       │     │  DNS :53       │
              │  REST API :8081│     │  REST API :8081│◄── GET only (read-only)
              │  Sync :8082    │◄────│  Sync client   │
              └────────┬───────┘     └────────────────┘
                       │
           POST /dns, /blacklist, /feeds
           (writes go to master only)
```

**Traffic flow:**
- DNS queries hit **both** nodes (round-robin, anycast, or keepalived VIP).
- **All writes** — DNS entries, blacklist, feeds — go to the **master** API only.
- The slave polls the master every `sync-interval` seconds (default: 30 s) and
  applies deltas immediately. Replication lag is typically < 30 s.
- If the master is unreachable, the slave keeps serving DNS from its last
  snapshot — read-only degradation, not a hard failure.

---

## Prerequisites

| | Master | Slave |
|---|:---:|:---:|
| Runbound binary | ✅ | ✅ |
| Port 53 open (DNS) | ✅ | ✅ |
| Port 8081 accessible (API) | localhost only | localhost only |
| Port 8082 accessible (sync) | from slave IPs | — |
| Dedicated config directory | `/etc/runbound/` | `/etc/runbound/` |
| Shared secret (`sync-key`) | ✅ | ✅ same value |

The sync port (8082) uses **HTTPS** with a self-signed cert auto-generated at
startup. No CA, no PKI — authentication is via a shared Bearer token
(`sync-key`) and TOFU cert pinning.

---

## Step 1 — Generate a shared secret

On any machine:

```bash
openssl rand -hex 32
# → e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

You will use this value as `sync-key` in **both** configs.

---

## Step 2 — Master configuration

`/etc/runbound/runbound.conf` on the **master**:

```
server:
    interface:  0.0.0.0
    port:       53
    do-ip4:     yes
    do-ip6:     yes
    do-udp:     yes
    do-tcp:     yes

    # Access control — adapt to your subnets
    access-control: 127.0.0.0/8      allow
    access-control: 192.168.0.0/16   allow
    access-control: 10.0.0.0/8       allow
    access-control: 0.0.0.0/0        refuse

    rate-limit:      500
    cache-max-ttl:   3600

    # DNS rebinding protection
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 127.0.0.0/8

    # ── Replication ────────────────────────────────────────────────────────
    mode:      master          # default — may be omitted
    sync-port: 8082            # HTTPS sync server on 0.0.0.0:8082
    sync-key:  "PASTE-YOUR-64-CHAR-HEX-HERE"

    # ── REST API ───────────────────────────────────────────────────────────
    api-port: 8081
    # Set RUNBOUND_API_KEY in /etc/runbound/env  (chmod 640)

    verbosity: 1

forward-zone:
    name:                 "."
    forward-addr:         1.1.1.1@853
    forward-addr:         1.0.0.1@853
    forward-tls-upstream: yes
```

Start and check the log:

```bash
systemctl start runbound

# Look for the sync cert fingerprint — you'll need it in a moment
journalctl -u runbound | grep -i "sha256\|fingerprint\|sync"
# [INFO] Sync HTTPS server starting  port=8082  sha256=AA:BB:CC:…
```

The master auto-generates `sync-cert.pem` and `sync-key.pem` on first start in the
**same directory as `runbound.conf`** (the runtime base directory). With the default
config path `/etc/runbound/runbound.conf`, the files land at:

| File | Path | Purpose |
|---|---|---|
| `sync-cert.pem` | `/etc/runbound/sync-cert.pem` | Master's self-signed TLS cert for the sync endpoint |
| `sync-key.pem` | `/etc/runbound/sync-key.pem` | Corresponding private key (chmod 600) |

On the slave side, after TOFU:

| File | Path | Purpose |
|---|---|---|
| `sync-master.fingerprint` | `/etc/runbound/sync-master.fingerprint` | Pinned SHA-256 of the master's cert |

If your config file is at a non-standard path, these files follow. For example, with
`/opt/runbound/runbound.conf` they would be at `/opt/runbound/sync-cert.pem` etc.

To force a re-TOFU (master cert regeneration or suspected compromise): delete
`sync-cert.pem` and `sync-key.pem` on the master, then `sync-master.fingerprint` on
the slave, and restart both.

Copy the SHA-256 fingerprint shown in the master log — you will verify it on the slave.

---

## Step 3 — Slave configuration

`/etc/runbound/runbound.conf` on the **slave**:

```
server:
    interface:  0.0.0.0
    port:       53
    do-ip4:     yes
    do-ip6:     yes
    do-udp:     yes
    do-tcp:     yes

    # Same ACL rules as the master
    access-control: 127.0.0.0/8      allow
    access-control: 192.168.0.0/16   allow
    access-control: 10.0.0.0/8       allow
    access-control: 0.0.0.0/0        refuse

    rate-limit:      500
    cache-max-ttl:   3600

    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 127.0.0.0/8

    # ── Replication ────────────────────────────────────────────────────────
    mode:          slave
    sync-master:   192.168.1.10:8082     # master IP:sync-port
    sync-key:      "PASTE-YOUR-64-CHAR-HEX-HERE"   # same as master
    sync-interval: 30                   # poll every 30 s (default)

    # ── REST API (read-only on slave) ──────────────────────────────────────
    api-port: 8081

    verbosity: 1

forward-zone:
    name:                 "."
    forward-addr:         1.1.1.1@853
    forward-addr:         1.0.0.1@853
    forward-tls-upstream: yes
```

Start the slave:

```bash
systemctl start runbound

# First-sync TOFU handshake — watch for the fingerprint warning
journalctl -u runbound -f
# WARN TOFU: first connection to master. Verify sync-master.fingerprint manually.
# WARN  sha256=AA:BB:CC:…
# INFO  Slave sync started → master 192.168.1.10:8082
```

---

## Step 4 — Verify the TOFU fingerprint

On the slave, compare the fingerprint printed in the log with the one from the master:

```bash
# On the master:
openssl x509 -fingerprint -sha256 -noout \
  -in /etc/runbound/sync-cert.pem
# SHA256 Fingerprint=AA:BB:CC:DD:…

# On the slave (what was saved after TOFU):
cat /etc/runbound/sync-master.fingerprint
# AA:BB:CC:DD:…
```

They must match. If they don't, a man-in-the-middle is present — stop the slave,
delete `/etc/runbound/sync-master.fingerprint`, investigate, and restart only when
the network path is verified clean.

Once verified, all subsequent connections from this slave pin that fingerprint in
rustls (no CA, no DNS). A cert change on the master invalidates the pin and the
slave logs an error — delete the fingerprint file to re-run TOFU.

---

## Step 5 — Test replication

Add a DNS entry on the master, verify it appears on the slave:

```bash
# Master: add an entry via the REST API
curl -X POST http://localhost:8081/dns \
  -H "Authorization: Bearer $(cat /etc/runbound/api.key)" \
  -H "Content-Type: application/json" \
  -d '{"name":"test.home.","type":"A","value":"192.168.1.99","ttl":60}'

# Wait up to sync-interval seconds (default 30 s)
sleep 35

# Slave: query the slave's DNS directly
dig @<slave-IP> test.home.
# ;; ANSWER SECTION:
# test.home.    60   IN   A   192.168.1.99   ← replicated!
```

---

## Slave read-only behaviour

When running as a slave, all write operations are blocked at the API level:

```bash
# On slave — write attempt
curl -X POST http://localhost:8081/dns ...
# HTTP 503
# {"error":"READ_ONLY","details":"This node is a slave replica — write operations are disabled"}
```

**Read operations work normally on the slave:**

```bash
curl http://localhost:8081/dns       # list DNS entries
curl http://localhost:8081/blacklist  # list blacklist
curl http://localhost:8081/stats      # live statistics
curl http://localhost:8081/logs       # query log
curl http://localhost:8081/health     # liveness probe (for load balancer checks)
```

Use `GET /health` on both nodes for load balancer health probes.

---

## Delta sync and full sync

The master keeps a **ring buffer of the last 1,000 events**. Each slave tracks the
last sequence number it received and requests `GET /sync/delta?since=N`.

```
Normal operation (slave < 1000 events behind):
  Slave → GET /sync/delta?since=417
  Master → 200 OK  [events 418..432]

Slave was offline too long (> 1000 events behind):
  Slave → GET /sync/delta?since=5
  Master → 410 Gone
  Slave → GET /sync/config  (full snapshot)
  Slave rebuilds all zones from scratch
  Slave resumes delta sync from the current master seq
```

Full sync is also triggered automatically on first start (slave seq = 0).

**Sync endpoints** (on master, HTTPS port 8082):

| Endpoint | Auth | Purpose |
|---|:---:|---|
| `GET /sync/cert` | None | SHA-256 cert fingerprint (TOFU bootstrap) |
| `GET /sync/state` | Bearer | Current journal sequence number |
| `GET /sync/config` | Bearer | Full state snapshot (DNS + blacklist + feeds) |
| `GET /sync/delta?since=N` | Bearer | Events with seq ≥ N (410 if too old) |

---

## Client-side failover

### Option A — DNS round-robin (simplest)

Point clients at both IPs. Clients will fail over automatically using their DNS retry logic:

```bash
# /etc/resolv.conf on clients
nameserver 192.168.1.10   # master
nameserver 192.168.1.11   # slave
```

Or in your DHCP server: advertise both IPs as DNS servers. RFC 3484 / glibc will
try the first and fall back to the second after a timeout (~5 s by default).

### Option B — Virtual IP with keepalived (recommended for LAN)

Install keepalived on both DNS nodes. The VIP floats to whichever node is alive.

```
# /etc/keepalived/keepalived.conf  — MASTER node
vrrp_instance DNS {
    state               MASTER
    interface           eth0
    virtual_router_id   51
    priority            100       # higher = preferred
    advert_int          1
    authentication {
        auth_type   PASS
        auth_pass   runbound-ha
    }
    virtual_ipaddress {
        192.168.1.200/24          # VIP — clients point here
    }
}
```

```
# /etc/keepalived/keepalived.conf  — SLAVE node
vrrp_instance DNS {
    state               BACKUP
    interface           eth0
    virtual_router_id   51
    priority            90        # lower than master
    advert_int          1
    authentication {
        auth_type   PASS
        auth_pass   runbound-ha
    }
    virtual_ipaddress {
        192.168.1.200/24
    }
}
```

Point all clients at `192.168.1.200`. Failover time: ~2 s (one missed heartbeat).

Add a health-check script to keepalived so it tracks Runbound, not just network:

```
# In keepalived.conf (both nodes)
vrrp_script check_runbound {
    script "/usr/local/bin/check-runbound.sh"
    interval 5
    weight   -30   # lower priority by 30 if check fails
}
```

```bash
#!/bin/sh
# /usr/local/bin/check-runbound.sh
dig @127.0.0.1 -p 53 runbound.health. A +short +time=2 &>/dev/null
```

### Option C — Anycast (data-centre / cloud)

Announce the same IP from both nodes via BGP with different MED values. Standard
anycast failover — out of scope for this guide.

---

## Two nodes on the same machine

For testing, or for edge nodes with a single server, you can run master and slave
on the same machine using different config directories and ports:

```bash
# Master — /etc/runbound/runbound.conf (ports 53 + 8081 + 8082)
# Slave  — /etc/runbound-slave/unbound.conf (ports 5300 + 8083 — different!)

# Because runtime files live next to the config, there are zero path collisions:
#   /etc/runbound/dns_entries.json       ← master
#   /etc/runbound-slave/dns_entries.json ← slave

runbound /etc/runbound/runbound.conf
runbound /etc/runbound-slave/unbound.conf
```

Slave config adjustment for same-machine use:

```
server:
    port:          5300           # different from master's 53
    api-port:      8083           # different from master's 8081
    mode:          slave
    sync-master:   127.0.0.1:8082
    sync-key:      "…"
    sync-interval: 5              # faster for local testing
```

---

## Monitoring

### Health check (HTTP)

Both nodes expose `GET /health` on port 8081 (localhost). Expose it via nginx for
external monitoring:

```nginx
# nginx — proxy /health to Runbound API (read-only, no sensitive data)
location /runbound-health {
    proxy_pass http://127.0.0.1:8081/health;
    proxy_set_header Authorization "Bearer YOUR_KEY";
}
```

Or use the DNS probe directly:

```bash
# In Nagios / Zabbix / Prometheus blackbox:
dig @192.168.1.10 runbound.health. A +short +time=2
```

### Replication lag

Check the slave's sync log:

```bash
journalctl -u runbound -g "Sync" --since="5 minutes ago"
# INFO Slave sync: applied 3 events (seq 418→421) — lag 2s
```

Or query the master's sequence and the slave's last-applied sequence via the API:

```bash
# Master current seq (via sync endpoint — not the REST API)
curl -H "Authorization: Bearer $SYNC_KEY" https://master:8082/sync/state

# Slave last-applied (from its own logs or REST API extended stats)
journalctl -u runbound @slave | grep "applied.*seq"
```

### Alert conditions

| Condition | Action |
|---|---|
| Slave cannot reach master for > 5 min | Alert — check network / sync-port firewall |
| Slave applied 410 Gone (full sync) | Informational — slave was behind by > 1000 events |
| Slave fingerprint mismatch | **Critical** — investigate immediately |
| Master sync-cert regenerated | Update slave's `sync-master.fingerprint` (delete + restart) |

---

## Key rotation

**sync-key:**

1. Generate a new key: `openssl rand -hex 32`
2. Update `sync-key` on the master. Restart master.
3. Update `sync-key` on the slave. Restart slave.

The slave will immediately reconnect with the new key. There is no grace period —
update both within a few seconds to avoid a sync gap.

**Master TLS cert (sync-cert.pem):**

The cert is auto-generated at startup and does not expire for 10 years.
To regenerate (e.g., after a compromise):

```bash
# On master:
rm /etc/runbound/sync-cert.pem /etc/runbound/sync-key.pem
systemctl restart runbound
# → new cert generated, new fingerprint in log

# On slave:
rm /etc/runbound/sync-master.fingerprint
systemctl restart runbound
# → TOFU re-runs with new fingerprint, verify it matches master
```

**API key:**

```bash
# On any node:
RUNBOUND_API_KEY=$(openssl rand -hex 32)
echo "RUNBOUND_API_KEY=$RUNBOUND_API_KEY" > /etc/runbound/env
chmod 640 /etc/runbound/env
systemctl restart runbound
```

The API key is independent per node — master and slave can have different API keys.

---

## Troubleshooting

### Slave shows "connection refused" to master

```bash
# Check sync port is open on master
ss -tlnp | grep 8082
# tcp  LISTEN  0  128  0.0.0.0:8082  …

# Check firewall
ufw status | grep 8082
iptables -L INPUT -n | grep 8082
```

Verify the slave can reach the master sync port:

```bash
curl -k https://MASTER-IP:8082/sync/cert
# Should return the cert fingerprint JSON
```

### Slave shows "fingerprint mismatch"

The master cert changed (node replaced, cert regenerated). On the slave:

```bash
rm /etc/runbound/sync-master.fingerprint
systemctl restart runbound
# Verify new fingerprint matches master
```

### Slave shows "410 Gone — triggering full sync"

Normal behaviour when the slave was offline for an extended period. Full sync
applies automatically. No action required.

### Replication stopped, no error

Check that the slave clock is not skewed:

```bash
timedatectl status    # on both nodes
chronyc tracking      # if using chrony
```

A clock skew > a few seconds does not break replication but can affect log timestamps.
Large skews (> 5 min) may cause TLS validation issues.

### Same machine: port 53 conflict

Use different ports for the slave and update your test clients accordingly, or use
`SO_REUSEPORT` with network namespaces (advanced — out of scope).

---

## Quick reference — sync directives

| Directive | Node | Default | Description |
|---|:---:|---|---|
| `mode` | both | `master` | Set to `slave` on replica nodes. |
| `sync-port` | master | — | HTTPS sync server port (e.g. 8082). Required on master. |
| `sync-key` | both | — | Shared Bearer token for sync auth. Required on both. |
| `sync-master` | slave | — | Master `ip:port` (e.g. `192.168.1.10:8082`). Required on slave. |
| `sync-interval` | slave | `30` | Poll interval in seconds. |

See [configuration.md](configuration.md) for all directives.
