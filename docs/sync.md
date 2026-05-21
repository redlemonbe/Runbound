# Master / Slave Synchronisation

Runbound supports active/passive replication. The master holds the authoritative
state (blacklist, DNS zones, feeds). Slaves connect to the master, receive the
full state on first connection, and receive incremental updates in real time.

---

## Architecture

```
clients → slave (192.168.1.11:53)  ──sync──▶  master (192.168.1.10:53)
clients → master (192.168.1.10:53)
```

The slave answers DNS queries autonomously. If the master is unreachable, the
slave continues serving from its last known state.

---

## Master configuration (`/etc/runbound/unbound.conf`)

```
server:
    mode:       master
    sync-port:  8082
    sync-key:   <generate with: openssl rand -hex 32>
```

`sync-port` defines the TCP port the master listens on for incoming slave connections.

---

## Slave configuration (`/etc/runbound/unbound.conf`)

```
server:
    mode:        slave
    sync-master: 192.168.1.10:8082   # IP:port — port must match master's sync-port
    sync-key:    <same key as master>
```

> **Note:** `sync-port` is a master-only directive. On the slave, the master
> address and port are combined in `sync-master: <IP>:<port>`. Using a separate
> `sync-port` directive on the slave produces `invalid socket address` at startup.

All other directives (`interface`, `port`, `forward-zone`, `access-control`, etc.)
are identical to the master.

---

## Firewall — required ports

This is the most common reason synchronisation fails.

| Port | Protocol | Direction | Purpose |
|---|---|---|---|
| 53 | UDP + TCP | clients → master/slave | DNS queries |
| 8082 | TCP | slave → master | sync channel |
| 8080 | TCP | localhost only | REST API (not exposed by default) |

**On the master**, open port 8082 to the slave subnet:

```bash
# UFW (Debian/Ubuntu)
sudo ufw allow from 192.168.0.0/16 to any port 8082 proto tcp comment "Runbound sync"

# iptables
sudo iptables -A INPUT -s 192.168.0.0/16 -p tcp --dport 8082 -j ACCEPT

# firewalld
sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=192.168.0.0/16 port port=8082 protocol=tcp accept'
sudo firewall-cmd --reload
```

> **Port 8082 is the #1 reason sync fails.** The port is open on Runbound's
> side but blocked by the host firewall. Verify from the slave:
> ```bash
> nc -zv 192.168.1.10 8082
> # Expected: Connection to 192.168.1.10 8082 port [tcp/*] succeeded
> ```

---

## Verifying synchronisation

On the slave, check the logs shortly after startup:

```bash
journalctl -u runbound -n 20
```

Expected:
```
INFO runbound::sync: connected to master master=192.168.1.10:8082
INFO runbound::sync: initial state received zones=42 blacklist=1200 feeds=2
```

If you see `Connection timed out` → firewall on the master blocking port 8082.  
If you see `Unauthorized` → `sync-key` mismatch between master and slave.

---

## Sync-key security

Generate a strong key — never use a short or default string:

```bash
openssl rand -hex 32
```

The same key must be set on both master and slave. To rotate:
1. Generate a new key
2. Update both configs simultaneously
3. `systemctl reload runbound` on master, then slave
