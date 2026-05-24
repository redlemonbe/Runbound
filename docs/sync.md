# Master / Slave Synchronisation

Runbound supports active/passive replication. The master holds the authoritative
state (blacklist, DNS zones, feeds). Slaves connect to the master, receive the
full state on first connection, and receive incremental updates in real time.

Starting with v0.6.20, the synchronisation stack also includes:

- **HMAC-SHA256 encrypted relay** (#85) — master can forward REST API commands to any slave over a signed TLS channel
- **Config push** (#87) — every write on the master is immediately pushed to all registered slaves (fire-and-forget)
- **Slave auto-registration** (#88) — slaves register themselves with the master at startup; no manual node setup required

---

## Architecture

```
                 ┌──────────────────────────────────┐
clients ──DNS──▶ │  slave  192.168.1.11:53           │
                 │  relay server :8082 (TLS + HMAC)  │◀── config push ──┐
                 └──────────────────────────────────┘                    │
                                  │ sync (delta journal)                 │
                                  ▼                                       │
                 ┌──────────────────────────────────┐                    │
clients ──DNS──▶ │  master 192.168.1.10:53           │ ─── relay fwd ───▶│
                 │  sync server :8082 (HTTPS)        │
                 │  REST API    :8080 (localhost)     │
                 └──────────────────────────────────┘
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

`sync-port` opens the HTTPS sync server (delta journal + node registration).  
`sync-key` authenticates slaves and signs relay traffic. If omitted, a random 256-bit
key is generated at startup and printed to the log.

---

## Slave configuration (`/etc/runbound/unbound.conf`)

```
server:
    mode:        slave
    sync-master: 192.168.1.10:8082   # master IP:port
    sync-key:    <same key as master>
    sync-port:   8082                # opens the slave relay server (TLS + HMAC)
```

`sync-port` on the slave starts a TLS relay server on that port. The master connects
to this port to push config changes and forward API commands.

On startup the slave:
1. Generates (or loads) a stable UUID from `/etc/runbound/node-id`.
2. Generates (or loads) a self-signed TLS certificate at `/etc/runbound/relay-cert.pem`.
3. Starts the TLS relay server on `sync-port`.
4. Registers with the master via `POST /nodes/register` (HMAC-signed), advertising its
   `relay_host` (`<slave_ip>:<sync-port>`) and cert fingerprint.

All other directives (`interface`, `port`, `forward-zone`, `access-control`, etc.)
are identical to the master.

---

## HMAC relay security

All relay traffic is authenticated with **HMAC-SHA256** using the shared `sync-key`.
Each request carries two headers:

| Header | Content |
|---|---|
| `X-Runbound-TS` | Unix timestamp (seconds) — anti-replay window |
| `X-Runbound-Sig` | `HMAC-SHA256(key, METHOD + PATH + TS)` encoded as hex |

The receiver rejects any request where the timestamp differs by more than **±30 seconds**
from its own clock. Signature comparison is constant-time (via `subtle::ConstantTimeEq`).

TLS provides encryption; HMAC provides authentication. The TLS layer does not validate
certificates (both sides use self-signed certs) — the shared key is the trust anchor.

---

## Config push (#87)

After every write operation on the master (add/delete DNS entry, blacklist, upstream),
the master fires-and-forgets the same operation to all registered slaves over the relay
channel. If a slave is unreachable, the push fails silently and a `WARN` is logged; the
slave will catch up via the normal delta-journal sync on its next poll.

---

## Relay forwarding

The master's REST API exposes a relay endpoint that forwards any request to a specific
slave:

```
ANY /api/nodes/{node_id}/relay/{path}
```

Example — flush the cache on a specific slave:

```bash
curl -X POST "http://localhost:8080/api/nodes/a1b2c3.../relay/cache/flush" \
  -H "Authorization: Bearer $RUNBOUND_API_KEY"
```

The master looks up the slave by `node_id`, signs the request with HMAC, and proxies it
to the slave's relay server. The slave's response is returned verbatim.

Anti-recursion: the master refuses to relay to `/relay/*` (prevents relay loops).

---

## Firewall — required ports

This is the most common reason synchronisation fails.

| Port | Protocol | Direction | Purpose |
|---|---|---|---|
| 53 | UDP + TCP | clients → master/slave | DNS queries |
| 8082 | TCP | slave → master | delta journal (slave initiates) |
| 8082 | TCP | master → slave | relay / config push (master initiates) |
| 8080 | TCP | localhost only | REST API (not exposed by default) |

**On the master**, open port 8082 inbound from the slave subnet:

```bash
# UFW (Debian/Ubuntu)
sudo ufw allow from 192.168.0.0/16 to any port 8082 proto tcp comment "Runbound sync"

# iptables
sudo iptables -A INPUT -s 192.168.0.0/16 -p tcp --dport 8082 -j ACCEPT

# firewalld
sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=192.168.0.0/16 port port=8082 protocol=tcp accept'
sudo firewall-cmd --reload
```

**On the slave**, open port 8082 inbound from the master:

```bash
sudo ufw allow from 192.168.1.10 to any port 8082 proto tcp comment "Runbound relay"
```

> **Port 8082 is the #1 reason sync fails.** Verify both directions:
> ```bash
> # From slave — can it reach the master?
> nc -zv 192.168.1.10 8082
> # From master — can it reach the slave?
> nc -zv 192.168.1.11 8082
> ```

---

## Verifying synchronisation

On the slave, check the logs shortly after startup:

```bash
journalctl -u runbound -n 30
```

Expected:
```
INFO runbound::sync: connected to master master=192.168.1.10:8082
INFO runbound::sync: initial state received zones=42 blacklist=1200 feeds=2
INFO runbound::sync: relay server listening port=8082
INFO runbound::api::relay: Registered with master master=192.168.1.10:8082
```

On the master:

```bash
curl -H "Authorization: Bearer $RUNBOUND_API_KEY" http://localhost:8080/api/nodes
```

```json
{
  "nodes": [
    {
      "node_id":          "a1b2c3d4-...",
      "addr":             "192.168.1.11",
      "relay_host":       "192.168.1.11:8082",
      "cert_fingerprint": "ab:cd:ef:...",
      "status":           "connected",
      "last_seen_secs":   5,
      "zones_synced":     42,
      "version":          "0.6.20"
    }
  ],
  "total": 1
}
```

If you see `Connection timed out` → firewall blocking port 8082.  
If you see `Unauthorized` → `sync-key` mismatch between master and slave.  
If the slave appears in `GET /api/nodes` but `relay_host` is absent → slave's `sync-port` is not configured.

---


## Real-time node health — `GET /api/events`

In addition to polling `GET /api/nodes`, the master exposes a Server-Sent Events
stream that pushes slave health changes in real time. This is useful for dashboards
and alerting systems that need sub-minute notification of slave outages.

```bash
curl -N -H "Authorization: Bearer $RUNBOUND_API_KEY" \
     http://localhost:8080/api/events
```

```
data: {"node_id":"1df6dc2c-94a7-485b-bb80-76b7f5aa438d","addr":"192.168.8.11","status":"ok","reason":"last seen 3s ago","ts":1748131200}
data: {"node_id":"1df6dc2c-94a7-485b-bb80-76b7f5aa438d","addr":"192.168.8.11","status":"warn","reason":"last seen 42s ago","ts":1748131242}
```

An event is emitted whenever a slave transitions between health categories.

**Health thresholds:**

| Status | `last_seen_secs` | Meaning |
|---|---|---|
| `ok` | < 15 s | Slave is syncing normally |
| `warn` | 15–59 s | One sync cycle missed — may be transient |
| `error` | ≥ 60 s | Slave likely unreachable |

This endpoint is **master-only** — it returns `404` on slave and standalone nodes.
Keep-alive comments are sent every 15 s. The broadcast channel holds up to 64 events;
slow consumers are disconnected if they fall behind.

See [api.md](api.md#get-apievents) for the full endpoint reference.

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
