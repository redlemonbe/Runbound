# Configuration Reference

Runbound uses the same configuration format as Unbound. Copy your existing
`unbound.conf` and it will work. This page documents every supported directive.

---

## File structure

```
server:
    directive: value
    directive: value

forward-zone:
    name: "."
    forward-addr: 1.1.1.1@53
```

Comments start with `#`. Indentation is optional but recommended.

---

## `server:` directives

### Network

| Directive | Type | Default | Description |
|---|---|---|---|
| `interface` | IP | `0.0.0.0` | IP address to listen on. Repeat for multiple interfaces. |
| `port` | int | `53` | UDP/TCP DNS port. |
| `do-ip4` | bool | `yes` | Accept IPv4 queries. |
| `do-ip6` | bool | `yes` | Accept IPv6 queries. |
| `do-udp` | bool | `yes` | Accept UDP queries. |
| `do-tcp` | bool | `yes` | Accept TCP queries. |

### Access control

```
access-control: 127.0.0.0/8    allow
access-control: 192.168.0.0/16 allow
access-control: 0.0.0.0/0      refuse
```

| Action | Behaviour |
|---|---|
| `allow` | Accept the query and answer it. |
| `deny` | Drop the packet silently. |
| `refuse` | Reply with DNS REFUSED. Recommended default — client knows it was blocked. |

Rules are evaluated in order. The first match wins. If no rule matches, the default
is `refuse` (fail-secure).

**IPv4-mapped IPv6:** A client connecting as `::ffff:192.168.1.1` is automatically
normalised to `192.168.1.1` before matching — your IPv4 ACL rules apply correctly.

### Rate limiting

```
rate-limit: 1000
```

Maximum queries per second accepted from a single source IP. Excess queries receive
a REFUSED response. Uses a token-bucket algorithm.

Setting `rate-limit: 0` disables rate limiting.

### Local zones

```
local-zone: "home." static
local-data: "nas.home. 300 IN A 192.168.1.10"
local-data: "printer.home. 300 IN A 192.168.1.20"
```

**Zone types:**

| Type | Behaviour |
|---|---|
| `static` | Authoritative zone — answer from `local-data`, NXDOMAIN for unknown names. |
| `always_nxdomain` | Always return NXDOMAIN. Used for domain blocking. |
| `transparent` | Answer from `local-data` if present, forward otherwise. |

**Supported record types in `local-data`:** A, AAAA, PTR, CNAME, MX, TXT, NS, SOA.

**Reverse DNS:**

```
local-zone: "1.168.192.in-addr.arpa." static
local-data: "10.1.168.192.in-addr.arpa. 300 IN PTR nas.home."
```

### TLS (DNS-over-TLS)

```
tls-service-pem: /etc/runbound/cert.pem
tls-service-key: /etc/runbound/key.pem
```

When both are set, Runbound listens on port **853** for DoT connections in addition
to port 53. See [tls.md](tls.md) for certificate setup.

### Logging

```
logfile: /var/log/runbound/runbound.log
verbosity: 1
```

| `verbosity` | Output |
|---|---|
| `0` | Errors only |
| `1` | Operational (default) |
| `2` | Detailed — includes query names |
| `3` | Debug |
| `4–5` | Trace |

Set `logfile: ""` or omit it to log to stdout (recommended with systemd).

### API key and port

```
# In config (not recommended for production):
api-key: "change-me"
api-port: 9090       # optional — default 8081

# Preferred — environment variable (never stored in config file):
# export RUNBOUND_API_KEY="$(openssl rand -hex 32)"
```

The environment variable takes priority over the config file value.  
The API always binds to `127.0.0.1` (localhost only) regardless of `api-port`.

### DNSSEC validation

```
dnssec-validation: no    # default — trust upstream AD bit (forwarder mode)
dnssec-validation: yes   # local re-validation (recursive mode only)
```

Mirrors Unbound's `dnssec-validation` directive. When set to `yes`, hickory-resolver
performs local DNSSEC re-validation of every response.

**Warning:** Only enable in full recursive deployments where upstream resolvers return
complete RRSIG/DNSKEY chains. In forwarder mode (the typical setup with Cloudflare or
Quad9), enabling this causes SERVFAIL on every signed domain because forwarders strip
DNSSEC records. Default is `no` — trust the upstream AD bit.

### Anti-OOM memory guard

Runbound runs two automatic memory-pressure defences — both are always active, no
configuration required.

**1 — Inflight concurrency cap (hard limit)**

```
# Not configurable — hardcoded at 4,096 concurrent requests.
# Excess requests receive REFUSED immediately, zero allocation.
```

`hickory-server` spawns one tokio task per incoming DNS request with no backpressure.
Under a flood (DDoS or benchmark), this exhausts RAM and triggers the Linux OOM killer.
Runbound imposes a semaphore of **4,096 concurrent in-flight requests**. When the limit
is reached, new requests receive `REFUSED` instantly without allocating any memory.
This bound is hard even at line rate.

**2 — Memory pressure guard (background, /proc/meminfo)**

```
# Not configurable — polls /proc/meminfo every 30 s.
# Threshold: purge when system RAM usage ≥ 80 %
# Target:    log status at 50 % after purge
```

A background task reads `/proc/meminfo` every 30 seconds. If system memory usage
reaches **80 %**, two caches are flushed atomically:

| Cache | Action | Recovery |
|---|---|---|
| Rate-limiter DashMap | All token buckets cleared | Rebuilds naturally on next query per IP |
| hickory-resolver cache | Resolver rebuilt, ArcSwap pointer swapped | In-flight queries keep old resolver; new queries use fresh empty cache |

After purging, usage and whether the 50 % target was reached are logged at `WARN` level.
On non-Linux systems or containers without `/proc/meminfo`, the guard silently skips
its check and DNS service continues normally.

**Log output example:**

```
WARN Memory pressure — purging DNS caches  used_pct=82.3%  avail_mb=312  total_mb=1753
WARN DNS resolver cache flushed and rate limiter cleared  freed_buckets=8241
WARN Memory after purge  used_pct=44.1%  status="below 50% target"
```

### Cache TTL cap

```
cache-max-ttl: 3600   # cap all TTLs at 1 hour (default: 86400)
```

Upstream resolvers sometimes return TTLs of 24–48 hours. Capping the TTL limits
how long a stale or poisoned record lingers in clients' caches.

### Private-address (DNS rebinding protection)

```
private-address: 10.0.0.0/8
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 127.0.0.0/8
private-address: fd00::/8
```

If an upstream resolver returns an A or AAAA record that falls within a
`private-address` range, the query is answered with SERVFAIL instead of
forwarding the private IP to the client. This prevents DNS rebinding attacks
where a public domain is made to resolve to an internal IP.

Mirrors Unbound's `private-address` directive.

---

## `forward-zone:` directives

```
forward-zone:
    name:         "."
    forward-addr: 9.9.9.9@53
    forward-addr: 1.1.1.1@53
```

| Directive | Description |
|---|---|
| `name` | Zone to forward. `"."` forwards everything not answered locally. |
| `forward-addr` | Upstream resolver. `ip@port` syntax. Repeat for redundancy. |
| `forward-tls-upstream` | `yes` → send queries over DNS-over-TLS (port 853). |

**DNS-over-TLS to upstream:**

```
forward-zone:
    name:                 "."
    forward-addr:         1.1.1.1@853
    forward-addr:         1.0.0.1@853
    forward-tls-upstream: yes
```

The `@port` syntax works for both plain and TLS upstreams. When `forward-tls-upstream: yes`
and no explicit port is given, port 853 is used automatically.

**Split-horizon DNS example:**

```
# Internal zone handled by Active Directory
forward-zone:
    name:         "corp.example.com."
    forward-addr: 10.10.0.5@53

# Everything else → Cloudflare
forward-zone:
    name:         "."
    forward-addr: 1.1.1.1@53
```

---

## Complete example

```
server:
    interface:  0.0.0.0
    port:       53

    do-ip4:     yes
    do-ip6:     yes
    do-udp:     yes
    do-tcp:     yes

    access-control: 127.0.0.0/8      allow
    access-control: 192.168.0.0/16   allow
    access-control: 0.0.0.0/0        refuse

    rate-limit:    500
    cache-max-ttl: 3600

    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 127.0.0.0/8

    local-zone: "home." static
    local-data: "nas.home.     300 IN A 192.168.1.10"
    local-data: "router.home.  300 IN A 192.168.1.1"

    tls-service-pem: /etc/runbound/cert.pem
    tls-service-key: /etc/runbound/key.pem

    api-port:  8081
    logfile:   ""
    verbosity: 1

forward-zone:
    name:                 "."
    forward-addr:         1.1.1.1@853
    forward-addr:         9.9.9.9@853
    forward-tls-upstream: yes
```

---

## Slave/master replication

Runbound supports a master/slave topology for high-availability DNS. The master serves
write operations and records them in a delta journal; slaves poll the master, apply
deltas, and rebuild their zone set automatically.

### Master configuration

```
server:
    mode:      master      # default — omit if not using replication
    sync-port: 8082        # opens HTTPS sync server on 0.0.0.0:8082
    sync-key:  <secret>    # shared Bearer token for slave authentication
```

On first start, the master auto-generates a self-signed TLS certificate for the sync
endpoint (`/etc/runbound/sync-cert.pem`). Its SHA-256 fingerprint is logged at startup
and is also available at `GET https://master:8082/sync/cert` (unauthenticated endpoint
used for TOFU bootstrap).

If `sync-key` is absent, a 256-bit random key is generated at startup and printed to
the log. Add it to both master and slave configs.

### Slave configuration

```
server:
    mode:          slave
    sync-master:   192.168.1.10:8082    # master ip:port (same as sync-port above)
    sync-key:      <same-secret>
    sync-interval: 30                   # poll interval in seconds (default: 30)
```

On first start, the slave performs a **TOFU (Trust On First Use)** TLS handshake:

1. Connects to master with no cert validation.
2. Downloads the cert fingerprint from `GET /sync/cert`.
3. Cross-checks it against the fingerprint captured during the TLS handshake.
4. Saves the SHA-256 fingerprint to `/etc/runbound/sync-master.fingerprint` (chmod 640).
5. Emits a `WARN` log with the fingerprint for manual verification.

All subsequent connections pin the saved fingerprint. A mismatch aborts the connection.
To re-key, delete `/etc/runbound/sync-master.fingerprint` on the slave and restart.

### Slave read-only mode

When `mode: slave` is set, all non-GET REST API requests return:

```json
HTTP 503
{"error": "READ_ONLY", "details": "This node is a slave replica — write operations are disabled"}
```

Changes must be made on the master and will replicate automatically.

### Delta sync and full sync

The master keeps a ring buffer of the last **1,000 events** (DNS adds/deletes, blacklist
changes, feed subscriptions, feed refreshes). Slaves request only the events they missed
since their last sync (`GET /sync/delta?since=N`).

If a slave falls more than 1,000 events behind (e.g., was offline for an extended period),
the master returns `410 Gone` and the slave automatically performs a full snapshot sync
(`GET /sync/config`).

### Slave feed updates

When the master refreshes a feed (`POST /feeds/:id/update`), the slave receives a
`UpdateFeed` event and re-downloads the feed from the **same URL stored in its local
config** — it does not stream feed content from the master. This keeps the sync protocol
lightweight regardless of feed size.

### Sync ports reference

| Port | Protocol | Purpose |
|---|---|---|
| 53 | UDP + TCP | DNS (all nodes) |
| 8081 | HTTP | REST API (localhost only, all nodes) |
| 8082 | HTTPS | Sync server (master only, network-accessible) |

The sync port number is configurable. The REST API stays on localhost on all nodes.

---

## Environment variables

| Variable | Description |
|---|---|
| `RUNBOUND_API_KEY` | REST API Bearer token. Overrides `api-key` in config. |
| `RUST_LOG` | Log filter (e.g. `runbound=debug,info`). |
