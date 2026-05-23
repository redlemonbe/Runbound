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
| `refuse` | Reply with DNS REFUSED. Recommended — client knows it was blocked. |
| *(no match)* | **`refuse`** — fail-secure default. If no rule matches the client IP, Runbound replies with REFUSED. |

Rules are evaluated in order. The first match wins. The implicit default when no rule
matches is `refuse` — this means an empty `access-control` block blocks all clients.

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

### TLS (DNS-over-TLS / DoH / DoQ)

```
tls-service-pem: /etc/runbound/cert.pem
tls-service-key: /etc/runbound/key.pem
tls-port:        853       # DoT port (default: 853)
https-port:      443       # DoH port (default: 443)
quic-port:       853       # DoQ port (default: 853 UDP)
```

When both `tls-service-pem` and `tls-service-key` are set, Runbound listens on the
configured TLS ports in addition to port 53. See [tls.md](tls.md) for certificate setup.

#### DoT mutual TLS (client authentication)

```
dot-client-auth-ca: /etc/runbound/client-ca.pem
```

When set, DoT clients must present a certificate signed by the specified CA.
Connections without a valid client certificate are rejected at the TLS handshake.
DoH and DoQ are unaffected (they authenticate via the REST API Bearer token).

Generate a client CA and client certificate:

```bash
# CA
openssl req -x509 -newkey ed25519 -keyout ca-key.pem -out ca-cert.pem -days 3650 -nodes -subj "/CN=RunboundClientCA"
# Client key + CSR + cert
openssl req -newkey ed25519 -keyout client-key.pem -out client-csr.pem -nodes -subj "/CN=dot-client"
openssl x509 -req -in client-csr.pem -CA ca-cert.pem -CAkey ca-key.pem -out client-cert.pem -days 365
```

Point `dot-client-auth-ca:` at `ca-cert.pem`. Distribute `client-cert.pem` + `client-key.pem`
to authorised DNS clients.

### Logging

```
logfile: /var/log/runbound/runbound.log
verbosity: 1
```

| `verbosity` | Level | `/logs` | Hot path (NOERROR) | Description |
|---|---|---|---|---|
| `0` | ERROR | empty | zero overhead | Startup/shutdown errors only |
| `1` | WARN | notable events | zero overhead | **Recommended for production** |
| `2` | INFO | all queries | log + alloc | Full per-query history |
| `3` | DEBUG | all queries | log + alloc | Development only |

**"Notable events" at `verbosity: 1`:** blocked, NXDOMAIN, SERVFAIL, refused, rate-limited.  
NOERROR queries (forwarded, cached, local) skip `sanitize_dns_name()`, mutex, and `SystemTime::now()` entirely.

**Performance impact (measured, AMD TR PRO 5995WX, 100k+ QPS):**

| verbosity | Level | p99 under stress |
|---|---|---|
| `0` | error | **0.18 ms** — maximum performance |
| `1` | warn | **0.19 ms** — production standard |
| `2` | info | 3.01 ms |

> **Production recommendation:** use `verbosity: 1`. The NOERROR hot path has zero overhead; `/logs` captures all actionable events (blocked, errors). Use `verbosity: 0` for benchmark baselines or ultra-high-load deployments where even notable-event logging must be eliminated. Use `verbosity: 2` only when you need full per-query history.

`verbosity: 2` logs every DNS query — at 100k QPS this generates ~100k log lines per second and adds significant CPU overhead. `--check-config` warns if `verbosity: 2` or higher is set on port 53.

**Priority:** `RUST_LOG` environment variable > `verbosity:` directive > default `warn`.  
Add `RUST_LOG=runbound=debug` to `/etc/runbound/environment` for temporary debug sessions without editing the config file.

Set `logfile: ""` or omit it to log to stdout (recommended with systemd).

### API key and port

```
# In config (not recommended for production):
api-key: "change-me"
api-port: 9090       # optional — default 8080

# Preferred — environment variable (never stored in config file):
# export RUNBOUND_API_KEY="$(openssl rand -hex 32)"
```

The environment variable takes priority over the config file value.  
The API always binds to `127.0.0.1` (localhost only) regardless of `api-port`.

### HSM key storage (PKCS#11)

Store the API key and store HMAC key in a Hardware Security Module instead of
environment variables. Requires a PKCS#11-compatible device (YubiHSM 2, Nitrokey
HSM 2, AWS CloudHSM, etc.) or SoftHSM2 for development.

```
server:
    # Path to the PKCS#11 shared library (.so) — HSM disabled when absent
    hsm-pkcs11-lib:  /usr/lib/softhsm/libsofthsm2.so

    # PKCS#11 slot index (0-based, default: 0)
    hsm-slot:        0

    # PIN — strongly prefer the HSM_PIN environment variable
    # hsm-pin:       1234       ← emits WARN if set here (plaintext in config)

    # Label of the CKO_SECRET_KEY object used as the REST API Bearer token
    hsm-api-key-label:   runbound-api-key

    # Label of the CKO_SECRET_KEY object used as the JSON store HMAC key
    hsm-store-key-label: runbound-store-key
```

Store the PIN in an env file:

```bash
echo "HSM_PIN=1234" >> /etc/runbound/env
chmod 640 /etc/runbound/env
```

**Key priority** (highest first): HSM → env var → config file → auto-generated.

When `hsm-pkcs11-lib` is set and any key fails to load, Runbound exits immediately
with an error. There is no silent fallback.

→ Full setup guide including SoftHSM2, YubiHSM 2, and production recommendations: [docs/hsm.md](hsm.md)

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

```
dnssec-log-bogus: yes   # log DNSSEC validation failures (default: no)
```

When enabled, every DNSSEC validation failure emits a `WARN` log line with the query
name, record type, and reason (`bogus`). Useful for diagnosing misconfigured zones
without enabling full `verbosity: 2` noise.

### Privacy controls (RGPD / GDPR)

```
server:
    log-retention: 1000   # max entries in the /logs ring buffer (0 = disabled)
    log-client-ip: no     # include client IPs in /logs (no = replace with "[redacted]")
```

| Directive | Type | Default | Description |
|---|---|---|---|
| `log-retention` | integer | `1000` | 🔒 RGPD — Maximum number of entries kept in the in-memory query log ring buffer. Set to `0` to disable the ring buffer entirely and return an empty array from `GET /logs`. No client IPs are held in RAM when set to `0`. |
| `log-client-ip` | bool | `no` | 🔒 RGPD — Whether to record the client IP in `/logs` and the logfile. Set to `yes` to include real IPs (debugging, investigation). Default `no` replaces every IP with `[redacted]` before storing. Does **not** affect the audit log (IPs are required there for PCI-DSS / NIS2 traceability). |

Both directives take effect at **startup only** — a full restart is required to change them
(SIGHUP hot-reload only reloads DNS zones, not the ring buffer configuration).

See [docs/gdpr.md](gdpr.md) for the full GDPR compliance guide.

### ACME / Let's Encrypt (automatic TLS)

Runbound can provision and renew a TLS certificate automatically from Let's Encrypt
using the ACME HTTP-01 challenge. Port 80 must be reachable from the internet.

```
server:
    acme-email:          admin@example.com    # required — contact email for Let's Encrypt
    acme-domain:         dns.example.com      # domain to certify (repeat for SANs)
    acme-domain:         alt.example.com
    acme-cache-dir:      /etc/runbound/acme   # stores account.json + cert files
    acme-staging:        no                   # yes → use Let's Encrypt staging CA (testing)
    acme-challenge-port: 80                   # port for HTTP-01 validation (default: 80)
```

| Directive | Type | Default | Description |
|---|---|---|---|
| `acme-email` | string | — | ACME contact email. Required to enable auto-TLS. |
| `acme-domain` | string | — | Domain name to include in the certificate. Repeat for multiple SANs. |
| `acme-cache-dir` | path | `/etc/runbound/acme` | Directory for ACME account credentials and certificate files. |
| `acme-staging` | bool | `no` | Use Let's Encrypt staging CA. Enable for testing — staging certs are not trusted by browsers. |
| `acme-challenge-port` | int | `80` | Port that the built-in HTTP-01 challenge server binds to. Port 80 must be publicly accessible. |

**How it works:**

1. On startup Runbound checks whether the certificate is missing or was last modified
   more than **60 days ago**. Let's Encrypt issues 90-day certificates, so a 60-day
   mtime threshold means renewal triggers with **at least 30 days of validity remaining**.
2. If renewal is needed, a temporary HTTP server binds on `acme-challenge-port` to answer
   Let's Encrypt's HTTP-01 challenge.
3. The issued certificate is written atomically to `acme-cache-dir/cert.pem` and
   `acme-cache-dir/key.pem` — then used as `tls-service-pem` / `tls-service-key`.
4. A background task **checks every 6 hours** and triggers renewal if the 60-day mtime
   threshold is met (i.e., ≤ 30 days before expiry).
5. After renewal, restart Runbound to load the new certificate (or configure your process
   supervisor to watch the cert file and SIGHUP on change).

**Timer summary:** check interval = 6 h · renewal threshold = cert age > 60 days · minimum validity at renewal = 30 days.

**Quick setup:**

```
server:
    acme-email:  admin@example.com
    acme-domain: dns.example.com

    # These are auto-populated from acme-cache-dir after first issuance:
    tls-service-pem: /etc/runbound/acme/cert.pem
    tls-service-key: /etc/runbound/acme/key.pem
```

See [tls.md](tls.md) for the full TLS setup options including self-signed and
bring-your-own certificate.

### Audit log

Runbound can write a tamper-evident audit log recording all zone changes, feed
operations, authentication failures, and configuration reloads.

```
server:
    audit-log:          yes
    audit-log-path:     /var/log/runbound/audit.log
    audit-log-hmac-key: "your-hex-encoded-key"   # see note below
```

| Directive | Type | Default | Description |
|---|---|---|---|
| `audit-log` | bool | `no` | Enable the audit log. |
| `audit-log-path` | path | `/var/log/runbound/audit.log` | Where to write audit events. Parent directory must exist. |
| `audit-log-hmac-key` | string | auto-generated | HMAC-SHA256 key (hex). If omitted, a random key is generated at startup and printed to the log. |

**Log format** — one JSON object per line:

```json
{"seq":1,"ts":1715000000,"event":"DnsAdd","fields":{"name":"nas.home.","rtype":"A","value":"192.168.1.10"},"mac":"a3f1..."}
```

| Field | Description |
|---|---|
| `seq` | Monotonic sequence number. Gaps indicate tampered or missing entries. |
| `ts` | Unix timestamp (seconds). |
| `event` | Event type (snake_case): `startup`, `shutdown`, `dns_add`, `dns_delete`, `feed_add`, `feed_delete`, `blacklist_add`, `blacklist_delete`, `auth_failure`, `config_reload`, `logs_clear`. |
| `fields` | Event-specific payload. |
| `mac` | HMAC-SHA256 over `seq ‖ ts ‖ event ‖ fields_json`. |

**Key management:**

```bash
# Generate a key:
openssl rand -hex 32

# Preferred — pass via environment variable to avoid storing in config:
export RUNBOUND_AUDIT_HMAC_KEY="$(openssl rand -hex 32)"
```

Setting `audit-log-hmac-key` in plain text emits a `WARN` at startup reminding you
to prefer the environment variable. When the env var is set it overrides the config value.

**Read the last N entries via the API:**

```bash
curl -s -H "Authorization: Bearer $KEY" http://localhost:8080/api/audit/tail?n=50
```

See [api.md](api.md) for the full `/audit/tail` endpoint documentation.

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

**`cache-min-entries`** — floor for memory-pressure halvings (v0.5.1+):

```
server:
    cache-min-entries: 2048
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `cache-min-entries` | integer | `2048` | Minimum number of entries the cache will be reduced to during memory pressure events. The cache halving mechanism will not go below this value. |

The halving loop also enforces a 5-minute cooldown between halvings and will disable
further halvings if they produce no measurable reduction in system memory pressure,
logging a clear `WARN` that points to the root cause.

Recommended values:
- `1024` — systems with < 4 GB RAM or high memory contention
- `2048` — default, suitable for most deployments
- `4096` — systems with ≥ 4 GB RAM where cache hit rate matters

### XDP kernel-bypass fast path

```
server:
    xdp: no    # default: yes
```

Disables the AF/XDP kernel-bypass fast path at runtime without recompiling. When set
to `no`, Runbound starts on the standard `SO_REUSEPORT` kernel path. All DNS features
remain active — only the kernel-bypass acceleration is skipped.

Equivalent to passing `--no-xdp` on the command line.

Use `xdp: no` when:
- The host lacks `CAP_NET_ADMIN`, `CAP_BPF`, or the `AF_XDP` address family
  (typical in containers, some cloud VMs, or restricted systemd sandboxing)
- Troubleshooting NIC compatibility issues
- The XDP program is rejected by the kernel BPF verifier

See [xdp.md](xdp.md) for full requirements and capability configuration.

### XDP interface selection

```
server:
    xdp-interface: eth1    # explicit NIC for XDP
    # xdp-interface: none  # disable XDP via interface override
```

By default, Runbound auto-selects the first non-loopback interface with an assigned
IP address. In multi-NIC systems this may silently pick the wrong interface.

Use `xdp-interface:` to pin XDP to a specific NIC:

```
# Dual-NIC setup: virtio for management, X520 for DNS
# Without this directive, Runbound may pick the wrong interface
server:
    xdp-interface: eth1
```

Set `xdp-interface: none` to disable XDP via the interface override — equivalent to
`xdp: no` but leaves the `xdp:` directive unchanged for other hosts sharing the
same config file:

```
server:
    xdp: yes            # kept for other hosts
    xdp-interface: none # this host: disable XDP (wrong NIC / missing caps)
```

The auto-select path logs the chosen interface at startup (verbosity ≥ 2):

```
INFO XDP auto-selected interface: ens18 (use xdp-interface: to override)
```

### XDP hugepages

```
server:
    xdp-hugepages: 512    # default: 0 (disabled)
```

Number of 2 MiB hugepages to pre-allocate for AF_XDP UMEM. Hugepages reduce TLB
pressure on the hot packet path. Requires `vm.nr_hugepages` to be set in the kernel
before Runbound starts:

```bash
echo 512 | sudo tee /proc/sys/vm/nr_hugepages
```

A value of 0 disables hugepage allocation (default). At 100 k QPS, 512 pages
(1 GiB) is a comfortable working set.

### XDP NIC ring size

```
server:
    xdp-ring-size: auto    # default: auto (maximize to driver max)
```

At startup, Runbound queries the NIC driver for the maximum supported RX/TX ring depth
via `SIOCETHTOOL` and applies it before attaching the XDP program. This eliminates
hardware FIFO overflows that would otherwise drop packets silently before XDP sees them
(common on Intel ixgbe cards whose default ring is 512 descriptors).

| Value | Behavior |
|---|---|
| `auto` | Detect and apply `rx_max_pending` / `tx_max_pending` from the driver |
| integer (e.g. `4096`) | Set ring to this exact value, capped at the driver maximum |

**Fallback:** If the driver does not support ethtool ring queries (virtio-net, some cloud
NICs) or Runbound lacks `CAP_NET_ADMIN`, the resize is silently skipped and the driver
default is used. A `WARN` is emitted in the log.

```
[INFO]  xdp: NIC ring ens18 rx 512→4096 tx 256→4096
[WARN]  xdp: ring resize failed on ens18 — Operation not permitted
```

Monitor via `GET /api/system`: `nic_rx_ring`, `nic_rx_ring_max`, `nic_rx_dropped`.

### XDP IRQ affinity

```
server:
    xdp-irq-affinity: auto    # default: off
```

When set to `auto`, Runbound pins each NIC queue's IRQ to the same physical core as its XDP worker at startup. Reads `/proc/interrupts`, writes `/proc/irq/<N>/smp_affinity_list`. Requires `CAP_NET_ADMIN`. Silent no-op in containers or when `/proc/irq/` is not writable.

Gain: −1–5 µs latency variance, +1–3% throughput on high-frequency workloads.

### XDP cache snapshot

```
server:
    xdp-cache-snapshot: yes    # default: no
```

Enable the XDP cache snapshot path: cache hits are answered directly by the XDP worker
thread from an `ArcSwap<HashMap>` without entering the hickory resolver.
Requires `xdp: yes`. Reduces per-query latency for cached responses to < 1 µs.

**Requires v1.0+** — planned for the v1.0 milestone (#60).

### XDP CPU governor

```
server:
    xdp-cpu-governor: performance    # default: (unset — do not touch)
```

Set the Linux CPU frequency governor for cores running XDP worker threads.
`performance` disables P-state transitions during the XDP polling loop, eliminating
the 10–50 µs wakeup latency spike seen when cores return from C-states.

Accepted values: `performance`, `powersave`, `ondemand`. Requires root and
`cpufreq` kernel support. Has no effect on systems without governor control.
### CPU affinity

```
server:
    cpu-affinity: no    # default: yes
```

Disables pinning tokio worker threads and DNS socket workers to physical CPU cores.
Set to `no` in containers or environments without `CAP_SYS_NICE`.

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

    tls-service-pem:    /etc/runbound/cert.pem
    tls-service-key:    /etc/runbound/key.pem
    dot-client-auth-ca: /etc/runbound/client-ca.pem   # optional — mTLS for DoT

    api-port:  8080
    logfile:   ""
    verbosity: 1

    dnssec-log-bogus: yes

    audit-log:      yes
    audit-log-path: /var/log/runbound/audit.log

    acme-email:  admin@example.com
    acme-domain: dns.example.com

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
| 8080 | HTTP | REST API (localhost only, all nodes) |
| 8082 | HTTPS | Sync server (master only, network-accessible) |

The sync port number is configurable. The REST API stays on localhost on all nodes.

---

## Environment variables

| Variable | Description |
|---|---|
| `RUNBOUND_API_KEY` | REST API Bearer token. Overrides `api-key` in config. |
| `RUNBOUND_AUDIT_HMAC_KEY` | HMAC key for the audit log. Overrides `audit-log-hmac-key` in config. |
| `RUNBOUND_STORE_KEY` | HMAC-SHA256 key for JSON store integrity (HIGH-06). See below. |
| `RUNBOUND_DISABLE_XDP` | Set to any value to skip the entire XDP fast path without editing config. Emergency escape hatch when the host becomes unreachable after XDP attaches to the wrong NIC. Equivalent to `xdp: no`. |
| `RUNBOUND_SKIP_XDP_SELFTEST` | Set to any value to bypass the XDP loopback self-test. Useful in isolated environments (CI, VMs with no DNS traffic) where the self-test would always time out and disable XDP. |
| `RUST_LOG` | Log filter (e.g. `runbound=debug,info`). |

### `RUNBOUND_STORE_KEY` — JSON store integrity (HIGH-06)

When set, Runbound computes `HMAC-SHA256(json_content, key)` on every write and saves
it to a sidecar `.mac` file (e.g. `dns_entries.mac`). On load, the MAC is verified before
deserialization. A mismatch (tampered file) causes an ERROR and load is refused.

```bash
# Generate a 256-bit key (recommended):
export RUNBOUND_STORE_KEY="$(openssl rand -hex 32)"
# Add to /etc/runbound/env (chmod 640)
```

**Accepted key formats:**

| Format | Example |
|---|---|
| 64+ hex chars (decoded to bytes) | `a3f1...` (64 hex chars) |
| Raw UTF-8 string (any length) | `my-store-passphrase` |

**Behaviour by case:**

| Key set | `.mac` present | Result |
|---|---|---|
| No | No | OK — integrity not configured |
| No | Yes | WARN — cannot verify without key |
| Yes | No | WARN — saved without protection (backwards compat) |
| Yes | Yes, match | OK |
| Yes | Yes, mismatch | **ERROR — load refused** |

Domain cache files (per-feed JSON under `feed_cache/`) are regeneratable: a HMAC
mismatch discards the cache with WARN and triggers a re-fetch on the next update cycle.

### API key rotation without restart

The Bearer token can be rotated live without restarting Runbound or interrupting DNS service:

```bash
# 1. Generate a new key and update the environment:
NEW_KEY=$(openssl rand -hex 32)
export RUNBOUND_API_KEY="$NEW_KEY"   # or update your systemd EnvironmentFile

# 2. Rotate — call with the CURRENT key, the new key is read from env:
curl -X POST http://localhost:8080/api/rotate-key \
  -H "Authorization: Bearer $OLD_KEY"

# 3. From this point on, $NEW_KEY is required for all API calls.
```

The old token is invalidated atomically. The rotation is recorded in the audit log.
See [api.md](api.md#post-rotate-key) for full details.

---

## Fixed runtime limits

The following limits are compiled in and cannot be changed via configuration.
They exist to bound memory usage and protect against authenticated DoS.

| Limit | Value | Description |
|---|---|---|
| **API max payload** | 64 KB | Maximum size of any single REST API request body. Requests with a `Content-Length` header exceeding this value receive a `413 Payload Too Large` response before the body is read. |
| **API rate limit** | 30 req/s | Token-bucket rate limiter per source IP on the REST API. Burst capacity: 60 requests. Returns `429 Too Many Requests` when exceeded. |
| **Sync ring buffer** | 1,000 events | The master keeps the last 1,000 delta events in memory. A slave that falls more than 1,000 events behind receives `410 Gone` and triggers a full re-sync. |
| **Memory purge threshold** | 80 % → 50 % | When system memory usage reaches 80 %, Runbound purges the DNS resolver cache. Purge stops when usage falls below 50 % (target). |
| **Max DNS entries (API)** | 10,000 | Maximum number of DNS records that can be added via `POST /dns`. Feed-loaded blocklist entries are not counted here. |
| **Max blacklist entries (API)** | 100,000 | Maximum number of manual blacklist entries via `POST /blacklist`. |
| **Max feed subscriptions** | 100 | Maximum number of concurrent feed subscriptions via `POST /feeds`. |
