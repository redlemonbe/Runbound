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


### Web UI (embedded server)

Runbound can serve the management dashboard itself — no nginx required.

```
server:
    ui-enabled: yes   # default: no
    ui-port:    8090  # default: 8090
    ui-bind:    0.0.0.0   # default: 0.0.0.0 (all interfaces)
```

| Directive | Type | Default | Description |
|-----------|------|---------|-------------|
| `ui-enabled` | bool (`yes`/`no`) | `no` | Enable the embedded web UI server |
| `ui-port` | integer | `8090` | TCP port the UI server binds to |
| `ui-bind` | string | `0.0.0.0` | Bind address for the UI server |

The embedded server serves `index.html` at `GET /` and transparently proxies
every `/api/*` request to `http://127.0.0.1:<api-port>` — the REST API remains
localhost-only. See [web-ui.md](web-ui.md) for setup details.

> **Note:** If `ui-enabled: no` (the default), no UI port is opened and the
> `ui-port` / `ui-bind` directives are ignored.


### ICMP echo responder (#89)

> Requires a binary compiled with `--features xdp`. On binaries without XDP support, this
> section is silently ignored.

```
icmp {
    enable:           no     # default: no — set yes to activate XDP ICMP responder
    rate-limit:       10     # echo requests/s per source IP before dropping (default: 10)
    rate-limit-burst: 5      # initial burst tokens for new source IPs (default: 5)
}
```

| Directive | Type | Default | Description |
|---|---|---|---|
| `enable` | bool (`yes`/`no`) | `no` | Activate the XDP ICMP echo handler |
| `rate-limit` | integer | `10` | Steady-state limit: max echo requests per second per source IP |
| `rate-limit-burst` | integer | `5` | Burst tokens granted to new source IPs on first contact |

**Rate limiting behaviour:** Each source IP starts with `rate-limit-burst` free tokens.
Once burst tokens are consumed, the steady-state `rate-limit` (pings/s) applies within a
1-second fixed window. Excess pings are dropped (XDP_DROP) with no reply. Counters are
available via `GET /api/icmp/stats`.

**Live updates:** `PUT /api/icmp/config` updates the running config without restart.
The background BPF poll task applies changes to the kernel map within 1 second.

> **Security note:** The default bind for the API is `127.0.0.1` only. The ICMP handler
> operates at the XDP layer on the NIC, independent of the API port. The XDP program handles
> frames arriving on the configured interface (`xdp-interface` or auto-detected).

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

### Serve-stale (RFC 8767)

Return expired cache entries while fetching a fresh answer in the background. Prevents NXDOMAIN or SERVFAIL from hitting clients when an upstream is momentarily unreachable.

```
server:
    serve-expired: yes             # Serve stale entries. Default: no.
    serve-expired-ttl: 86400       # Max age of stale entries in seconds. 0 = unlimited.
    serve-expired-reply-ttl: 30    # TTL returned to clients for stale answers.
```

### Prefetch

Proactively refresh cache entries that are about to expire when they are queried. Reduces latency for frequently-requested domains.

```
server:
    prefetch: yes                  # Enable prefetch. Default: no.
    prefetch-threshold: 10         # Only prefetch entries queried at least N times. Default: 0.
```

### HTTP/3 guard

```
block-https-record: yes   # default: no
```

When enabled, Runbound returns `NOERROR` with an empty answer for all DNS queries of
type HTTPS (type 65). This prevents browsers from discovering HTTP/3 (QUIC) support
via DNS and forces them to use HTTP/2 over TCP.

**Use case:** networks where UDP/443 is blocked or unreliable. Without this option,
browsers cache the HTTPS record and attempt QUIC connections that silently fail,
causing slow or broken page loads for sites that advertise `alpn="h3"`.

This has no effect on browsers that use DNS-over-HTTPS (DoH) directly — they bypass
Runbound entirely for DNS resolution.

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
# Single NIC — explicit
server:
    xdp-interface: eth1

# Dual-NIC 10G — bind XDP on both fibres simultaneously
server:
    xdp-interface: nic2,nic3

# Auto-detect all eligible physical interfaces (UP, non-bonded, non-virtual)
server:
    xdp-interface: auto
```

**Multi-interface mode** ( or ): Runbound binds an independent
AF_XDP socket set and worker pool on each interface. Useful for multi-fibre setups
where a single 10 GbE card is the bottleneck. XDP is **not compatible with bonding**
— use independent interfaces, never a bond master.

The  mode enumerates  and skips: , bridges (,
), , , bonded interfaces (master or slave). A WARN is logged for
each skipped bonded interface.

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

Cache entries are stored with a pre-serialized wire-format payload (`wire_payload: Bytes`).
The worker does a direct memcpy + QueryID patch — no DNS parsing on cache hit.

### XDP domain-affinity routing

```
server:
    xdp-domain-routing: no    # default: no
```

When enabled, the eBPF program hashes each DNS QNAME with FNV-1a and redirects the packet to a dedicated CPU via CPUMAP. All queries for the same domain always land on the same core — the cache entry stays warm in L1/L2.

ASCII-lowercased before hashing: `Example.com` and `example.com` route to the same core.

Requires multi-queue NIC and XDP native mode. Falls back to RSS (random distribution) with a `WARN` if CPUMAP init fails.

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

### Upstream racing

```
server:
    upstream-racing: yes    # default: no
```

When enabled, every forwarded query is sent to **all** configured upstreams
simultaneously. The first valid response wins; replies from slower upstreams are
discarded. Reduces tail latency when upstream reliability varies.

Requires at least two upstreams. Falls back silently to single-resolver mode when
fewer than 2 upstreams are available.

Per-upstream win counters are exposed in `GET /api/system` as
`upstream_racing_wins: {"ip": count}`.

### resolv.conf emergency fallback

```
server:
    resolv-fallback: yes    # default: yes
```

When **all** configured upstreams become unreachable, Runbound reads
`/etc/resolv.conf` and injects the listed `nameserver` lines as temporary
plain-UDP upstreams. These fallback upstreams are:

- Visible in `GET /api/upstreams` with `"source": "resolv.conf"` and `"temporary": true`
- Automatically removed when any primary upstream recovers (checked every 30 s)
- Never persisted to `upstreams.json`

Set `resolv-fallback: no` to disable this behaviour entirely. Useful in
environments where `/etc/resolv.conf` points to a loopback stub resolver
(e.g. `systemd-resolved`) that would create a forwarding loop.

---

### Firewall auto-management

Opt-in feature: Runbound can open the ports it needs (DNS, API, sync) in the
host firewall on startup and close them on clean shutdown. Supports UFW,
nftables, and iptables. Detected automatically; explicitly selectable.

```
server:
    firewall-manage: no      # default: no — opt-in, never changes rules by default
    firewall-backend: auto   # auto | ufw | nftables | iptables
    firewall-tag: runbound   # comment tag added to every rule Runbound manages
```

**Detection order** (when `firewall-backend: auto`):
1. UFW — if `ufw` binary exists and UFW is active
2. nftables — if `nft` binary exists
3. iptables — if `iptables` binary exists
4. None — feature is a no-op (startup proceeds normally)

**Ports opened** (on startup) and **closed** (on clean shutdown):

| Port | Proto | Condition |
|------|-------|-----------|
| `port` (DNS) | UDP + TCP | always |
| `api-port` | TCP | if API is enabled |
| `sync-port` | TCP | master only |

Rules are tagged with `firewall-tag` (default `runbound`). Only rules with
that tag are ever removed. Runbound never flushes chains or modifies unrelated
rules.

> **Safety:** `firewall-manage: no` (default) means Runbound never touches
> firewall rules unless explicitly enabled. If the process is killed with
> SIGKILL the rules remain open until manually removed or next clean start.

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
| `forward-tls-hostname` | TLS SNI hostname for DoT. Overrides the built-in IP→name map. Required for custom DoT servers. |

**DNS-over-TLS to upstream:**

```
forward-zone:
    name:                 "."
    forward-addr:         1.1.1.1@853
    forward-addr:         1.0.0.1@853
    forward-tls-upstream: yes
    # forward-tls-hostname: cloudflare-dns.com  ← auto-detected for 1.1.1.1/1.0.0.1
```

Built-in SNI map (no `forward-tls-hostname` needed for these):

| IP | SNI used |
|---|---|
| `1.1.1.1`, `1.0.0.1` | `cloudflare-dns.com` |
| `9.9.9.9`, `149.112.112.112` | `dns.quad9.net` |
| `8.8.8.8`, `8.8.4.4` | `dns.google` |
| `208.67.222.222`, `208.67.220.220` | `dns.opendns.com` |
| *(any other IP)* | IP literal — TLS will fail unless you set `forward-tls-hostname` |

For custom DoT servers, set the hostname explicitly:

```
forward-zone:
    name:                 "."
    forward-addr:         203.0.113.1@853
    forward-tls-upstream: yes
    forward-tls-hostname: dot.internal.example.com
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

    upstream-racing:  yes          # send to all upstreams, return first response
    resolv-fallback:  yes          # fallback to /etc/resolv.conf when all upstreams fail

    # Replication — master side:
    # mode:      master
    # sync-port: 8082
    # sync-key:  <openssl rand -hex 32>

    # Replication — slave side:
    # mode:        slave
    # sync-master: 192.168.1.10:8082
    # sync-key:    <same key as master>
    # sync-port:   8082   # enables relay server + auto-registration

forward-zone:
    name:                 "."
    forward-addr:         1.1.1.1@853
    forward-addr:         9.9.9.9@853
    forward-tls-upstream: yes

# Optional — io_uring for TCP/DoT/DoH slow path (Linux 5.10+)
# io-uring {
#     enable: yes
# }

# Optional — AXFR zone transfers for secondary nameservers
# axfr {
#     enable: yes
#     allow:  192.168.1.20     # IP of your secondary DNS
# }

# Optional — alert thresholds (DDoS detection + auto-block)
# alert {
#     name:             ddos-block
#     metric:           client-qps
#     window-s:         10
#     threshold:        500
#     action:           block
#     block-duration-s: 300
# }
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
    sync-port:     8082                 # opens the slave relay server (TLS + HMAC)
```

`sync-port` on a slave starts a TLS relay server that the master connects to for
config push and relay forwarding. When set, the slave registers with the master at
startup and advertises `<slave_ip>:<sync-port>` as its relay address.

On first start, the slave performs a **TOFU (Trust On First Use)** TLS handshake:

1. Connects to master with no cert validation.
2. Downloads the cert fingerprint from `GET /sync/cert`.
3. Cross-checks it against the fingerprint captured during the TLS handshake.
4. Saves the SHA-256 fingerprint to `/etc/runbound/sync-master.fingerprint` (chmod 640).
5. Emits a `WARN` log with the fingerprint for manual verification.

All subsequent connections pin the saved fingerprint. A mismatch aborts the connection.
To re-key, delete `/etc/runbound/sync-master.fingerprint` on the slave and restart.

**Auto-registration** — when `sync-port` is set on the slave, it generates (or reloads)
a stable UUID from `/etc/runbound/node-id` and a self-signed relay certificate at
`/etc/runbound/relay-cert.pem`, then registers with the master via a HMAC-signed
`POST /nodes/register` request. Registered nodes appear in `GET /api/nodes` on the master.

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

| Port | Protocol | Direction | Purpose |
|---|---|---|---|
| 53 | UDP + TCP | clients → any node | DNS queries |
| 8080 | HTTP | localhost only | REST API (all nodes) |
| 8082 | HTTPS | slave → master | Delta journal sync (slave initiates) |
| 8082 | TLS | master → slave | Relay / config push (master initiates) |

The sync port number is configurable. Both sides use the same port number by convention.
The REST API stays on localhost on all nodes.

---

---

## `io-uring:` directives

> Requires Linux 5.1+ with io_uring support (`CONFIG_IO_URING`). On kernels
> without io_uring, this section is silently ignored and Runbound falls back
> to epoll/tokio default I/O.

io_uring replaces the default epoll-based async I/O with the Linux io_uring
submission-queue interface. Reduces system-call overhead on the slow path
(TCP DNS, DoT, DoH) by batching I/O operations into ring buffers shared
between user space and kernel.

```
io-uring {
    enable: yes
}
```

| Directive | Type | Default | Description |
|---|---|---|---|
| `enable` | bool (`yes`/`no`) | `no` | Enable io_uring for async DNS and API I/O. |

**Startup detection:** Runbound reads `/proc/sys/kernel/io_uring_disabled` at
startup. If the value is `1` or `2` (restricted or disabled), io_uring is
silently skipped even when `enable: yes` is set, and a `WARN` is emitted.

**Performance impact (slow path):** io_uring reduces per-syscall overhead for
TCP connections. The XDP fast path (UDP) is unaffected — it never uses syscalls.
At 5M+ QPS with a high cache-hit rate (≥ 85 % XDP fast path), the improvement
is primarily felt on the remaining slow-path TCP/DoT/DoH queries.

**When to enable:**
- Bare-metal or VM with Linux ≥ 5.1 and `io_uring_disabled = 0`
- High-volume DoT/DoH deployments (millions of TCP connections)
- Benchmarking the slow path

**When to leave disabled (default):**
- Containers with restricted syscall profiles (Docker default seccomp blocks
  some io_uring operations on older container runtimes)
- Kernels older than 5.10 (io_uring was stabilised in 5.10)

Check your kernel's io_uring status:

```bash
cat /proc/sys/kernel/io_uring_disabled
# 0 = enabled (safe to use)
# 1 = restricted (only privileged processes)
# 2 = disabled system-wide
```

---

## `axfr:` directives

AXFR zone transfers (RFC 5936) allow secondary DNS servers to pull a complete
copy of a zone from Runbound. Useful for populating legacy resolvers, BIND9
secondaries, or monitoring tools that speak AXFR.

> AXFR support requires local zones to be defined with `local-zone:` /
> `local-data:` or loaded via the API. Feed-populated blocklists are not
> transferable via AXFR. Available since v0.9.13.

```
axfr {
    enable: yes
    allow:  192.168.0.0/16
    allow:  10.0.0.0/8
}
```

| Directive | Type | Default | Description |
|---|---|---|---|
| `enable` | bool (`yes`/`no`) | `no` | Enable AXFR zone transfer responses on TCP port 53. |
| `allow` | CIDR | — | IP range allowed to request AXFR. Repeat for multiple ranges. Required when `enable: yes`. |

**Security model:** AXFR exposes your full zone contents in a single TCP
connection. Always restrict `allow:` to trusted secondary nameserver IPs.
Requests from IPs not matching any `allow:` range receive `REFUSED`.

**Behaviour:**
- AXFR is delivered as: SOA → all records → SOA (RFC 5936 §2.2)
- Only `local-zone:` zones are transferable; the global catch-all is not
- IXFR requests (RFC 1995) receive a full AXFR fallback response

**Test a zone transfer:**

```bash
# Transfer the "home." zone from localhost
dig @127.0.0.1 home. AXFR

# Transfer from a secondary (replace with secondary IP):
dig @192.168.1.10 home. AXFR
```

---

## WebUI TLS certificate SANs

### Adding IP/hostname SANs to the auto-generated certificate

By default, the auto-generated WebUI certificate includes `localhost`, `127.0.0.1`, and `::1`
as Subject Alternative Names (as of v0.9.44).

To add your server's LAN IP or a custom hostname (required for browser access by IP without a
certificate warning):

```
server:
    ui-tls-san: 192.168.1.10
    ui-tls-san: myserver.local
```

The directive may appear multiple times — each value adds one SAN.

After adding SANs, delete the existing cert and restart to regenerate:

```bash
sudo rm /etc/runbound/webui-cert.pem /etc/runbound/webui-key.pem
sudo systemctl restart runbound
```

> **Note:** The cert is cached on disk. The fix only takes effect when the cert is regenerated.
> Existing installs must delete the cached cert files and restart.

---

## `alert:` directives

Alert rules trigger automated responses when a DNS metric exceeds a threshold
within a sliding time window. Use them to detect DDoS ramps, DNS flood attacks,
and reconnaissance sweeps without external monitoring tools.

Multiple `alert:` blocks can be defined — each creates an independent rule.

```
alert {
    name:             ddos-ramp
    metric:           client-qps
    window-s:         10
    threshold:        500
    action:           block
    block-duration-s: 300
}

alert {
    name:      recon-sweep
    metric:    client-qps
    window-s:  60
    threshold: 2000
    action:    notify
    notify-url: https://hooks.example.com/runbound-alert
}
```

| Directive | Type | Default | Description |
|---|---|---|---|
| `name` | string | — | Human-readable rule identifier. Required. Appears in logs and webhook payloads. |
| `metric` | string | `client-qps` | Metric to monitor. Currently supported: `client-qps` (queries/window/source IP). |
| `window-s` | integer | `10` | Sliding window length in seconds. Queries older than `window-s` are expired. |
| `threshold` | integer | `1000` | Query count that triggers the action (inclusive). |
| `action` | string | `log` | What to do when the threshold is reached: `log`, `block`, or `notify`. |
| `notify-url` | URL | — | Webhook URL for `action: notify`. POST with JSON payload (see below). |
| `block-duration-s` | integer | `300` | Seconds to block the source IP for `action: block`. `0` = permanent until restart. |

> **Note:** `name:` must be the first directive in each `alert:` block. If other directives appear before `name:`, a warning is logged and a rule is auto-created with a generated name — but this is not reliable. Always place `name:` first.

**Actions:**

| Action | Behaviour |
|---|---|
| `log` | Emit a `WARN` log line. No traffic impact. |
| `block` | Drop all queries from the source IP for `block-duration-s` seconds. Counter is visible in `GET /api/stats`. |
| `notify` | POST a JSON webhook to `notify-url`. Non-blocking — uses a background tokio task. |

**Webhook payload (`action: notify`):**

```json
{
  "rule":      "recon-sweep",
  "metric":    "client-qps",
  "source_ip": "1.2.3.4",
  "count":     2104,
  "threshold": 2000,
  "window_s":  60,
  "ts":        1748188800
}
```

**Alert status API:**

```bash
# List active blocks, rules, and recent alerts
curl -s http://localhost:8080/api/alerts   -H "Authorization: Bearer $TOKEN"

# Manually block an IP (permanent, no expiry)
curl -s -X PUT http://localhost:8080/api/alerts/blocked/1.2.3.4   -H "Authorization: Bearer $TOKEN"

# Unblock an IP manually
curl -s -X DELETE http://localhost:8080/api/alerts/blocked/1.2.3.4   -H "Authorization: Bearer $TOKEN"
```

> **Note:** Alert blocks are persisted to `alert-blocks.json` in the config directory and survive
> restarts. Blocks with an expiry time that has already passed are dropped on load.
> A background task runs every 60 seconds to remove expired blocks from both the in-memory tracker
> and the XDP map. Bot bans from the bot defense system also appear here with rules
> `bot-honeypot`, `bot-scanner`, or `bot-burst`.
> As of v0.9.44, alert *rules* **are** reloaded by `POST /api/reload` without a restart.

**Example — multi-layer protection:**

```
# Layer 1 — rate limiter (built-in, per-query token bucket)
server:
    rate-limit: 200

# Layer 2 — alert: block after sustained flood
alert {
    name:             sustained-flood
    metric:           client-qps
    window-s:         5
    threshold:        800
    action:           block
    block-duration-s: 600
}

# Layer 3 — notify NOC on very high-volume attack
alert {
    name:      noc-escalation
    metric:    client-qps
    window-s:  5
    threshold: 5000
    action:    notify
    notify-url: https://pagerduty.example.com/webhook
}
```


## Bot defense

Runbound includes a multi-layer bot defense system for the WebUI. All bot bans are integrated
into the alert system and visible in `GET /api/alerts`.

```
server:
    bot-ban-duration-secs: 86400   # Max ban duration in seconds. Default: 86400 (24h). 0 = permanent.
    bot-honeypot-enabled:  yes     # Enable honeypot on login form. Default: no.
```

**Detection layers:**

- **Honeypot** (`bot-honeypot-enabled: yes`): Hidden fake fields in the login form trap bots that
  auto-fill forms. First hit → immediate ban (rule: `bot-honeypot`).
- **Scanner detection**: Requests to known vulnerability scanner paths (`/wp-admin`, `/.env`,
  `/.git/*`, `/phpmyadmin`, `/xmlrpc.php`, etc.) → immediate ban (rule: `bot-scanner`).
- **Behavioral burst**: 10 failed requests within 5 seconds from the same IP → ban (rule: `bot-burst`).



> **Note:** Loopback addresses (`127.x`, `::1`), RFC-1918 private addresses, link-local, and ULA (`fc00::/7`) are **never** banned by the bot defense engine, even if they trigger a detection rule. This prevents the server from banning itself when internal tooling or health checks hit scanner trap paths.

**Enforcement**: Bans use the same pipeline as alert blocks — XDP BPF map injection (IPv4) or
userspace block (IPv6). Bans persist to `alert-blocks.json` and survive restarts.

**Auto-deban**: A background task runs every 60 seconds and removes expired bans from both the
userspace tracker and the XDP map.

**Cross-cluster**: Master propagates bot bans to all slaves via `SyncOp::AddGlobalBan`. Expired
bans or manual unbans propagate via `SyncOp::DeleteGlobalBan`.

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

---

## Additional directives reference

Directives below are supported by the parser but were previously undocumented.
Defaults reflect the code. Booleans accept `yes`/`no`. All live in the `server:` block
unless a section header is shown.

### Cache & TTL

| Directive | Default | Description |
|-----------|---------|-------------|
| `cache-min-ttl` | (unset) | Minimum TTL (seconds) advertised for cached answers — floor enforcement. |
| `cache-flush-cooldown` | `60` | Minimum seconds between two cache flushes (anti-abuse). |

### Serve-stale (RFC 8767)

| Directive | Default | Description |
|-----------|---------|-------------|
| `serve-stale` | `yes` | Serve expired cached answers while a refresh is in flight. Set `no` to disable. |
| `stale-answer-ttl` | `30` | TTL (seconds) sent with a stale answer. |
| `stale-max-age` | `86400` | Maximum age (seconds) a stale entry may be served. |

### Rate-limit tuning

| Directive | Default | Description |
|-----------|---------|-------------|
| `rate-limit-prefix-v4` | `24` | IPv4 prefix length used to bucket per-source rate limiting. |
| `rate-limit-prefix-v6` | `48` | IPv6 prefix length used to bucket per-source rate limiting. |
| `udp-busy-poll` | `no` | Enable UDP socket busy-polling on the kernel slow path (lower latency, higher CPU). |

### Block page (NXDOMAIN landing page)

| Directive | Default | Description |
|-----------|---------|-------------|
| `block-page` | `no` | Serve an HTTP block page for blocked domains instead of plain NXDOMAIN. |
| `block-page-port` | `8083` | TCP port for the block page server. |
| `block-page-title` | (brand) | Title shown on the block page. |
| `block-page-org` | (brand) | Organisation name shown on the block page. |
| `block-page-redirect-ip` | (unset) | IP returned for blocked names so clients reach the block page. |
| `block-page-allow-bypass` | `no` | Allow a user to bypass a block with a PIN. |
| `block-page-bypass-pin` | (unset) | PIN required when `block-page-allow-bypass` is enabled. |

### Other server directives

| Directive | Default | Description |
|-----------|---------|-------------|
| `pidfile` | (unset) | Path to write the process PID file. |
| `allow-update` | `yes` | Allow live record updates via the REST API. Set `no` for read-only. |
| `audit-checkpoint-every` | `10000` | Write an audit-log checkpoint every N entries (fast crash recovery). `0` disables. |
| `sync-allow-private-relay` | `no` | Master: accept slave relay hosts in RFC 1918 / ULA ranges (local deployments). |
| `tsig-key` | — | AXFR/IXFR TSIG key: `tsig-key: "name" <algorithm> "base64secret"`. May repeat. |

### XDP fine-tuning

| Directive | Default | Description |
|-----------|---------|-------------|
| `xdp-busy-poll` | `yes` | Drain the RX ring before sleeping + NAPI busy-poll hints (lower idle latency). |
| `xdp-cache-snapshot-size` | `10000` | Max entries in the XDP cache snapshot. |
| `xdp-fill-ring-size` / `xdp-comp-ring-size` / `xdp-rx-ring-size` / `xdp-tx-ring-size` | `auto` | Per-ring AF_XDP sizes; `auto` derives them from the NIC hardware ring. |

### WebUI TLS / ACME / branding

| Directive | Default | Description |
|-----------|---------|-------------|
| `ui-ca-cert` / `ui-ca-key` | (auto) | CA cert/key used to sign the self-signed WebUI certificate. |
| `ui-acme-domain` | (unset) | Domain for an ACME-issued WebUI certificate (`ui-tls: acme`). |
| `ui-acme-email` | (unset) | ACME account contact email for the WebUI cert. |
| `ui-acme-dns` | (unset) | ACME DNS-01 provider (e.g. `cloudflare`) for the WebUI cert. |
| `ui-acme-cf-token` | (unset) | Cloudflare API token for ACME DNS-01. |
| `ui-acme-hook` | (unset) | External hook command for ACME DNS-01. |
| `ui-brand-name` | `RUNBOUND` | White-label brand name shown in the WebUI header. |
| `ui-brand-logo-url` | (unset) | Logo URL for white-label branding. |
| `ui-accent-color` | `#22d3ee` | Accent colour (hex) for the WebUI theme. |
| `ui-favicon-url` | (unset) | Favicon URL for white-label branding. |

### Webhook target (in the `server:` block, repeatable)

A webhook is declared by a `webhook` line, optionally followed by its sub-directives:

```
server:
    webhook:         "https://hooks.slack.com/services/..."
    webhook-format:  slack          # slack | discord | ntfy | generic-json
    webhook-token:   "secret"       # optional bearer/token
    webhook-events:  "domain_blocked qps_spike slave_disconnect"   # or "all"
```

### `api-key-extra:` section (scoped API keys)

```
api-key-extra:
    label: "ci-readonly"
    key:   "env:CI_API_KEY"        # literal, or env:VAR to read from environment
    role:  read                    # read | dns | operator | admin
```

### `split-horizon:` section (per-subnet answers)

```
split-horizon:
    name:       "office"
    subnet:     "10.0.0.0/8"        # may repeat
    local-data: "intra.corp. A 10.0.0.5"   # may repeat
```
