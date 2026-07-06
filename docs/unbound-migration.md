# Unbound Migration Guide

Runbound is designed as a compatible DNS server for existing Unbound deployments. In most cases, pointing it at your existing `unbound.conf` is all you need. `include:` and `include-toplevel:` are honoured (glob supported), so a split configuration — e.g. Debian's `include: "/etc/unbound/unbound.conf.d/*.conf"` — loads correctly (included files must stay within the config file's directory). This page documents exactly what is and isn't supported.

---

## Compatibility matrix

### Fully supported

Directives with identical behavior to Unbound — no changes required.

#### `server:` block

| Directive | Notes |
|---|---|
| `interface` | Bind address(es) |
| `port` | Listen port (default: 53) |
| `do-ip4` | Enable/disable IPv4 |
| `do-ip6` | Enable/disable IPv6 |
| `do-udp` | Enable/disable UDP |
| `do-tcp` | Enable/disable TCP |
| `access-control` | ACL — `allow`, `deny`, `refuse` |
| `local-zone` | Static zones — `static`, `always_nxdomain`, etc. |
| `local-data` | Local DNS records — A, AAAA, PTR, CNAME, MX, TXT |
| `tls-service-pem` | TLS certificate path for DoT/DoH/DoQ |
| `tls-service-key` | TLS private key path |
| `verbosity` | Log level 0–5 |
| `logfile` | Log destination (`""` = stdout) |
| `private-address` | DNS rebinding guard — block CIDR ranges in resolver responses |
| `cache-max-ttl` | TTL cap for cached records (seconds) |
| `rate-limit` | Per-IP query rate limit in q/s |
| `dnssec-validation` | Enable DNSSEC (see caveats below) |
| `serve-expired` | Serve stale/expired cached answers when upstream is unreachable (Runbound alias: `serve-stale`) |
| `serve-expired-ttl` | Max age of a stale record still eligible to be served (Runbound alias: `stale-max-age`, default: 86400s) |
| `serve-expired-reply-ttl` | TTL returned to the client on a stale answer (Runbound alias: `stale-answer-ttl`, default: 30s) |
| `hide-identity` / `hide-version` | Refuse `id.server.`/`hostname.bind.` and `version.bind.`/`version.server.` CH TXT queries. Default: `yes` (hidden) — matches Unbound's secure-by-default. Set to `no` to answer them (RFC 4892 for `id.server.`; the others are long-standing BIND/Unbound convention). `authors.bind.` has no RFC standing and always REFUSED. |
| `identity` / `version` | Custom string returned for the identity/version CH TXT queries above when not hidden. Falls back to the system hostname / build version if unset. |

#### `forward-zone:` block

| Directive | Notes |
|---|---|
| `name` | Zone name |
| `forward-addr` | Upstream address (`ip@port` syntax supported) |
| `forward-tls-upstream` | Send queries over DNS-over-TLS to upstream |

---

### Supported with caveats

Directives that work but with noted differences from Unbound's behavior.

| Directive | Caveat |
|---|---|
| `dnssec-validation` | In the **default `forward` resolution mode**, Runbound does no DNSSEC validation at all — responses are built with the AD bit never set (not "trusted" or passed through from upstream). Full RRSIG-chain validation is performed under sovereign full recursion (`resolution: full-recursion`), an in-house resolver (`src/dns/recursor_wire.rs`, `src/dns/dnssec_*.rs`) entirely in-house and always compiled in (no Cargo feature gates it) — but OFF by runtime default: `resolution: forward` and `dnssec-validation: no` are the defaults; full recursion + DNSSEC validation are opt-in via config (`resolution: full-recursion`, `dnssec-validation: yes`), not a build flag. |
| `rate-limit` | Runbound uses a per-IP token bucket compatible with Unbound's semantics. Runbound extends this with per-subnet bucketing via `rate-limit-prefix-v4` / `rate-limit-prefix-v6` (Runbound-specific directives). |
| `tls-cert-bundle` | Accepted as an alias for `tls-service-pem`. Unbound uses `tls-cert-bundle` for the CA bundle, not the server certificate — if you use both, set `tls-service-pem` explicitly. |

---

### Parsed but ignored

Directives accepted without error but with no effect at runtime. Safe to leave in your existing config. Runbound logs a silent no-op — no warning emitted. (`logfile`, `pidfile`, `do-udp`, `do-tcp` and `axfr-enable` **are** honoured now and are not in this table.)

| Directive | Why it's a no-op in Runbound |
|---|---|
| `num-threads` | Runbound uses a Tokio async runtime with `SO_REUSEPORT` — threads are managed internally, not configurable via this directive |
| `msg-cache-size` / `rrset-cache-size` | Runbound has **one** unified answer cache, not separate message/rrset caches — use `cache-size` (which **is** honoured: it caps the answer cache; RAM-based auto-sizing when unset) |
| `so-rcvbuf` / `so-sndbuf` | Socket buffers managed internally |
| `outgoing-range` | Outgoing port range not applicable to Runbound's upstream pool |
| `num-queries-per-thread` | See `num-threads` |
| `infra-cache-slabs` / `key-cache-slabs` / `msg-cache-slabs` / `rrset-cache-slabs` | Runbound uses DashMap sharding, not configurable slab counts |
| `prefetch-key` | Key prefetching not separately configurable |
| `use-syslog` | Runbound logs to stdout/journald via `tracing` |
| `log-queries` / `log-replies` | Use `verbosity: 2` for per-query logging |
| `username` / `chroot` / `directory` | Process isolation handled by systemd (static `User=runbound`/`Group=runbound` created by `install.sh`, plus `PrivateTmp`) — no `DynamicUser` |
| `auto-trust-anchor-file` / `val-log-level` | See `dnssec-validation` caveat above |
| `harden-glue` / `harden-dnssec-stripped` | Security defaults equivalent to Unbound's hardened mode are always on |
| `unwanted-reply-threshold` / `private-domain` | Not currently implemented |
| `cpu-affinity` | Deprecated and ignored — CPU placement is now automatic (#163). Unlike the other entries in this table, this one **does** log a deprecation warning |
| `do-ip4` / `do-ip6` | The IPv4/IPv6 **listen** set is controlled by which `interface:` addresses you configure (`0.0.0.0` / `::` / a literal); these flags do not separately gate the resolver's outbound traffic |
| `udp-busy-poll` | `SO_BUSY_POLL` is not applied to the kernel-UDP sockets (distinct from `xdp-busy-poll`, which **is** wired) |
| `prefetch-threshold` | Accepted but unused: the prefetch refresher (#16) is TTL-driven (it refreshes entries near expiry), not hit-count-driven |
| `module-config` | Unbound modules are not supported — Runbound is not module-extensible. Not a recognized directive, so it's captured into `raw_passthrough` and re-emitted unchanged on config regen — no warning is logged |
| `python-script` | No Python scripting support. Same silent passthrough as `module-config` |
| `dnstap` | Not planned. Same silent passthrough as `module-config` |
| `forward-first` | `forward-zone` flag — unimplemented. Same silent passthrough as `module-config` |

---

## Runbound-only directives

Directives accepted by Runbound but not understood by Unbound. Unbound will warn on these; strip them if running the same config on both.

| Directive | Description |
|---|---|
| `api-key` | REST API Bearer token (prefer `RUNBOUND_API_KEY` env var) |
| `api-port` | REST API port (default: 8080) |
| `resolution` | Resolution mode: `forward` (default, trusts upstream) or `full-recursion` (in-house sovereign resolver, `src/dns/recursor_wire.rs`, with full RRSIG-chain DNSSEC validation) |
| `local-zone-dnssec` | Enable DNSSEC authoritative signing for local zones (default: no) |
| `rate-limit-prefix-v4` | IPv4 prefix for subnet bucketing (default: /24) |
| `rate-limit-prefix-v6` | IPv6 prefix for subnet bucketing (default: /48) |
| `cache-min-entries` | Minimum cache entries after memory pressure halvings (default: 2048) |
| `dnssec-log-bogus` | Log WARN on DNSSEC failures (default: no) |
| `log-retention` | In-RAM query log ring buffer size (default: 1000; 0 = disabled) |
| `log-client-ip` | Include client IPs in `/logs` (default: yes — set `no` for GDPR) |
| `audit-log` | Enable HMAC-SHA256 per-entry audit log with periodic checkpoints (default: no) |
| `audit-log-path` | Path for the audit log file |
| `audit-log-hmac-key` | HMAC key (hex). Auto-generated if omitted |
| `mode` | `master` (default) or `slave` — HA replication role |
| `sync-port` | Master: HTTPS sync server port |
| `sync-master` | Slave: `ip:port` of master |
| `sync-key` | Slave: Bearer token for master auth |
| `sync-interval` | Slave: sync interval in seconds (default: 30) |
| `acme-email` | ACME contact email for Let's Encrypt |
| `acme-domain` | Domain(s) for the certificate (repeat for SANs) |
| `acme-cache-dir` | Directory for ACME credentials and temp files |
| `acme-staging` | Use Let's Encrypt Staging (default: no) |
| `acme-challenge-port` | HTTP-01 challenge port (default: 80) |
| `tls-port` | DNS-over-TLS port (default: 853) |
| `https-port` | DNS-over-HTTPS port (default: 443) |
| `quic-port` | DNS-over-QUIC port (default: 853/UDP) |
| `tls-cert-hostname` | Hostname for TLS SNI and DoH path. Also accepted as `server-hostname` (alias parsed identically) |
| `dot-client-auth-ca` | Path to CA certificate PEM for DoT mutual TLS client authentication. When set, DoT clients must present a certificate signed by this CA. DoH and DoQ unaffected |
| `hsm-pkcs11-lib` | Path to PKCS#11 shared library (.so) for HSM integration — HSM disabled when absent |
| `hsm-slot` | PKCS#11 slot index (0-based, default: 0) |
| `hsm-pin` | PKCS#11 PIN — prefer `HSM_PIN` environment variable (chmod 640) |
| `hsm-api-key-label` | Label of the `CKO_SECRET_KEY` object used as the REST API Bearer token |
| `hsm-store-key-label` | Label of the `CKO_SECRET_KEY` object used as the JSON store HMAC key |
| `xdp` | Enable AF/XDP kernel-bypass fast path (default: yes) |
| `xdp-interface` | Explicit XDP network interface (default: auto-detect) |
| `xdp-cpu-governor` | Set `performance` governor on XDP cores (default: no) |
| `xdp-irq-affinity` | Pin NIC queue IRQs to XDP worker cores (default: no) |
| `xdp-hugepages` | Allocate UMEM with 2 MiB huge pages (default: yes) |
| `xdp-cache-snapshot` | Enable ArcSwap-backed XDP cache (default: yes) |
| `xdp-cache-snapshot-size` | Max entries in the XDP cache snapshot (default: 10000) |
| `xdp-domain-routing` | Route queries by QNAME hash to dedicated CPU (default: no) |
| `xdp-ring-size` | NIC ring buffer size — integer or `auto` (default: auto) |
| `xdp-rx-ring-size` | AF_XDP RX ring size — power of 2, 64–65536 (default: 4096) |
| `xdp-tx-ring-size` | AF_XDP TX ring size — power of 2, 64–65536 (default: 4096) |
| `xdp-fill-ring-size` | AF_XDP fill ring size — power of 2, 64–65536 (default: 4096) |
| `xdp-comp-ring-size` | AF_XDP completion ring size — power of 2, 64–65536 (default: 4096) |
| `prefetch` | Pre-resolve popular domains before TTL expiry (default: no) |
| `prefetch-threshold` | Min query count to qualify for prefetch (default: 5) |
| `cache-flush-cooldown` | Min seconds between consecutive cache flush calls (default: 60) |
| `upstream-racing` | Query all upstreams simultaneously, return first valid response (default: no) |
| `resolv-fallback` | Fall back to `/etc/resolv.conf` when all upstreams are unhealthy (default: yes) |

---

## Step-by-step migration

### 1. Install Runbound

```bash
curl -LO https://github.com/redlemonbe/Runbound/releases/latest/download/runbound-x86_64-linux-musl
chmod +x runbound-x86_64-linux-musl
sudo mv runbound-x86_64-linux-musl /usr/local/sbin/runbound
```

### 2. Test against your existing config

```bash
# Run on a non-standard port first to avoid disruption. The config path is a
# bare positional argument (there is no --config flag), and there is no --port
# flag either — the listen port comes only from the config file's port:
# directive. Set "port: 5353" in /etc/unbound/unbound.conf before starting.
sudo RUNBOUND_API_KEY="test" runbound /etc/unbound/unbound.conf

# Verify resolution
dig @127.0.0.1 -p 5353 google.com
dig @127.0.0.1 -p 5353 your-internal-host.corp.
```

### 3. Stop Unbound, start Runbound

```bash
sudo systemctl stop unbound
sudo systemctl disable unbound

sudo systemctl enable --now runbound
```

### 4. Roll back if needed

```bash
sudo systemctl stop runbound
sudo systemctl start unbound
```

---

## Known differences in behaviour

**Default ACL:** Unbound defaults to `refuse` for unknown IPs. Runbound does the same —
if no `access-control` entries match, the request is refused. No change needed.

**IPv4-mapped IPv6:** If a client connects via IPv6 as `::ffff:10.0.0.1`, Runbound
normalises it to `10.0.0.1` before ACL matching. Unbound behaviour varies by version.

**`num-threads`:** Unbound spawns OS threads; Runbound uses a Tokio async runtime
with `SO_REUSEPORT`. Setting `num-threads` in your config is harmless — it's silently
ignored.

**Module config:** If your Unbound config loads modules (`python`, `dynlib`, etc.),
strip those lines before migrating — Runbound doesn't support them. Unrecognized
directives are captured verbatim and re-emitted unchanged on config regen, with no
warning logged, so a stale module line won't be flagged for you.
