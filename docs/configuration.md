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

### API key

```
# In config (not recommended for production):
api-key: "change-me"

# Preferred — environment variable (never stored in config file):
# export RUNBOUND_API_KEY="$(openssl rand -hex 32)"
```

The environment variable takes priority over the config file value.

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

    rate-limit: 500

    local-zone: "home." static
    local-data: "nas.home.     300 IN A 192.168.1.10"
    local-data: "router.home.  300 IN A 192.168.1.1"

    tls-service-pem: /etc/runbound/cert.pem
    tls-service-key: /etc/runbound/key.pem

    logfile: ""
    verbosity: 1

forward-zone:
    name:         "."
    forward-addr: 1.1.1.1@53
    forward-addr: 9.9.9.9@53
```

---

## Environment variables

| Variable | Description |
|---|---|
| `RUNBOUND_API_KEY` | REST API Bearer token. Overrides `api-key` in config. |
| `RUST_LOG` | Log filter (e.g. `runbound=debug,info`). |
