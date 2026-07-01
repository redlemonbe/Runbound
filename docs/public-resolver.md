# Deploying Runbound as a public encrypted resolver (#204)

Runbound already serves **DoT (853)**, **DoH (443)** and **DoQ (853/udp)** and
forwards upstream over DoT. This guide turns that into a real public,
encrypted, auto-discoverable resolver ("like 1.1.1.1") — the *deployment and
discovery* story, not new transports.

It builds on three features documented elsewhere:
- Encrypted serving + live cert management — [tls.md](tls.md)
- Anti-amplification (DNS Cookies, RRL slip, ANY-refused) — [configuration.md](configuration.md) (#203)
- Anycast readiness (health 503, drain, node-id, PROXY protocol) — [anycast.md](anycast.md) (#21)

---

## 1. Ports & firewall

| Port | Proto | Purpose |
|------|-------|---------|
| 53 | UDP + TCP | Plain DNS (legacy clients) |
| 853 | TCP | DoT (RFC 7858) |
| 443 | TCP | DoH (RFC 8484) — path `/dns-query` |
| 853 | UDP | DoQ (RFC 9250, QUIC) |

Open these inbound. If you terminate behind an L4 load balancer or anycast
relay, enable `proxy-protocol: yes` so per-client rate-limiting, ACL and logging
see the real client IP (see [anycast.md](anycast.md)).

---

## 2. A real certificate (not self-signed)

Public clients validate the certificate against your **hostname**, so a
self-signed cert is not an option. Use Let's Encrypt:

```
server:
    tls-service-pem: /etc/letsencrypt/live/dns.example.com/fullchain.pem
    tls-service-key: /etc/letsencrypt/live/dns.example.com/privkey.pem
    tls-cert-hostname: "dns.example.com"
```

DoT/DoH/DoQ auto-activate once `tls-service-pem`/`-key` are set. Certificate
changes are **applied live** — no restart (see [tls.md](tls.md)). For the WebUI
cert, built-in ACME (`ui-tls: acme`) is also available.

---

## 3. Auto-discovery — DDR (RFC 9462)

**Known limitation:** `ddr: yes` parses and Runbound stores the endpoint info
(hostname + DoT/DoH/DoQ ports), but SVCB synthesis for `_dns.resolver.arpa` is
**not yet wired into the wire serving path** (`serve_wire`, the only DNS
serving path in the current binary) — the struct holding this info is
currently dead code. A query for `SVCB _dns.resolver.arpa` gets whatever your
normal resolution/local-zone rules produce, not a synthesized answer. Treat
the config below as forward-looking; clients cannot yet auto-discover the
encrypted endpoint this way. See the tracked gap (PAR-7) for status.

Intended configuration once implemented:

```
server:
    ddr: yes
    tls-cert-hostname: "dns.example.com"
```

The design is for Runbound to answer `SVCB _dns.resolver.arpa` with one record
per transport, pointing at your hostname:

```
_dns.resolver.arpa. 7200 IN SVCB 1 dns.example.com. alpn="dot" port=853
_dns.resolver.arpa. 7200 IN SVCB 2 dns.example.com. alpn="h2"  port=443 dohpath="/dns-query{?dns}"
_dns.resolver.arpa. 7200 IN SVCB 3 dns.example.com. alpn="doq" port=853
```

A client reaching Runbound over plain DNS would then discover and verify the
encrypted endpoint before upgrading. The advertised ports would follow
`tls-port` / `https-port` / `quic-port` (defaults 853 / 443 / 853). Until this
lands, distribute the DoT/DoH/DoQ endpoint out-of-band (client provisioning,
a static SVCB record on a separate authoritative zone, etc.).

---

## 4. Access model — pick a profile

### Private resolver (closed) — mutual TLS

Require every DoT client to present a certificate signed by your CA (HIGH-08):

```
server:
    dot-client-auth-ca: /etc/runbound/clients-ca.pem
```

Only holders of an issued client cert can resolve. Ideal for an org-internal
encrypted resolver.

### Public resolver (open) — cookies + RRL

Open to the internet, hardened against spoofed-source amplification (#203):

```
server:
    dns-cookies: yes      # RFC 7873 — defeats spoofed UDP amplification
    rrl-slip:    2        # leak 1-in-2 over-rate UDP, silently drop the rest
    rate-limit:  200      # per-source-IP token bucket
    # ANY is already refused (RFC 8482)
```

DoT/DoH/DoQ are connection-oriented (TCP/QUIC handshake) and are **not** a
spoofed-amplification vector; the cookies + RRL layer protects the plain UDP
`:53` surface.

---

## 5. Anycast / multiple PoPs

Run the same config on every node, give each a `node-id`, and let an external
BGP daemon (BIRD/ExaBGP/FRR) announce one VIP and withdraw it when `/health`
returns 503. See [anycast.md](anycast.md) and the `health-*` / `drain-timeout`
directives.

---

## 6. DDNS / dynamic-IP caveats

- DDR and the certificate are tied to a stable **hostname**, not the IP — a
  changing public IP is fine as long as DNS for `dns.example.com` tracks it.
- Let's Encrypt issuance needs the hostname to resolve to the node during the
  ACME challenge.
- On anycast, every PoP presents the **same** hostname and certificate.

---

See also: [tls.md](tls.md), [anycast.md](anycast.md), [configuration.md](configuration.md), [api.md](api.md).
