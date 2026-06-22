# TLS Setup (DoT / DoH / DoQ)

Runbound supports three encrypted DNS protocols when a certificate and private key
are configured:

| Protocol | RFC | Default port | Path |
|---|---|---|---|
| **DNS-over-TLS (DoT)** | RFC 7858 | 853 (TCP) | — |
| **DNS-over-HTTPS (DoH)** | RFC 8484 | 443 (HTTPS) | `/dns-query` |
| **DNS-over-QUIC (DoQ)** | RFC 9250 | 853 (UDP) | — |

All three activate automatically when `tls-service-pem` and `tls-service-key` are set.
No additional directives are needed to enable DoH or DoQ.

### DoH quick test

```bash
# POST method (wire format)
curl -s --doh-url https://dns.example.com/dns-query https://example.com

# GET method (base64url-encoded DNS message)
kdig @dns.example.com +https google.com

# Using doggo
doggo --nameserver https://dns.example.com/dns-query google.com
```

### DoH client configuration

**Firefox:** Settings → Network Settings → Enable DNS over HTTPS → Custom → `https://dns.example.com/dns-query`

**Chrome/Edge:** Settings → Privacy → Use secure DNS → Custom → `https://dns.example.com/dns-query`

**Android 9+ (Private DNS):** Supports DoT only — enter `dns.example.com` (no path).

**Windows 11:** Settings → Network → DNS over HTTPS → `https://dns.example.com/dns-query`

---

## Option A — Let's Encrypt (public server)

Requires a publicly reachable server with a domain name pointing to it.

```bash
# Install certbot
apt-get install -y certbot

# Issue certificate (stop runbound briefly if it binds port 80)
certbot certonly --standalone -d dns.example.com

# Paths to use in runbound.conf:
# tls-service-pem: /etc/letsencrypt/live/dns.example.com/fullchain.pem
# tls-service-key: /etc/letsencrypt/live/dns.example.com/privkey.pem
```

Add to `/etc/runbound/runbound.conf`:

```
server:
    tls-service-pem: /etc/letsencrypt/live/dns.example.com/fullchain.pem
    tls-service-key: /etc/letsencrypt/live/dns.example.com/privkey.pem
```

**Auto-renewal:** certbot installs a systemd timer. After renewal, reload Runbound:

```bash
# /etc/letsencrypt/renewal-hooks/deploy/runbound.sh
#!/bin/sh
systemctl reload runbound
```

```bash
chmod +x /etc/letsencrypt/renewal-hooks/deploy/runbound.sh
```

---

## Option B — Self-signed certificate (internal / air-gapped)

For internal networks where clients trust your own CA.

```bash
# Generate a private key and self-signed certificate (10-year validity)
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout /etc/runbound/key.pem \
  -out /etc/runbound/cert.pem \
  -days 3650 \
  -subj "/CN=dns.internal"

# Lock down permissions
chmod 640 /etc/runbound/key.pem /etc/runbound/cert.pem
chown runbound:runbound /etc/runbound/key.pem /etc/runbound/cert.pem
```

Add to `runbound.conf`:

```
server:
    tls-service-pem: /etc/runbound/cert.pem
    tls-service-key: /etc/runbound/key.pem
```

Clients must be configured to trust your CA or the self-signed certificate.

---

## Option C — Internal CA (enterprise)

```bash
# 1. Generate CA key and certificate
openssl genrsa -out /etc/runbound/ca.key 4096
openssl req -x509 -new -nodes -key /etc/runbound/ca.key \
  -sha256 -days 3650 -out /etc/runbound/ca.crt \
  -subj "/CN=Internal CA"

# 2. Generate server key and CSR
openssl genrsa -out /etc/runbound/key.pem 4096
openssl req -new -key /etc/runbound/key.pem \
  -out /etc/runbound/server.csr \
  -subj "/CN=dns.corp.example.com"

# 3. Sign with your CA
openssl x509 -req -in /etc/runbound/server.csr \
  -CA /etc/runbound/ca.crt -CAkey /etc/runbound/ca.key \
  -CAcreateserial -out /etc/runbound/cert.pem \
  -days 825 -sha256

# 4. Distribute ca.crt to all clients
```

---

## Option D — Built-in ACME (automatic, zero-maintenance)

Runbound can provision and renew its own Let's Encrypt certificate with no external
tools. Port 80 must be publicly reachable and the domain must point to this server.

```
server:
    acme-email:  admin@example.com
    acme-domain: dns.example.com

    # Point TLS to the auto-managed files:
    tls-service-pem: /etc/runbound/acme/cert.pem
    tls-service-key: /etc/runbound/acme/key.pem
```

Runbound handles the full ACME HTTP-01 flow at startup and checks for renewal every
6 hours (renews when ≤ 30 days remain). After renewal, restart Runbound to load the
new certificate.

**Automatic restart on renewal** (systemd):

```ini
# /etc/systemd/system/runbound.service
[Service]
...
ExecStartPost=/bin/sh -c 'while inotifywait -e close_write /etc/runbound/acme/cert.pem 2>/dev/null; do systemctl reload-or-restart runbound; done &'
```

Or use a dedicated deploy hook:

```bash
# /etc/runbound/renew-hook.sh — called by Runbound after each renewal
#!/bin/sh
systemctl restart runbound
```

See [configuration.md](configuration.md#acme--lets-encrypt-automatic-tls) for the full
list of `acme-*` directives.

---

## Option E — WebUI / API (generate or import, no shell)

Since v0.20.0 you can enable DoT/DoH/DoQ entirely from the **WebUI** (*Settings -> Encrypted
DNS*) or the REST API — no OpenSSL, no file editing:

- **Generate a self-signed certificate:** `POST /api/tls/self-signed {"hostname":"dns.example.com"}`
  — writes `cert.pem` + `key.pem` (`0600`) in `base_dir` and sets the config.
- **Import an existing cert + key** (e.g. Lets Encrypt): `POST /api/tls/import {"cert_pem":"...","key_pem":"..."}`
  — the pair is validated (the key must match the leaf certificate) before being written.
- **Status / disable:** `GET /api/tls/cert` (CN, expiry, SHA-256 fingerprint, SANs) and `DELETE /api/tls`.

These mutations are **admin-only** and persist the `tls-service-*` directives. The DoT/DoH/DoQ
listeners are then **(re)bound live** — no process restart, and the plain UDP/TCP :53 path is
never interrupted (`restart_required: false`). See [api.md](api.md).

### Trusting the generated certificate (browsers / DoH)

A WebUI/API self-signed certificate is **signed by the Runbound Local CA**, not a bare
self-signed leaf — so a single CA import makes every certificate it issues (DoT, DoH, and the
WebUI itself) trusted, and the trust survives regeneration/renewal. Browsers refuse a DoH
resolver whose certificate does not chain to a trusted CA — and Firefox in *Max Protection*
mode has no fallback, so the network simply appears down. This import is therefore required
to use DoH from a browser:

1. **Download the CA** — *Settings → Encrypted DNS → Download CA cert…*, or
   `GET /api/tls/ca` (returns `runbound-ca.pem`, `Content-Type: application/x-pem-file`).
2. **Import it once** into the client trust store:
   - **Firefox:** Settings → Privacy & Security → Certificates → View Certificates →
     *Authorities* → Import → select `runbound-ca.pem` → tick *Trust this CA to identify websites*.
   - **Linux (system-wide):** `sudo cp runbound-ca.pem /usr/local/share/ca-certificates/runbound-ca.crt && sudo update-ca-certificates`
   - **macOS:** Keychain Access → *System* → import `runbound-ca.pem` → set *Always Trust*.
   - **Windows (admin):** `certutil -addstore -f Root runbound-ca.pem`
3. Point the client at `https://<hostname>/dns-query` (DoH) or `<hostname>:853` (DoT). The
   `<hostname>` must match a SAN on the certificate — i.e. the hostname you generated it with.

> A publicly-trusted certificate (e.g. Let's Encrypt) needs **no** client import: obtain it
> out-of-band and load it via *Import certificate…* / `POST /api/tls/import`, or use the
> built-in ACME flow (Option D) on an internet-reachable host. ACME cannot validate a host
> that is only reachable on a private LAN (HTTP-01 needs a public port 80).

## WebUI TLS — auto-generated certificate SANs

### Default SANs

When Runbound generates a WebUI TLS certificate automatically (the default when no
`ui-cert`/`ui-key` is configured), the certificate always includes the following
Subject Alternative Names:

- `localhost` (DNS)
- `127.0.0.1` (IP)
- `::1` (IP)

This means loopback access works without a browser warning out of the box.

### Adding custom IP or hostname SANs

To allow browser access by LAN IP (e.g., `https://192.168.1.10:8091`) without
a certificate warning, add the server's IP as a SAN:

```
server:
    ui-tls-san: 192.168.1.10
    ui-tls-san: myserver.local
```

The `ui-tls-san` directive may appear multiple times — each line adds one SAN.
IP addresses and hostnames are both accepted.

### Applying the change

The auto-generated certificate is cached on disk. After adding `ui-tls-san` directives,
delete the cached cert files and restart to regenerate with the new SANs:

```bash
sudo rm /etc/runbound/webui-cert.pem /etc/runbound/webui-key.pem
sudo systemctl restart runbound
```

After restart, reinstall the CA certificate in your browser (or trust the new cert) —
the cert fingerprint changes on regeneration.

---

## Verify DoT is working

```bash
# Using kdig (from knot-dnsutils)
kdig @127.0.0.1 +tls google.com

# Using openssl
openssl s_client -connect 127.0.0.1:853 -servername dns.example.com
```

---

## Client configuration

**Android 9+ (Private DNS):** Settings → Network → Private DNS → enter `dns.example.com`.

**systemd-resolved (`/etc/systemd/resolved.conf`):**
```ini
[Resolve]
DNS=192.168.1.5
DNSOverTLS=yes
```

**Unbound (as a client forwarding to Runbound):**
```
forward-zone:
    name: "."
    forward-addr: 192.168.1.5@853
    forward-tls-upstream: yes
```

**Pi-hole:** DNS settings → Custom upstream → `192.168.1.5#853`.

---

## Per-upstream SNI (forward-tls-hostname)

When using DoT upstreams (`forward-tls-upstream: yes`), Runbound uses the `forward-tls-hostname` directive to set a specific SNI for each upstream independently:

```
forward-zone:
    name: "."
    forward-addr: 1.1.1.1@853
    forward-tls-upstream: yes
    forward-tls-hostname: cloudflare-dns.com

forward-zone:
    name: "."
    forward-addr: 9.9.9.9@853
    forward-tls-upstream: yes
    forward-tls-hostname: dns.quad9.net
```

If omitted, Runbound derives the hostname from the IP using a built-in resolver list. See [configuration.md](configuration.md) for the full directive reference.
