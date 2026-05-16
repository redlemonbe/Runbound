# TLS Setup (DNS-over-TLS)

Runbound supports **DNS-over-TLS (DoT)** on port **853** when a certificate and
private key are provided. Clients that support DoT (Android 9+, systemd-resolved,
Unbound, Pi-hole, etc.) will encrypt all DNS traffic.

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
