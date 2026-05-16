# Home Lab DNS with Runbound

**Goal:** Replace your router's built-in DNS (or Pi-hole) with Runbound on a Raspberry Pi or
small home server. At the end you will have:

- Custom local hostnames: `nas.home`, `router.home`, `camera1.home` — no more memorising IPs
- Network-wide ad and tracker blocking via Runbound feeds
- Encrypted DNS to upstream (Cloudflare / Quad9 over DoT)
- A REST API to add entries live from any terminal without touching config files
- Zero downtime config reloads

---

## What you need

| Item | Example |
|---|---|
| A Linux box with a static LAN IP | Raspberry Pi 4, mini PC, NAS |
| A subnet you control | `192.168.1.0/24` |
| Root / sudo access | — |
| A DHCP server you can configure | Router admin page, pfSense, OPNsense |

The box running Runbound does **not** need to be your router. A Pi sitting on your LAN is fine.

---

## Step 1 — Give the host a static IP

Before anything else, make your Runbound host's IP permanent. Options:

**Option A — DHCP reservation (recommended):** log into your router, find the device's MAC address,
and assign it a fixed IP (e.g. `192.168.1.5`). The Pi still gets its IP from DHCP, but it's always
the same address.

**Option B — Static IP on the host** (Debian/Ubuntu example):

```bash
# /etc/network/interfaces or use nmtui / netplan depending on your distro
```

Either way, note the IP — you'll point your router's DNS at it.

---

## Step 2 — Install Runbound

```bash
# One-liner: downloads the latest release binary, sets up systemd, generates an API key
sudo bash <(curl -fsSL https://github.com/redlemonbe/Runbound/releases/latest/download/install.sh)
```

The installer will:
- Download the static binary for your architecture (x86_64 or aarch64)
- Create a `runbound` system user
- Write a default config to `/etc/runbound/runbound.conf`
- Generate a random API key in `/etc/runbound/env`
- Install and start the systemd service

After install, note your API key:

```bash
sudo cat /etc/runbound/env
# RUNBOUND_API_KEY=a3f8c2...
export RUNBOUND_API_KEY="a3f8c2..."
```

Verify it's running:

```bash
systemctl status runbound
dig @127.0.0.1 google.com       # should return an answer
```

---

## Step 3 — Configure your local zone

Edit `/etc/runbound/runbound.conf`. The key section is `local-zone` and `local-data`.

Replace the defaults with your actual subnet and hostnames:

```
server:
    interface:  0.0.0.0
    port:       53

    do-ip4:     yes
    do-ip6:     yes
    do-udp:     yes
    do-tcp:     yes

    # ── Access control ───────────────────────────────────────────────────────
    # Adapt to your subnet. Refuse everything from the internet.
    access-control: 127.0.0.0/8      allow
    access-control: 192.168.1.0/24   allow    # ← your LAN subnet
    access-control: 0.0.0.0/0        refuse

    # ── Rate limiting & TTL cap ──────────────────────────────────────────────
    rate-limit:    200
    cache-max-ttl: 3600

    # ── DNS rebinding protection ─────────────────────────────────────────────
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 127.0.0.0/8

    # ── Your local hostnames ─────────────────────────────────────────────────
    # Add one local-data line per device. Use a short domain like "home."
    local-zone: "home." static

    local-data: "router.home.   300 IN A 192.168.1.1"
    local-data: "pi.home.       300 IN A 192.168.1.5"    # ← this box
    local-data: "nas.home.      300 IN A 192.168.1.10"
    local-data: "printer.home.  300 IN A 192.168.1.20"
    local-data: "camera1.home.  300 IN A 192.168.1.30"

    # Reverse DNS (optional — useful for log readability)
    local-zone: "1.168.192.in-addr.arpa." static
    local-data: "10.1.168.192.in-addr.arpa. 300 IN PTR nas.home."

    logfile:    ""       # stdout → journald
    verbosity:  1

# ── Encrypted upstream DNS (Cloudflare + Quad9 over DoT) ─────────────────────
forward-zone:
    name:                 "."
    forward-addr:         1.1.1.1@853
    forward-addr:         9.9.9.9@853
    forward-tls-upstream: yes
```

Reload to apply:

```bash
sudo systemctl reload runbound
```

Test your local names resolve:

```bash
dig @127.0.0.1 nas.home.
# → 192.168.1.10
```

---

## Step 4 — Tell your router to use Runbound as DNS

Log into your router's admin interface and change the DHCP DNS server to the static IP of your
Runbound host (e.g. `192.168.1.5`). All clients on the LAN will start using Runbound within
the DHCP lease renewal period (usually a few minutes, or force renewal with `dhclient -r` /
reconnect Wi-Fi).

**Router-specific examples:**

| Router / Firmware | Where to change |
|---|---|
| Consumer router (generic) | DHCP settings → Primary DNS |
| pfSense | Services → DHCP Server → DNS servers |
| OPNsense | Services → DHCPv4 → DNS servers |
| Pi OS with dnsmasq | `/etc/dnsmasq.conf` → `server=192.168.1.5` |
| Synology Router | Network Center → Local Network → DNS |

> **Do not** set the router's own DNS to Runbound if Runbound is running *on* the router — that
> creates a loop. In that case, use `127.0.0.1` in the DHCP DNS field.

After clients pick up the new DNS, verify from a client machine:

```bash
# macOS / Linux
dig nas.home. @192.168.1.5
nslookup nas.home 192.168.1.5

# Windows (PowerShell)
Resolve-DnsName nas.home -Server 192.168.1.5
```

---

## Step 5 — Add network-wide ad blocking

Runbound can subscribe to remote blocklists and auto-refresh them. Start with a few
well-maintained ones:

```bash
API="http://localhost:8081"
TOKEN="$RUNBOUND_API_KEY"

# OISD — comprehensive tracker + ad block list
curl -s -X POST "$API/feeds" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"oisd","url":"https://big.oisd.nl/"}'

# URLhaus — active malware domains
curl -s -X POST "$API/feeds" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"urlhaus","url":"https://urlhaus.abuse.ch/downloads/hostfile/"}'

# Check subscribed feeds
curl -s "$API/feeds" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Or use the built-in presets:

```bash
curl -s "$API/feeds/presets" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Feeds auto-refresh every 24 hours. To force an immediate refresh:

```bash
curl -s -X POST "$API/feeds/update" -H "Authorization: Bearer $TOKEN"
```

---

## Step 6 — Day-2 operations

Once running, you manage Runbound entirely via the REST API — no config file edits needed for
routine changes.

### Add a new device without restarting

```bash
# A new IoT device joined the network
curl -s -X POST "$API/dns" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"thermostat.home.","type":"A","value":"192.168.1.42","ttl":300}'
```

### Block a domain manually

```bash
curl -s -X POST "$API/blacklist" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"doubleclick.net"}'
```

### Check query statistics

```bash
curl -s "$API/stats" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# → { "total": 48291, "blocked": 3847, "forwarded": 41203, "nxdomain": 3241 }
```

### Reload after editing the config file

Use this when you've edited `runbound.conf` to add new `local-data` entries:

```bash
sudo systemctl reload runbound
# Logs will confirm: INFO Hot-reload complete local_zones=4 local_data=18
```

What gets reloaded vs. what needs a restart → see [Systemd Setup](systemd.md#hot-reload).

---

## Troubleshooting

### LAN clients can't resolve local names

```bash
# Is Runbound running?
systemctl status runbound

# Can the Runbound host itself resolve the name?
dig @127.0.0.1 nas.home.

# Is the client using the right DNS?
# Linux:
cat /etc/resolv.conf
# macOS:
scutil --dns | grep nameserver
# Windows:
ipconfig /all | findstr "DNS Servers"

# Test cross-machine (from a client against the Runbound host)
dig @192.168.1.5 nas.home.
```

### Runbound starts but clients can't connect

Check the firewall on the Runbound host:

```bash
# Allow DNS from the LAN
sudo ufw allow from 192.168.1.0/24 to any port 53
# or with iptables:
sudo iptables -A INPUT -p udp --dport 53 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 53 -s 192.168.1.0/24 -j ACCEPT
```

### A specific domain is blocked unexpectedly

```bash
# Check if it's in the blacklist
curl -s "$API/blacklist" -H "Authorization: Bearer $TOKEN" | grep example.com

# Remove it
curl -s -X DELETE "$API/blacklist/example.com" -H "Authorization: Bearer $TOKEN"
```

### View live DNS queries

```bash
RUST_LOG=debug systemctl restart runbound
journalctl -u runbound -f | grep '"query"'
```

---

## What's next

| Guide | |
|---|---|
| [TLS Setup](tls.md) | Encrypt client-to-Runbound queries with DoT on port 853 |
| [Systemd Setup](systemd.md) | Hardened service file, logrotate, hot reload details |
| [REST API Reference](api.md) | All endpoints with examples |
| [Unbound Migration](unbound-migration.md) | Migrating from an existing Unbound config |
| [Security Architecture](security.md) | ACL, rate limiting, DNS rebinding protection |
