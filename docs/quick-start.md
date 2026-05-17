# Quick Start

Up and running in 5 minutes.

---

## 1. Download

Grab the static binary for your platform from the [latest release](https://github.com/redlemonbe/Runbound/releases/latest).
No dependencies required for the `musl` builds.

| Platform | File |
|---|---|
| Linux x86_64 (most servers, VMs) | `runbound-vX.Y.Z-x86_64-linux-musl` |
| Linux ARM64 (Raspberry Pi, ARM servers) | `runbound-vX.Y.Z-aarch64-linux-musl` |

```bash
# Replace vX.Y.Z with the latest tag from https://github.com/redlemonbe/Runbound/releases
curl -LO https://github.com/redlemonbe/Runbound/releases/latest/download/runbound-v0.2.5-x86_64-linux-musl
chmod +x runbound-v0.2.5-x86_64-linux-musl
sudo mv runbound-v0.2.5-x86_64-linux-musl /usr/local/bin/runbound
```

---

## 2. Configure

**Option A — reuse your existing Unbound config:**

```bash
sudo mkdir -p /etc/runbound
sudo cp /etc/unbound/unbound.conf /etc/runbound/runbound.conf
```

Runbound reads the same `server:`, `forward-zone:`, `local-zone:`, and `local-data:` directives.
See [unbound-migration.md](unbound-migration.md) for the compatibility table.

**Option B — start from an example:**

```bash
sudo mkdir -p /etc/runbound
# Pick the config closest to your use case:
sudo cp /path/to/Runbound/examples/home.conf    /etc/runbound/runbound.conf  # Pi-hole replacement
sudo cp /path/to/Runbound/examples/office.conf  /etc/runbound/runbound.conf  # SMB office
sudo cp /path/to/Runbound/examples/server.conf  /etc/runbound/runbound.conf  # Public resolver
sudo cp /path/to/Runbound/examples/secure.conf  /etc/runbound/runbound.conf  # Air-gapped
```

**Set your API key:**

```bash
export RUNBOUND_API_KEY="$(openssl rand -hex 32)"
echo "RUNBOUND_API_KEY=$RUNBOUND_API_KEY" | sudo tee /etc/runbound/env
```

---

## 3. Run

```bash
# Foreground (test first):
sudo RUNBOUND_API_KEY="your-key" runbound --config /etc/runbound/runbound.conf

# Verify DNS is working:
dig @127.0.0.1 google.com

# Verify the API is reachable:
curl -s http://localhost:8081/health -H "Authorization: Bearer $RUNBOUND_API_KEY"
# → {"status":"ok","uptime_secs":3,"queries":0}
```

---

## 4. Install as a service (production)

See [systemd.md](systemd.md) for the full hardened unit file.

Quick version:

```bash
sudo useradd -r -s /sbin/nologin runbound
sudo runbound --config /etc/runbound/runbound.conf --install-service
sudo systemctl enable --now runbound
```

---

## 5. First API calls

```bash
API="http://localhost:8081"
TOKEN="your-key"

# Add a local DNS entry
curl -s -X POST "$API/dns" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"myserver.home.","type":"A","value":"192.168.1.50","ttl":300}'

# Check it resolves
dig @127.0.0.1 myserver.home.

# View stats
curl -s "$API/stats" -H "Authorization: Bearer $TOKEN"
```

That's all. For the full API reference see [api.md](api.md).
