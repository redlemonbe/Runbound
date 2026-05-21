# Web Management Console

Runbound ships a single-file HTML/JS dashboard (`examples/web-ui/index.html`) that
lets you manage DNS entries, the blacklist, feeds, and live logs from any browser —
no build step, no framework, no dependencies beyond a CDN-hosted Tailwind CSS.

---

## Features

| Tab | What you can do |
|---|---|
| **Overview** | Real-time stats: QPS, total queries, cache hit rate, blocked, forwarded, SERVFAIL, avg latency, uptime |
| **DNS Entries** | Add / delete local A, AAAA, CNAME, TXT, MX records |
| **Blacklist** | Add / delete blocked domains (nxdomain or refuse action) |
| **Feeds** | Add / delete blocklist feed URLs with live entry count |
| **Logs** | Tail the query ring buffer with 3-second auto-refresh |

The header bar also shows a live QPS / query count / uptime and a **↺ Reload** button
that sends `POST /reload` to apply config changes without restarting the service.

---

## Serving the dashboard

The Runbound API only listens on `127.0.0.1` (localhost). To reach it from a browser
on another machine you need a small reverse proxy in front — nginx is the recommended
option because it also serves the static file on the same origin (no CORS issues).

### 1. Install nginx

```bash
sudo apt-get install -y nginx
```

### 2. Create the site config

```bash
sudo mkdir -p /var/www/runbound-ui
sudo cp examples/web-ui/index.html /var/www/runbound-ui/index.html
```

Create `/etc/nginx/sites-available/runbound-ui`:

```nginx
server {
    listen 8090;
    server_name _;

    root /var/www/runbound-ui;
    index index.html;

    # Static dashboard
    location / {
        try_files $uri $uri/ =404;
    }

    # Proxy to Runbound API — keeps the API off the LAN
    location /api/ {
        proxy_pass            http://127.0.0.1:8080/;
        proxy_http_version    1.0;
        proxy_set_header      Host $host;
        proxy_set_header      X-Real-IP $remote_addr;
        proxy_set_header      Content-Length "";
        proxy_read_timeout    30s;
    }
}
```

Enable it:

```bash
sudo ln -sf /etc/nginx/sites-available/runbound-ui /etc/nginx/sites-enabled/runbound-ui
sudo nginx -t && sudo systemctl enable --now nginx
```

### 3. Allow the port through the firewall

```bash
# UFW — allow LAN access only
sudo ufw allow from 192.168.0.0/16 to any port 8090 proto tcp comment "Runbound web UI"
```

Adjust the subnet to match your network. **Do not expose port 8090 to the internet** —
the dashboard forwards your API Bearer token with every request.

---

## First connection

Open `http://<server-ip>:8090` in your browser.

- **API URL** is pre-filled to `/api` (the nginx proxy path) — leave it as-is.
- **API key** — find it in `/etc/runbound/environment`:

  ```bash
  sudo grep RUNBOUND_API_KEY /etc/runbound/environment
  ```

Enter the key and click **Connect**. The key is saved in `localStorage` and restored
automatically on every subsequent visit.

> **Tip:** On a private LAN server you can hardcode the key directly in the HTML so
> the dashboard connects automatically on page load:
>
> ```bash
> sudo sed -i 's|placeholder="API key (Bearer token)"|value="YOUR_KEY_HERE" placeholder="API key (Bearer token)"|' \
>   /var/www/runbound-ui/index.html
> ```

---

## API URL reference

The dashboard uses **relative paths** (`/api`) by default, which routes through the
nginx proxy. If you point `cfg-url` directly at the Runbound API (e.g. for local
testing on the same machine), use `http://localhost:8080` instead.

| Setting | When to use |
|---|---|
| `/api` | nginx proxy — access from any LAN browser (default) |
| `http://localhost:8080` | Direct — only works in a browser on the DNS server itself |

---

## Security notes

- The nginx proxy keeps port 8080 off the network — Runbound's API remains
  localhost-only.
- The Bearer token travels over plain HTTP inside your LAN. Use a VPN or
  restrict the firewall rule to a management VLAN if you want stricter isolation.
- For HTTPS, see [tls.md](tls.md) — you can terminate TLS in nginx and proxy
  to the Runbound API backend.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `411 Length Required` | `Content-Type: application/json` sent on a GET request | Update to the latest `index.html` from the repo (fixed in v0.5.7+) |
| `Connection failed` | Wrong API URL or Bearer token | Check `/etc/runbound/environment` for the key |
| Stats show `—` but no error | Auto-refresh polling before connect completes | Click **Connect** manually |
| nginx `address already in use` on port 80 | Another service owns port 80 | Use a different listen port (8090 is the recommended default) |
