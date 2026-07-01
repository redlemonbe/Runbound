# Web Management Console

Runbound embeds a single-file HTML/JS dashboard served directly over HTTPS — no nginx,
no external CDN, no build step. The UI is compiled into the binary at build time
(`src/webui/index.html`).

---

## Enable the UI

Add these lines inside the `server:` section of your `runbound.conf`:

```
server:
    ui-enabled: yes
    ui-port:    8091
    # ui-bind:  127.0.0.1   # default — loopback only
    # ui-bind:  0.0.0.0     # expose the dashboard on the LAN (explicit opt-in)
```

The dashboard binds **`127.0.0.1` by default** — reachable only from the host
itself. To reach it from other machines on your network, set `ui-bind: 0.0.0.0`
(or a specific interface IP) explicitly.

Restart the service:

```bash
sudo systemctl restart runbound
```

The dashboard is then available at `https://127.0.0.1:8091` (default loopback
bind), or at `https://<server-ip>:8091` once you set `ui-bind: 0.0.0.0`.

---

## Certificate trust (one-time setup)

On first access your browser will warn about the self-signed certificate.
Runbound generates its own CA at startup — install it once and all devices on
your network get a trusted connection.

Download the CA at:

```
https://<server-ip>:8091/webui/ca.crt
```

| OS | Steps |
|---|---|
| **macOS** | Double-click the file → Keychain Access → right-click → Get Info → Trust → Always Trust |
| **Windows** | Double-click → Install Certificate → Local Machine → Trusted Root Certification Authorities |
| **Linux** | `sudo cp runbound-ca.pem /usr/local/share/ca-certificates/runbound.crt && sudo update-ca-certificates` |
| **Firefox** | Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import |
| **iOS** | Open the file → Settings → General → VPN & Device Management → Install → then Certificate Trust Settings → Enable |
| **Android** | Settings → Security → Install from storage → CA Certificate |

The CA certificate is also downloadable from the Settings tab inside the UI after login.

---

## Login

Open `https://<server-ip>:8091` and enter your credentials.

Default username is `admin`. The password is set during install or changed via
Account → Change Password. Sessions have a flat 8-hour expiry from login — there is
no idle-based auto-logout (activity does not extend or reset the session timer).

If the WebUI is still on the default `admin`/`admin` credentials, the dashboard
shows a one-time prompt on connect to change them (it disappears once changed).

Passwords are hashed with **argon2id** (m=19456, t=2, p=1).

---

## Features

| Tab | What you can do |
|---|---|
| **Overview** | Real-time stats: QPS, cache hit rate, blocked, SERVFAIL, latency **min / average / max**; live 60-second QPS sparkline; top-10 queried domains  Includes a **Banned IPs** count tile. |
| **DNS** | Add / delete local A, AAAA, CNAME, TXT, MX, PTR, SRV records; DNS Lookup panel with cache hit indicator |
| **Blacklist** | Add / delete blocked domains (`nxdomain` or `refuse` action) |
| **Feeds** | Add / delete blocklist feed URLs (hosts or adblock format); preset list; entry count; error text on refresh failure |
| **Upstreams** | Add / delete resolvers; 14 built-in presets (Cloudflare, Google, Quad9, OpenDNS — plain + DoT variants); health dots, DNSSEC badge, latency sparkline, DoT SNI config; **↺ Reconnect DoT** button |
| **Subnets** | **Split-Horizon**: per-subnet answer sets (add / delete, applied on next restart). **Subnet Policies** (#8): per-subnet/VLAN filtering — extra blacklist domains scoped to a subnet, additive to the global blacklist, **applied live, no restart** |
| **Logs** | Query ring buffer with 3-second auto-refresh; **admin & config audit** (who did what — actor, action, result); **WebUI auth activity**; a **functional search** filtering the query log and the admin/config audit (the WebUI auth activity list is not filtered by this search). |
| **Protection** | ICMP XDP flood protection (enable/disable per node; rate / burst / ban-threshold; per-node stats cards); **Banned source IPs** table (IP, source, age) with per-row **Blacklist** (make permanent) and **Unban** buttons; DDoS alerts log. Bans are enforced on both the XDP fast path and the kernel slow path. |
| **System** | Runtime info (version, XDP mode, memory, CPU); slave list with sync status and version; full backup download / restore; cache flush button |
| **Settings** | DNSSEC validation toggle; **Resolution mode** (forward to full-recursion, #202); **Encrypted DNS** panel: enable DoT/DoH/DoQ with a self-signed **or** imported certificate — **applied live, no restart** (cert CN/expiry/fingerprint shown); CA certificate download |
| **Users** | Multi-user administration: create / list / delete users, per-user API key rotation. Disabled by default — enable by creating `users.json` in the data directory and restarting. |
| **Account** | Per-user settings: change password, session info (fixed 8-hour session duration, no idle timeout enforced; logout now), recent auth event log |
| **About** | Version badge, uptime, feature list, GitHub links, credits; plus a custom organisation / blurb / support-link card when white-label branding is enabled |

The header bar shows: connection dot (blink green = connected, red = error), live
QPS / query count / uptime, node pills for multi-node selection, **↺ Reload** button
(`POST /api/reload` — applies config changes without restart), and **⏏ Logout**.

---

## Branding (white-label)

Set `branding: yes` in the main config and place a `branding.conf` next to it to
re-brand the console: product name, logo, accent colour, favicon, and an About
card (organisation, blurb, support link). Hex colours work (quote them), and
branding is **Web UI-only** — it never touches the REST API. The older
`ui-brand-*` main-config directives remain as a fallback.

Full reference and key table: **[branding.md](branding.md)**. Ready-to-edit
example: [`examples/branding.conf`](../examples/branding.conf).

---

## Multi-node

When slaves are registered via the relay, node pills appear in the header. Click a
node to scope Overview stats to that node, or keep **all** selected for cluster-wide
aggregation. Cluster rates (cache hit, blocked %) and latency are **weighted by each
node's resolution volume** — idle nodes are excluded, so a node serving 50 queries
weighs ten times one serving 5 (never a flat average of the nodes).

---

## Security notes

- All browser ↔ Runbound traffic is HTTPS (TLS 1.2+, rustls, auto-generated cert).
- Sessions use HTTP-only cookies with CSRF tokens on all mutating requests.
- The API port (8080) remains localhost-only — the UI server proxies `/api/*` internally.
- Flat 8-hour session limit; there is no idle-based auto-logout.
- All login attempts are logged (Account → Recent Auth Events).

---

## Bot Defense

Runbound's built-in bot defense system automatically protects the WebUI login and admin surface.
No external WAF or reverse proxy is needed.

### Detection layers

**Honeypot** (opt-in via `bot-honeypot-enabled: yes`): The login form contains hidden fields
that legitimate browsers leave empty. Any client that fills them in is immediately banned.
This catches most credential-stuffing bots on first contact.

**Scanner trap paths**: Requests to well-known vulnerability scanner paths
(`/wp-admin`, `/.env`, `/.git/config`, `/.git/*`, `/phpmyadmin`, `/xmlrpc.php`, etc.)
trigger an immediate ban. There is no legitimate reason for a DNS server UI to receive
these requests.

**Behavioral burst**: Any IP that produces 10 or more failed requests within a 5-second window
is automatically banned (rule: `bot-burst`). This catches brute-force tools that retry quickly.

### Viewing bot bans

Bot bans appear alongside regular alert blocks in the **Protection** tab of the WebUI. They
are also returned by `GET /api/alerts` under `blocked_clients`, with `rule` values of
`bot-honeypot`, `bot-scanner`, or `bot-burst`.

### Configuration directives

| Directive | Default | Description |
|---|---|---|
| `bot-ban-duration-secs` | `86400` | Duration of a bot ban in seconds. `0` = permanent. |
| `bot-honeypot-enabled` | `no` | Enable the hidden honeypot field in the login form. |

```
server:
    bot-ban-duration-secs: 86400
    bot-honeypot-enabled:  yes
```



> **Note:** Loopback addresses (`127.x`, `::1`), RFC-1918 private addresses, link-local, and ULA (`fc00::/7`) are **never** banned by the bot defense engine, even if they trigger a detection rule. This prevents the server from banning itself when internal tooling or health checks hit scanner trap paths.

### Enforcement

Bans are enforced via the same pipeline as alert blocks: XDP BPF map injection (IPv4) or
userspace block (IPv6). The **Protection** tab also has a live **Alert rules** editor (add/remove rules, action `log`/`tarpit`/`block`/`notify`, `Load recommended` for a sane base set; saved via `PUT /api/alerts/rules`, applied without restart). They persist across restarts in `alert-blocks.json` and are
automatically purged by a background task when they expire.

---

## Security audit document

The consolidated security audit (all cycles) is available without internet access at:

```
https://<host>:<ui-port>/webui/security-audit
```

This page is served directly by Runbound from the embedded binary (no CDN). Note: the
**About** tab → Links card currently links to the GitHub copy of the audit doc (requires
internet access), not to this local `/webui/security-audit` route.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Browser certificate warning | Install the CA at `https://<ip>:8091/webui/ca.crt` |
| `Connection refused` on port 8091 | Verify `ui-enabled: yes` in config; `sudo systemctl status runbound` |
| Stats show `—` after login | Session may have expired — reload the page |
| Login fails | Check credentials; change password via `POST /api/webui/password` |
| Port conflict | Change `ui-port` in `runbound.conf` to any free port |
