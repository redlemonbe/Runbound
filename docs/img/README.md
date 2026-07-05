# Runbound dashboard — screenshots

Screenshots of Runbound's built-in web dashboard (v0.9), referenced from the top-level
[README](../../README.md#dashboard). One per tab of the UI.

| File | Tab | What it shows |
|------|-----|---------------|
| [dashboard-overview.png](dashboard-overview.png) | Overview | Live QPS, total queries, cache hit rate, blocked count, banned IPs, forwarded/SERVFAIL, uptime, latency (min/avg/max), DNSSEC (secure/bogus/insecure), XDP fast-path status, live QPS graph, top domains. |
| [dashboard-dns.png](dashboard-dns.png) | DNS | Add / search local records; per-zone tree view; record types A/AAAA/CNAME/MX/TXT/PTR/SRV. Changes apply live (no restart). |
| [dashboard-blacklist.png](dashboard-blacklist.png) | Blacklist | Block individual domains, choosing the block action (NXDOMAIN or REFUSED). |
| [dashboard-feeds.png](dashboard-feeds.png) | Feeds | Curated remote blocklist presets (StevenBlack, OISD, Hagezi, AdGuard DNS Filter, URLhaus…) plus active feeds with per-feed entry counts and refresh state. |
| [dashboard-subnets.png](dashboard-subnets.png) | Subnets | Split-horizon per-subnet answers, and per-subnet / per-VLAN filtering policies (additive to the global filter). |
| [dashboard-logs.png](dashboard-logs.png) | Logs | Query log (resolved / forwarded / cached / NXDOMAIN / SERVFAIL). |
| [dashboard-protection.png](dashboard-protection.png) | Protection | ICMP XDP responder config, banned source IPs, DDoS alerts, and abuse-detection alert rules (tarpit / block / notify), applied live. |
| [dashboard-users.png](dashboard-users.png) | Users | RBAC users and roles (read / dns / operator / admin) with per-user zone scoping. |
| [dashboard-system.png](dashboard-system.png) | System | Runtime (version, uptime, workers, prefetch), XDP fast path, hardware, sync / slaves, anycast, and full backup / restore. |
| [dashboard-settings.png](dashboard-settings.png) | Settings | DNSSEC validation toggle, resolution mode (Forward / **Sovereign**), downloadable local CA certificate, and encrypted DNS (DoT / DoH / DoQ). |
| [dashboard-account.png](dashboard-account.png) | Account | Change password, session policy (idle auto-logout, session duration), recent authentication events. |

_Captured on the v0.9 LXC deployment. To regenerate: open each tab of the web UI and take a full-page screenshot._
