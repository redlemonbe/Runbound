# GDPR

## Responsibilities

Runbound is software. Its author is a **data processor vendor** under the GDPR —
it does not process any personal data belonging to your users.

The **operator** who deploys Runbound is the data controller.
It is the operator's responsibility to define the legal basis, retention periods,
and procedures for handling data subject requests.

## Data processed by Runbound

| Data | Where | Duration | Configurable |
|------|-------|----------|--------------|
| Source IP of DNS queries | In-memory ring buffer (`/logs`) | Until restart or rotation | `log-retention`, `log-client-ip` |
| Queried domain names | In-memory ring buffer (`/logs`) | Until restart or rotation | `log-retention` |
| Source IP of API calls | Audit log | Until manual rotation | `audit-log-path` |
| Master API key (plain text) | Memory only | Duration of the process | — |
| Per-user API keys (plain text, multi-user mode) | `users.json` on disk (file must be `0600`) | Until the user account is deleted | `DELETE /api/users/:id` |

Runbound **does not persist** DNS data to disk by default.
The `logfile:` directive is disabled by default.

## Compliance recommendations

**Data minimisation:** disable `/logs` if not needed:

```
log-retention: 0
```

**Pseudonymisation:** mask client IPs:

```
log-client-ip: no
```

> Both directives require a **restart** to take effect
> (SIGHUP only reloads DNS zones, not the ring buffer).

**Right to erasure:** flush the ring buffer on demand:

```
curl -X DELETE http://localhost:8080/api/logs -H "Authorization: Bearer $KEY"
```

**Disk logfile:** if you enable `logfile:`, set up rotation with `logrotate`
and define an explicit retention period.

## Transfers outside the EU

Blocklist feeds (Hagezi, etc.) are downloaded from international CDNs.
No personal data is transmitted during these downloads — only a plain HTTP GET
request with no payload is issued.
