# Anycast deployment

Run the **same service IP from multiple Runbound nodes** and let the network route each
client to the nearest healthy one — the model every large public resolver (1.1.1.1, 8.8.8.8,
the root servers) uses. DNS is the ideal anycast workload: a query is one request / one
response with **no session state**, so it does not matter if consecutive queries from a
client land on different nodes.

> **Bottom line:** anycast needs **no Runbound code changes** and is **safe for both the
> XDP fast path and the kernel slow path**. It is a network + config exercise. The one rule
> is **bind the explicit anycast IP, never `0.0.0.0`** (see §3). Everything below was
> validated on the bench — see §6. Related: [issue #199](https://github.com/redlemonbe/Runbound/issues/199).

## 1. Two planes — keep them separate

| Plane | What | How |
|---|---|---|
| **Control** | keep every node serving the *same data* | the existing master → slave relay (zones, feeds, blacklists) + health via `/api/events` (SSE `node_status`) and `/api/system` |
| **Data** | distribute client traffic | the **anycast VIP** announced from every node; the network (BGP / ECMP) load-balances |

At the data plane there is **no master/slave distinction** — every node serves the VIP as an
equal. The master/slave hierarchy is purely the control plane. This separation is the whole
point: the relay keeps the anycast fleet consistent, anycast spreads the load.

## 2. Why no datapath code is needed

- **Fast path (`xdp: yes`)** — the eBPF program filters on **UDP dport 53** and **reflects**
  the packet (swaps src/dst IP + MAC, `ebpf/dns_xdp.c`). The answer is sourced from the
  *destination IP of the incoming query* and egresses the same NIC. It does not depend on a
  bound local IP — the VIP "just works", and cache misses are forwarded by the worker and
  replied via the same reflecting XSK TX (still sourced from the VIP).
- **Slow path (`xdp: no`)** — a kernel UDP socket bound to the VIP sources its replies from
  the VIP. Standard, exactly like unbound / BIND do anycast.

## 3. Per-node configuration

### Runbound

Bind the **explicit anycast IP** — this is the only rule that matters:

```
server:
  interface: 198.51.100.53     # the anycast VIP — NOT 0.0.0.0
  # ... your normal config ...
  # xdp: yes + xdp-interface: <phys-nic>   for the fast path (optional)
```

> **Do not bind `0.0.0.0`.** On the slow path a wildcard socket may answer from the node's
> *unicast* address instead of the VIP; the client then sees a source ≠ the address it
> queried and **drops the reply**. Binding the VIP explicitly fixes it (verified, §6).

### Host (each node)

```bash
# the VIP on a dummy interface (or lo), as a /32
ip link add dummy0 type dummy && ip link set dummy0 up
ip addr add 198.51.100.53/32 dev dummy0

# loose reverse-path filtering: the query arrives on a physical NIC while the VIP lives on
# dummy0 — an asymmetric path that strict rp_filter would drop.
sysctl -w net.ipv4.conf.all.rp_filter=2
```

## 4. The announcer (this is what "does" anycast)

Each node runs a routing daemon that **announces `198.51.100.53/32` only while Runbound is
healthy**, and **withdraws** it the moment the node is unhealthy so traffic drains to the
others. The classic tool for service anycast is **exabgp** (announce/withdraw driven by a
health command); **bird** / **FRR** work too.

A health check that tests the *real* datapath rather than just a process liveness:

```bash
# healthy if Runbound actually answers DNS on the VIP
dig +short +time=1 +tries=1 @198.51.100.53 health.check. CH TXT >/dev/null && echo "up" || echo "down"
# (or poll the API: curl -fsS -H "Authorization: Bearer $KEY" http://127.0.0.1:8080/api/system)
```

exabgp announces the `/32` while that check passes and withdraws it when it fails. Inside a
datacenter you can equally use ECMP: the upstream router holds an equal-cost route to the VIP
via every node and hashes flows across them (enable L4 hashing:
`net.ipv4.fib_multipath_hash_policy=1`).

## 5. Health-driven withdrawal is mandatory

A dead node that is **still announced** is worse than no anycast: roughly *1/N* of all queries
black-hole into it until its route is pulled. The announcer's health check is therefore not
optional — it is the mechanism that makes anycast resilient (§6, step C). Runbound already
exposes the health signal the announcer needs (`/api/events` `node_status`, `/api/system`),
and on a fleet the master aggregates it.

## 6. Bench validation (2026-06-13)

All three were measured, not assumed.

- **A — source-IP correctness.** One node, VIP on `dummy0`, queried from a remote client.
  tcpdump confirmed **every reply sourced from the VIP** on all paths — UDP cache-hit, UDP
  cache-miss (forwarded), and TCP — in `xdp: no`; and under load in `xdp: yes`, a
  source-validating client (dnsperf) completed **99.96 %** including forwarded misses
  (NXDOMAIN / SERVFAIL). **Zero** replies leaked from the node's unicast address.
- **B — ECMP distribution.** Two nodes serving the same VIP, an ECMP client with L4 hashing.
  50 queries split **29 / 21** across the two nodes — same VIP, both answer, client accepts.
- **C — withdrawal.** With one node killed but **still in the ECMP route**, ~**half the
  queries failed** (21/40 timed out). After withdrawing the dead next-hop (what the
  health-checked announcer does automatically), **0 failures** — all traffic drained to the
  healthy node.

## 7. Notes

- **Not a bond.** Link bonding stays unsupported for AF_XDP (a bond master has no zero-copy
  XSK). "One IP, many links/nodes" is anycast / ECMP at L3, not L2 bonding.
- The fast path's AF_XDP workers pick up traffic best **under load**; a single probe packet at
  near-zero rate may not be drained promptly (an AF_XDP characteristic, not an anycast issue) —
  use the API or a TCP probe for health if you want a guaranteed low-rate response.
- Per-node throughput is unchanged by anycast — see [docs/benchmark/INDEX.md](benchmark/INDEX.md);
  anycast multiplies it across nodes.
