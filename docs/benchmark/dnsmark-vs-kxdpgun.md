# dnsmark vs kxdpgun — two AF_XDP DNS generators, one server, measured at the NIC

Two open-loop AF_XDP DNS traffic generators — **kxdpgun** (CZ.NIC, shipped with Knot DNS)
and **dnsmark** (RunASM) — drive the same server over the same link, under the
[Runbound benchmark methodology](https://github.com/redlemonbe/Runbound/blob/main/docs/benchmark/README.md).
The point is not which floods faster (at 10 GbE both saturate the wire); it is what each
tool *reports*, and how far that is from what the receiver's NIC actually counted.

## Setup (identical for both, per methodology)

| | |
|---|---|
| Server | Runbound v0.9, `xdp: yes` (AF_XDP fast path), Intel X710 / i40e, single 10 GbE port, 64 combined RX queues (= cores; the i40e accepts up to 128 on this port), warm cache |
| Server host | AMD Threadripper PRO 5995WX (64c/128t), governor `performance`, other VMs stopped |
| Generator host | dual Intel Xeon E5-2690 v2 (20c/40t) |
| Link | direct DAC 10 GbE, flow-control off both ends, RSS `udp4 sdfn`, 10.71.10.2 → 10.71.10.1 |
| Workload | `top-10000-domains.txt`, 10 000 real names, random order, cache warmed (forward-zone `.` → 1.1.1.1 / 8.8.8.8 / 9.9.9.9), no local data |
| Truth | receiver NIC counters (`/sys/class/net/<nic>/statistics/{tx,rx}_packets`, `rx_missed_errors`), 1 s steady windows — not the generator's self-report |

## Results — at the receiver NIC

| Generator | Offered (gen egress) | Received (`rx`) | **Served (`tx`)** | NIC drops | Generator's own count |
|---|---|---|---|---|---|
| dnsmark `--xdp -Q 13M --max-outstanding 0` | 10.8–13.0 M/s | ~13.0 M/s | **10.14 M/s** | ~0 (rx_missed 4155 total) | egress PHY-confirmed |
| kxdpgun `-Q 20M` | 13.9 M/s | ~13.1 M/s | **10.14 M/s** | ~0 (rx_missed 3035 total) | **6.43 M replies = 37 % below served** |

Server CPU at ~10 M served: **6.5 % of 64 cores** (`/proc/stat`). The exact figure is
incidental — what holds across runs is that the server is nowhere near CPU-bound.
Latency is deliberately out of scope here: this note is about throughput and counters, and a
defensible p50/p95/p99 must be anchored to a tcpdump wire capture (methodology rule 7) — a
separate measurement, a separate document.

Two facts stand out:

1. **The server serves the same 10.14 M/s under either generator**, no NIC drops, at
   single-digit CPU. Replies are 1:1 with queries, UDP only (no TCP fallback),
   **average reply 57 B — single frame, no fragmentation**; so that ceiling is the
   **10 GbE response direction at small-DNS line rate**, not the server (~93 % of the machine
   idle). Both generators agree on it because both saturate the wire and the server answers
   all the link can carry.

2. **kxdpgun's self-reported replies — 6.43 M/s — fall 37 % below what the server actually
   served (10.14 M/s, receiver `tx` counter).** Whatever the cause — return-path loss, the
   generator's own receive accounting — the lesson holds: a generator's self-count is not the
   server's throughput. Trust the 6.43 M and you conclude the server does 6.4 M; the
   receiver's own NIC says 10.14 M.

## What the two tools are for

**kxdpgun — the stress weapon.** *"How many packets can I throw, how does the server hold
up?"* Open-loop, instantaneous, minimal output (sent, received, reply size, reply bitrate).
It reports what it sent and what it received back — right for finding a breaking point,
though as above its received count can sit below what a fast server actually served, and it
leaves its XDP program attached on exit (the operator detaches it afterward). A focused,
low-overhead instrument for capacity and resilience testing, and good at exactly that.

**dnsmark — the measured instrument.** *"What went on the wire, and can I trust the number?"*
AF_XDP datapath with a NIC-PHY egress check (it refuses to print a throughput the hardware
did not transmit) and a ramp to find saturation. It does not flood faster — at line rate the
two tie — it measures with less room to deceive. (When a NIC is left wedged by another tool,
dnsmark detects the gap between intended and PHY-transmitted packets and flags the figure as
fictional rather than print it.)

## The rule both demonstrate

A traffic generator measures *itself*: what it sent, and what it managed to receive back.
Neither is the server's throughput. To benchmark a DNS server you read **three** hardware
counters — generator egress, server ingress, server egress — and the server's egress is the
only one that says what it served. Here that is 10.14 M/s; one generator's self-report put it
at 6.43 M. Read the receiver.

## Reproduce

```bash
# Server (Runbound, xdp: yes), per methodology
ethtool -L <nic> combined 64                 # queues = cores; covers the NIC's NUMA node
ethtool -A <nic> rx off tx off
ethtool -N <nic> rx-flow-hash udp4 sdfn
cpupower frequency-set -g performance         # + IRQs one-per-core, ulimit -l unlimited
runbound -c receiver-bench.conf               # forward-zone cache; warm the 10k corpus first

# Truth = receiver NIC, 1 s windows:
cat /sys/class/net/<nic>/statistics/tx_packets   # served
cat /sys/class/net/<nic>/statistics/rx_packets   # received
ethtool -S <nic> | grep rx_missed_errors

# dnsmark — firehose
DNSMARK_SPORT_SPREAD=4096 dnsmark -s <ip> -p 53 -d top-10000-domains.txt --xdp -Q 13000000 --max-outstanding 0 -l 22

# kxdpgun — firehose (query file needs "name type" per line)
kxdpgun -t 15 -Q 20000000 -i queries-with-types.txt <ip>
ip link set <gen_nic> xdp off                # detach its program afterwards
```

## Which to use

- Stress / capacity / breaking point: **kxdpgun**.
- A served-throughput figure you can defend, egress confirmed at the PHY: **dnsmark** — and
  read the receiver NIC either way.
