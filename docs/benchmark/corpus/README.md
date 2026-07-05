# Benchmark corpus

Reusable real-world query name lists for benchmarking Runbound (and the
companion generator [dnsmark](https://github.com/redlemonbe/dnsmark)).

## `top-10000-domains.txt`

The 10 000 most popular domains, one per line, ordered by popularity rank
(`google.com` first, long tail after). Real names → realistic qname
diversity, cache-key spread and label-length distribution.

- **Source:** [Tranco list](https://tranco-list.eu/) (`top-1m.csv`), top 10 000 by rank.
- **Generated:** `curl -sL https://tranco-list.eu/top-1m.csv.zip | bsdtar -xOf - | head -10000 | cut -d, -f2`
- **Quality:** 10 000 lines, no duplicates, no malformed entries, 341 distinct TLDs.

## `top-100000-resolving.txt`

100 000 domains that **all resolve to an A record** — the clean corpus for
forward+cache throughput benches. A raw popularity list carries a few percent of
NXDOMAIN/dead names in its long tail; under a warmed-cache flood those never
cache, fall to the slow path mid-run, stall the XDP worker per miss, overflow the
RX ring and cap the served rate (measured: a raw 100k corpus gave ~7.3 M served
with ~3–9 % `rx_missed` drops, vs ~9.7 M and far fewer drops on a fully
resolvable set). Every name here is cacheable, so a warmed run serves 100 % cache
hits and a clean measurement can saturate the link.

- **Source:** [Tranco list](https://tranco-list.eu/) `top-1m`, first 150 000 by
  rank, resolved for `A` with [massdns](https://github.com/blechschmidt/massdns)
  against a **local recursive `unbound`** (full recursion straight to the
  authoritative servers — no public-resolver rate-limiting, which otherwise
  silently caps the success rate). Kept the names that returned an A record, in
  popularity order, truncated to the first 100 000. Tranco apex names resolve at
  ~80 % (raw Cisco Umbrella `top-1m`, by contrast, is ~39 % A-resolving — its long
  tail is mostly CDN/tracking hostnames and NXDOMAIN, so it was rejected as a
  source here).
- **Use for:** XDP throughput benches — warm the cache (rate-limited, not a
  flood), then flood; every name is a cache hit.
- **Built:** 2026-06-20.

### Using it with dnsmark

dnsmark expects a `name TYPE` corpus (dnsperf format, **TYPE uppercase**).
Build an A-record corpus from the name list:

```bash
awk '{print $0 " A"}' top-10000-domains.txt > corpus-a.txt
dnsmark -s 10.0.0.3 -d corpus-a.txt -c 16 -l 30
```

For an all-types corpus, append the desired type per line
(`A`, `AAAA`, `MX`, `TXT`, `NS`, `SOA`, `SRV`, `CAA`, ...).

### Exercising the XDP wire fast path

The XDP fast path only serves names present in the local zone. To make every
A/AAAA query hit the wire path (instead of falling to recursion), load the same
names as `local-data` with synthetic addresses:

```bash
awk '{print "local-data: \"" $0 " A 203.0.113.1\""}' top-10000-domains.txt > bench-zone.conf
```

The answer content is irrelevant for a wire-path benchmark — what matters is that
10 000 distinct qnames stress the LocalZoneSet lookup under realistic diversity.
