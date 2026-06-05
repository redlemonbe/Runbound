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

### Using it with dnsmark

dnsmark expects a `name TYPE` corpus (dnsperf format, **TYPE uppercase**).
Build an A-record corpus from the name list:

```bash
awk '{print $0 " A"}' top-10000-domains.txt > corpus-a.txt
dnsmark -s 10.10.10.2 -d corpus-a.txt -c 16 -l 30
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
