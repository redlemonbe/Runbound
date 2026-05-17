#!/usr/bin/env python3
"""
Runbound → PostgreSQL collector (reference example)

Polls /stats every minute and /logs every 30 s, inserts into two tables.
Not production code — no retry logic, no connection pooling, no backoff.

Schema (run once):
    CREATE TABLE dns_stats (
        ts          TIMESTAMPTZ PRIMARY KEY,
        total       BIGINT, blocked   BIGINT, forwarded  BIGINT,
        nxdomain    BIGINT, servfail  BIGINT, local_hits BIGINT,
        qps_1m      FLOAT,  qps_peak  BIGINT,
        p50_ms      FLOAT,  p95_ms    FLOAT,  p99_ms     FLOAT,
        cache_hit   FLOAT,  blocked_pct FLOAT
    );
    CREATE TABLE dns_queries (
        ts          TIMESTAMPTZ, name TEXT, client INET,
        qtype       SMALLINT,    action TEXT, elapsed_ms INT
    );
    CREATE INDEX ON dns_queries (ts DESC);

Usage:
    pip install psycopg2-binary requests
    export RUNBOUND_API_KEY="your-key-here"
    export PGDATABASE=runbound  PGUSER=postgres  PGPASSWORD=...
    python3 postgres_collector.py
"""

import os, time, datetime, requests, psycopg2

RUNBOUND   = os.getenv("RUNBOUND_URL", "http://localhost:8081")
API_KEY    = os.environ["RUNBOUND_API_KEY"]
HEADERS    = {"Authorization": f"Bearer {API_KEY}"}
DSN        = os.getenv("DATABASE_URL", "")           # or rely on PG* env vars
STATS_INT  = 60   # seconds between /stats polls
LOGS_INT   = 30   # seconds between /logs polls

_last_log_ts = 0  # Unix timestamp of the most recent log entry inserted


def fetch(path: str) -> dict:
    r = requests.get(f"{RUNBOUND}{path}", headers=HEADERS, timeout=5)
    r.raise_for_status()
    return r.json()


def insert_stats(cur, s: dict) -> None:
    cur.execute("""
        INSERT INTO dns_stats VALUES (
            now(), %(total)s, %(blocked)s, %(forwarded)s,
            %(nxdomain)s, %(servfail)s, %(local_hits)s,
            %(qps_1m)s, %(qps_peak)s,
            %(latency_p50_ms)s, %(latency_p95_ms)s, %(latency_p99_ms)s,
            %(cache_hit_rate)s, %(blocked_percent)s
        ) ON CONFLICT DO NOTHING
    """, s)


def insert_logs(cur, entries: list) -> None:
    global _last_log_ts
    new_ts = _last_log_ts
    rows = []
    for e in entries:
        ts = datetime.datetime.fromisoformat(e["ts"].replace("Z", "+00:00"))
        unix = ts.timestamp()
        if unix <= _last_log_ts:
            continue
        rows.append((ts, e["name"], e.get("client"), e["qtype"],
                     e["action"], e["elapsed_ms"]))
        if unix > new_ts:
            new_ts = unix
    if rows:
        cur.executemany(
            "INSERT INTO dns_queries VALUES (%s,%s,%s,%s,%s,%s)", rows)
        _last_log_ts = new_ts


def main() -> None:
    conn = psycopg2.connect(DSN) if DSN else psycopg2.connect()
    conn.autocommit = True
    cur = conn.cursor()
    next_stats = 0.0
    while True:
        now = time.time()
        if now >= next_stats:
            insert_stats(cur, fetch("/stats"))
            next_stats = now + STATS_INT
        logs = fetch(f"/logs?limit=1000&since={int(_last_log_ts)}")
        insert_logs(cur, logs["entries"])
        time.sleep(LOGS_INT)


if __name__ == "__main__":
    main()
