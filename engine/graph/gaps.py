"""Logging gaps: windows inside an incident where a host that normally logs went silent.

A host's expected rate is its median events/hour over the dataset; a silence longer than
max(30 min, 20 expected inter-event intervals) inside [first step - 1 h, last step + 1 h] is a gap.
Edges between steps that straddle a gap on either host are marked inferred, never observed.
"""
from __future__ import annotations

import duckdb

HOUR = 3_600_000


def host_rates(con: duckdb.DuckDBPyConnection) -> dict[str, float]:
    rows = con.execute("""
        WITH h AS (SELECT host, ts // 3600000 AS hr, count(*) AS n FROM events
                   WHERE host IS NOT NULL AND ts IS NOT NULL GROUP BY 1, 2)
        SELECT host, median(n) FROM h GROUP BY host""").fetchall()
    return {h: float(m or 0) for h, m in rows}


def find_gaps(con: duckdb.DuckDBPyConnection, hosts: list[str], lo: int, hi: int, rates: dict[str, float]) -> list[dict]:
    out = []
    for h in hosts:
        rate = rates.get(h, 0.0)
        if rate < 2:                                  # host barely logs: silence is normal, not a gap
            continue
        min_gap = max(30 * 60_000, int(20 * HOUR / rate))
        rows = con.execute("""
            WITH t AS (SELECT ts, lag(ts) OVER (ORDER BY ts) AS prev FROM events
                       WHERE host = ? AND ts BETWEEN ? AND ?)
            SELECT prev, ts FROM t WHERE ts - prev >= ? ORDER BY prev""",
                           [h, lo - HOUR, hi + HOUR, min_gap]).fetchall()
        for a, b in rows:
            out.append({"host": h, "start_ts": a, "end_ts": b, "expected_events": round(rate * (b - a) / HOUR, 1)})
    return out


def crosses(gaps: list[dict], host_a: str | None, ts_a: int, host_b: str | None, ts_b: int) -> bool:
    lo, hi = min(ts_a, ts_b), max(ts_a, ts_b)
    for g in gaps:
        if g["host"] in (host_a, host_b) and g["start_ts"] < hi and g["end_ts"] > lo:
            return True
    return False
