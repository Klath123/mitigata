"""Data quality and processing observability.

The reconstructed attack can only be as good as the logs. This module measures, per dataset, per file
and per host, how much of the input was usable, and turns that into plain warnings, including
per-incident warnings that explain why an attack path may be incomplete.

Nothing is silently dropped: malformed lines are kept (generic fallback), records without a usable
timestamp stay in `events_all` and are only excluded from detection, which runs on `events`.
"""
from __future__ import annotations

import json
import os

import duckdb

from .store.db import DUP_KEY, TS_MIN

LATE_TOLERANCE_MS = 5 * 60_000
UNKNOWN_TYPES = ("generic", "jsonl", "json_stream", "csv", "tsv", "kv", "xml_events", "syslog", "cef", "leef")
USER_EXPECTED = ("win:4624", "win:4625", "win:4688", "win:4672", "sysmon:1", "auth:success", "auth:fail",
                 "auth:sudo", "audit:execve")
PROC_EXPECTED = ("win:4688", "sysmon:1", "sysmon:3", "sysmon:10", "sysmon:11", "audit:execve")
DUP_KEY_CROSS = ("hash(ts, host, event_type, \"user\", process, cmdline, target, src_ip, dst_ip, dst_port, bytes_out, "
                 "logon_id)")


def _pct(n, d) -> float:
    return round(100.0 * n / d, 3) if d else 0.0


def compute(con: duckdb.DuckDBPyConnection, ingest_report: dict) -> dict:
    ts_ok = f"ts BETWEEN {TS_MIN} AND epoch_ms(now()::TIMESTAMP) + {2 * 86_400_000}"
    unknown = "event_type IN (" + ",".join(f"'{t}'" for t in UNKNOWN_TYPES) + ")"
    ue = "event_type IN (" + ",".join(f"'{t}'" for t in USER_EXPECTED) + ")"
    pe = "event_type IN (" + ",".join(f"'{t}'" for t in PROC_EXPECTED) + ")"
    row = con.execute(f"""
        SELECT count(*) AS records,
               count(*) FILTER (WHERE ts IS NULL) AS ts_missing,
               count(*) FILTER (WHERE ts IS NOT NULL AND NOT ({ts_ok})) AS ts_invalid,
               count(*) FILTER (WHERE host IS NULL) AS host_missing,
               count(*) FILTER (WHERE ts_assumed) AS ts_assumed,
               count(*) FILTER (WHERE event_type IS NULL) AS type_missing,
               count(*) FILTER (WHERE {unknown}) AS unknown_type,
               count(*) FILTER (WHERE {ue}) AS user_expected,
               count(*) FILTER (WHERE {ue} AND "user" IS NULL) AS user_missing,
               count(*) FILTER (WHERE event_type = 'win:4624' AND logon_type IN (3, 10)) AS remote_logons,
               count(*) FILTER (WHERE event_type = 'win:4624' AND logon_type IN (3, 10) AND src_ip IS NULL
                                AND src_host IS NULL) AS remote_logon_no_source,
               count(*) FILTER (WHERE {pe}) AS proc_expected,
               count(*) FILTER (WHERE {pe} AND process IS NULL) AS process_missing,
               count(DISTINCT host) AS hosts, min(ts) FILTER (WHERE {ts_ok}) AS first_ts,
               max(ts) FILTER (WHERE {ts_ok}) AS last_ts
        FROM events_all""").fetchone()
    cols = ["records", "ts_missing", "ts_invalid", "host_missing", "ts_assumed", "type_missing", "unknown_type", "user_expected",
            "user_missing", "remote_logons", "remote_logon_no_source", "proc_expected", "process_missing", "hosts",
            "first_ts", "last_ts"]
    t = dict(zip(cols, row))
    recs = t["records"] or 0

    # duplicates: identical records (same file) and the same event delivered by two sources/files
    dup_same = recs - (con.execute(f"SELECT count(DISTINCT {DUP_KEY}) FROM events_all").fetchone()[0] or 0)
    dup_any = recs - (con.execute(f"SELECT count(DISTINCT {DUP_KEY_CROSS}) FROM events_all").fetchone()[0] or 0)

    # late arrivals: a record older than something already seen earlier in the same file
    late_rows = con.execute(f"""
        WITH o AS (SELECT src_file, ts, max(ts) OVER (PARTITION BY src_file ORDER BY line
                     ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) AS prev_max
                   FROM events_all WHERE {ts_ok})
        SELECT src_file, count(*) FILTER (WHERE prev_max - ts > {LATE_TOLERANCE_MS}) AS late,
               max(prev_max - ts) FILTER (WHERE prev_max - ts > {LATE_TOLERANCE_MS}) AS worst
        FROM o GROUP BY src_file""").fetchall()
    late_by_file = {f: {"late": n, "worst_ms": w} for f, n, w in late_rows}
    late_total = sum(v["late"] for v in late_by_file.values())

    lines = ingest_report.get("lines") or recs
    malformed = ingest_report.get("unparsed", 0)
    excluded = t["ts_missing"] + t["ts_invalid"]
    summary = {
        "total_lines_read": lines,
        "total_records": recs,
        "successfully_parsed": recs - malformed,
        "malformed_records": malformed,
        "binary_lines_skipped": ingest_report.get("binary_lines", 0),
        "missing_critical_fields": {
            "timestamp": t["ts_missing"], "host": t["host_missing"], "event_type": t["type_missing"],
            "user_where_expected": t["user_missing"], "source_of_remote_logon": t["remote_logon_no_source"],
            "process_where_expected": t["process_missing"]},
        "invalid_timestamps": t["ts_invalid"],
        "timestamps_with_assumption": t["ts_assumed"],
        "unknown_event_types": t["unknown_type"],
        "duplicate_records": dup_same,
        "duplicate_records_across_sources": max(dup_any - dup_same, 0),
        "late_arriving_events": late_total,
        "records_excluded_from_detection": excluded,
        "records_used_for_detection": recs - excluded,
        "hosts": t["hosts"],
        "time_range": [t["first_ts"], t["last_ts"]],
    }
    rates = {
        "parsed_pct": _pct(recs - malformed, recs), "malformed_pct": _pct(malformed, recs),
        "timestamp_missing_or_invalid_pct": _pct(excluded, recs), "host_missing_pct": _pct(t["host_missing"], recs),
        "unknown_type_pct": _pct(t["unknown_type"], recs), "duplicate_pct": _pct(dup_same, recs),
        "late_pct": _pct(late_total, recs), "user_missing_pct": _pct(t["user_missing"], t["user_expected"]),
        "remote_logon_source_missing_pct": _pct(t["remote_logon_no_source"], t["remote_logons"]),
        "process_missing_pct": _pct(t["process_missing"], t["proc_expected"]),
    }
    score = max(0.0, 100.0 - rates["malformed_pct"] - rates["timestamp_missing_or_invalid_pct"]
                - 0.5 * rates["host_missing_pct"] - 0.5 * rates["unknown_type_pct"] - 0.25 * rates["duplicate_pct"]
                - 0.25 * rates["user_missing_pct"])

    # per file
    files = []
    fstats = {f: (n, tsm, tsi, hm, unk) for f, n, tsm, tsi, hm, unk in con.execute(f"""
        SELECT src_file, count(*), count(*) FILTER (WHERE ts IS NULL),
               count(*) FILTER (WHERE ts IS NOT NULL AND NOT ({ts_ok})), count(*) FILTER (WHERE host IS NULL),
               count(*) FILTER (WHERE {unknown})
        FROM events_all GROUP BY src_file""").fetchall()}
    for rel, f in (ingest_report.get("files") or {}).items():
        n, tsm, tsi, hm, unk = fstats.get(rel, (0, 0, 0, 0, 0))
        lf = late_by_file.get(rel, {"late": 0, "worst_ms": None})
        files.append({"file": rel, "format": f.get("format"), "lines": f.get("lines"), "records": n,
                      "malformed": f.get("unparsed", 0), "timestamp_missing": tsm, "timestamp_invalid": tsi,
                      "host_missing": hm, "unknown_type": unk, "late": lf["late"], "worst_late_ms": lf["worst_ms"],
                      "top_unmapped_fields": list((f.get("unmapped") or {}).keys())[:8]})
    files.sort(key=lambda x: -(x["malformed"] + x["timestamp_missing"] + x["timestamp_invalid"] + x["host_missing"]
                               + x["unknown_type"] + x["late"]))

    # per host
    hosts = {}
    for h, n, um, ue_n, dups, srcs, lo, hi, rl, rlns in con.execute(f"""
        SELECT host, count(*), count(*) FILTER (WHERE {ue} AND "user" IS NULL), count(*) FILTER (WHERE {ue}),
               count(*) - count(DISTINCT {DUP_KEY}), list(DISTINCT format), min(ts) FILTER (WHERE {ts_ok}),
               max(ts) FILTER (WHERE {ts_ok}),
               count(*) FILTER (WHERE event_type = 'win:4624' AND logon_type IN (3, 10)),
               count(*) FILTER (WHERE event_type = 'win:4624' AND logon_type IN (3, 10) AND src_ip IS NULL
                                AND src_host IS NULL)
        FROM events_all WHERE host IS NOT NULL GROUP BY host""").fetchall():
        hosts[h] = {"records": n, "user_missing_pct": _pct(um, ue_n), "duplicates": dups, "formats": sorted(srcs),
                    "first_ts": lo, "last_ts": hi, "remote_logon_source_missing_pct": _pct(rlns, rl)}
    excluded_by_host = dict(con.execute(f"""SELECT host, count(*) FROM events_all
        WHERE host IS NOT NULL AND (ts IS NULL OR NOT ({ts_ok})) GROUP BY host""").fetchall())
    for h, n in excluded_by_host.items():
        hosts.setdefault(h, {"records": 0})["excluded_from_detection"] = n

    unknown_top = [{"event_type": et, "file": f, "records": n} for et, f, n in con.execute(f"""
        SELECT event_type, src_file, count(*) FROM events_all WHERE {unknown} GROUP BY ALL ORDER BY 3 DESC LIMIT 15
        """).fetchall()]

    warnings = []

    def warn(level, text):
        warnings.append({"level": level, "text": text})

    for sk in ingest_report.get("skipped") or []:
        warn("medium", f"file {sk['file']} was not read: {sk['reason']}")
    if rates["malformed_pct"] >= 1:
        warn("high", f"{malformed:,} records ({rates['malformed_pct']}%) matched no parser; kept as raw text "
                     f"(generic) so keyword rules still see them, but fields are guessed")
    if excluded:
        warn("high" if rates["timestamp_missing_or_invalid_pct"] >= 1 else "medium",
             f"{excluded:,} records ({rates['timestamp_missing_or_invalid_pct']}%) have a missing or impossible "
             f"timestamp and were excluded from detection (kept in events_all)")
    if t["ts_assumed"]:
        warn("medium" if _pct(t["ts_assumed"], recs) >= 1 else "low",
             f"{t['ts_assumed']:,} timestamps ({_pct(t['ts_assumed'], recs)}%) relied on an assumption (no timezone "
             f"in the log and none declared, or a syslog date without a year); declare `timezone`/`year` in "
             f"manifest.json so cross-source ordering is exact")
    if rates["host_missing_pct"] >= 1:
        warn("medium", f"{t['host_missing']:,} records ({rates['host_missing_pct']}%) name no host; add the host to "
                       f"manifest.json or a host-named folder")
    if rates["unknown_type_pct"] >= 1:
        warn("medium", f"{t['unknown_type']:,} records ({rates['unknown_type_pct']}%) have an unrecognised event type; "
                       f"add aliases/action mappings in rules/mappings/fields.yaml")
    if rates["duplicate_pct"] >= 0.5:
        warn("low", f"{dup_same:,} duplicate records ({rates['duplicate_pct']}%); alert counts may be inflated")
    if summary["duplicate_records_across_sources"]:
        warn("low", f"{summary['duplicate_records_across_sources']:,} events were delivered by more than one file/source")
    if late_total:
        worst = max((v["worst_ms"] or 0) for v in late_by_file.values()) / 60000
        warn("low", f"{late_total:,} late-arriving records ({rates['late_pct']}%), worst {worst:.0f} min out of order; "
                    f"ordering uses event time, not file order")
    if rates["user_missing_pct"] >= 5:
        warn("medium", f"{rates['user_missing_pct']}% of logon/process records carry no account; "
                       f"account-based linking will be weaker")
    if rates["remote_logon_source_missing_pct"] >= 5:
        warn("high", f"{rates['remote_logon_source_missing_pct']}% of remote logons carry no source IP/host; "
                     f"lateral-movement hops cannot be traced for those")
    span = (t["last_ts"] or 0) - (t["first_ts"] or 0)
    if recs and span < 6 * 3_600_000:
        warn("high", f"the whole dataset spans only {span / 1000:.1f} s; first-seen (rarity) rules are disabled "
                     f"and time-based ordering is unreliable")
        score = min(score, 70.0)                 # dataset-level problem: every record is fine, the timeline is not

    summary["files_skipped"] = len(ingest_report.get("skipped") or [])
    return {"summary": summary, "rates": rates, "skipped_files": ingest_report.get("skipped") or [], "quality_score": round(score, 1), "warnings": warnings,
            "files": files, "hosts": hosts, "unknown_event_types": unknown_top,
            "late_tolerance_ms": LATE_TOLERANCE_MS}


def for_incident(q: dict, steps: list[dict], gaps: list[dict]) -> dict:
    """Why this incident's path might be incomplete: quality of the logs from its own hosts."""
    hosts = sorted({s["host"] for s in steps if s.get("host")})
    out = []
    for h in hosts:
        hq = q.get("hosts", {}).get(h)
        if not hq:
            out.append({"host": h, "text": f"{h}: no records attributed to this host in the dataset"})
            continue
        if hq.get("excluded_from_detection"):
            out.append({"host": h, "text": f"{h}: {hq['excluded_from_detection']} records had unusable timestamps "
                                           f"and could not be placed in this story"})
        if hq.get("user_missing_pct", 0) >= 5:
            out.append({"host": h, "text": f"{h}: {hq['user_missing_pct']}% of logon/process records lack an account"})
        if hq.get("remote_logon_source_missing_pct", 0) >= 5:
            out.append({"host": h, "text": f"{h}: {hq['remote_logon_source_missing_pct']}% of remote logons have no "
                                           f"source, so hops into this host may be missing"})
        if hq.get("duplicates", 0) > 0.01 * max(hq.get("records", 1), 1):
            out.append({"host": h, "text": f"{h}: {hq['duplicates']} duplicate records"})
        if not any(f in (hq.get("formats") or []) for f in ("jsonl", "xml_events", "evtx", "auditd")):
            out.append({"host": h, "text": f"{h}: only {', '.join(hq.get('formats') or [])} logs; no endpoint "
                                           f"telemetry, so process-level steps cannot be seen"})
    for g in gaps:
        out.append({"host": g["host"], "text": f"{g['host']}: no logs from {g['start']} to {g['end']} "
                                               f"(~{g['expected_events']} expected); links across it are inferred"})
    return {"hosts": hosts, "warnings": out, "complete": not out}


def write(run_dir: str, q: dict) -> None:
    with open(os.path.join(run_dir, "quality.json"), "w", encoding="utf-8") as f:
        json.dump(q, f, indent=1, default=str)
