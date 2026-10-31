"""Tracer: pull the un-flagged events around an incident from the Parquet store.

Backward: parent processes and the logon sessions that ran the incident's processes (entry points).
Forward: children, network connections, file and registry writes of incident processes (+6 h), and
the network flows that carried each lateral hop. Every query is filtered by host and time.
"""
from __future__ import annotations

import duckdb

HOUR = 3_600_000
CTX_COLS = ("src_file, line, ts, host, \"user\", event_type, process, parent, process_guid, parent_guid, "
            "logon_id, logon_type, src_ip, dst_ip, dst_port, target, cmdline, bytes_out")
MAX_CONTEXT = 400


def _in(vals) -> str:
    vals = sorted({str(v).replace("'", "''") for v in vals if v})
    return "(" + ",".join(f"'{v}'" for v in vals) + ")" if vals else "('')"


def trace(con: duckdb.DuckDBPyConnection, steps: list[dict], hops: list[dict], resolver_ip: dict[str, str]) -> list[dict]:
    rows = [r for s in steps for r in s["_rows"]]
    if not rows:
        return []
    have = {f"{r['src_file']}:{r['line']}" for r in rows}
    hosts = {r["host"] for r in rows if r.get("host")}
    lo = min(r["ts"] for r in rows) - 6 * HOUR
    hi = max(r["ts"] for r in rows) + 6 * HOUR
    guids = {r.get("process_guid") for r in rows} | {r.get("target_guid") for r in rows}
    parents = {r.get("parent_guid") for r in rows}
    sessions = {(r["host"], r["logon_id"]) for r in rows if r.get("logon_id") and r.get("host")
                and r["logon_id"] not in ("0x3e7", "0x3e4", "0x3e5")}
    q = []
    base = f"host IN {_in(hosts)} AND ts BETWEEN {lo} AND {hi}"
    if parents - {None}:
        q.append(f"SELECT {CTX_COLS}, 'parent process' AS why FROM events WHERE {base} "
                 f"AND event_type IN ('sysmon:1') AND process_guid IN {_in(parents)}")
    if guids - {None}:
        q.append(f"SELECT {CTX_COLS}, 'child of incident process' AS why FROM events WHERE {base} "
                 f"AND event_type = 'sysmon:1' AND parent_guid IN {_in(guids)}")
        q.append(f"SELECT {CTX_COLS}, 'activity of incident process' AS why FROM events WHERE {base} "
                 f"AND event_type IN ('sysmon:3','sysmon:11','sysmon:13','sysmon:22','sysmon:10') "
                 f"AND process_guid IN {_in(guids)}")
    if sessions:
        conds = " OR ".join(f"(host = '{h}' AND logon_id = '{lid}')" for h, lid in sorted(sessions)[:200])
        q.append(f"SELECT {CTX_COLS}, 'logon session' AS why FROM events WHERE {base} "
                 f"AND event_type IN ('win:4624','win:4672','win:4634') AND ({conds})")
    for h in hops:
        if h.get("external"):
            continue
        src_ip = resolver_ip.get(h["from"])
        dst_ip = resolver_ip.get(h["to"])
        if src_ip and dst_ip:
            q.append(f"SELECT {CTX_COLS}, 'network flow of hop {h['from']}->{h['to']}' AS why FROM events "
                     f"WHERE event_type IN ('net:flow','zeek:conn') AND src_ip = '{src_ip}' AND dst_ip = '{dst_ip}' "
                     f"AND ts BETWEEN {h['ts'] - 120_000} AND {h['ts'] + 120_000}")
    if not q:
        return []
    cur = con.execute(" UNION ALL ".join(q) + f" ORDER BY ts LIMIT {MAX_CONTEXT * 3}")
    cols = [d[0] for d in cur.description]
    out, seen = [], set()
    for row in cur.fetchall():
        r = dict(zip(cols, row))
        e = f"{r['src_file']}:{r['line']}"
        if e in have or e in seen:
            continue
        seen.add(e)
        r["evidence"] = e
        out.append(r)
        if len(out) >= MAX_CONTEXT:
            break
    return out
