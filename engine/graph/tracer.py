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


_ENV_ROOTS = (("%systemroot%", "c:\\windows"), ("%windir%", "c:\\windows"), ("\\systemroot\\", "c:\\windows\\"),
              ("%programfiles%", "c:\\program files"), ("%programdata%", "c:\\programdata"))


def service_image(path: str) -> str:
    """A service ImagePath as the process start will show it: env roots expanded, quotes and arguments dropped
    ('%SystemRoot%\\PSEXESVC.exe' and '"C:\\x\\a.exe" -k' match the process images C:\\Windows\\..., C:\\x\\a.exe)."""
    p = path.strip().lower()
    if p.startswith('"'):
        p = p[1:].split('"', 1)[0]
    elif ".exe " in p:
        p = p.split(".exe ", 1)[0] + ".exe"
    for env, real in _ENV_ROOTS:
        if p.startswith(env):
            p = real + p[len(env):]
            break
    return p


def corroborate(con: duckdb.DuckDBPyConnection, steps: list[dict], ip_of_host: dict[str, str]) -> int:
    """Attach the evidence that proves a step but matched no rule (it changes no score, only the evidence):
    - the network flow that carried a logon (same source IP -> the target's IP, seconds before it)
    - explicit-credential use (4648) on the source host naming the target, just before a hop
    - the remote-exec tool on the source host whose command line names the target host
    - share access / privilege grants inside the hop's logon session
    - the process a newly installed service started (same image path, minutes after) and its children
    Returns the number of evidence lines added."""
    added = 0
    for s in steps:
        have = set(s["evidence"])
        found: list[tuple[str, int]] = []
        for r in s["_rows"]:
            et, h, ts = r.get("event_type"), r.get("host"), r.get("ts")
            if not h or ts is None:
                continue
            if et in ("win:4624", "win:4625", "auth:success", "auth:fail") and r.get("src_ip"):
                dst = ip_of_host.get(h)
                if dst:
                    found += con.execute("""SELECT src_file, line FROM events WHERE event_type IN
                        ('net:flow', 'fw:flow', 'zeek:conn') AND src_ip = ? AND dst_ip = ?
                        AND ts BETWEEN ? AND ?""", [r["src_ip"], dst, ts - 120_000, ts + 5_000]).fetchall()
                src_h = r.get("src_h")
                if src_h and src_h != h:
                    found += con.execute("""SELECT src_file, line FROM events WHERE host = ? AND
                        ((event_type = 'win:4648' AND upper(split_part(coalesce(dst_host, target, ''), '.', 1)) = upper(?))
                         OR (event_type IN ('sysmon:1', 'win:4688') AND contains(upper(coalesce(cmdline, '')), ?)))
                        AND ts BETWEEN ? AND ?""", [src_h, h, "\\\\" + h.upper(), ts - 300_000, ts + 2_000]).fetchall()
                if r.get("logon_id"):
                    found += con.execute("""SELECT src_file, line FROM events WHERE host = ? AND logon_id = ?
                        AND event_type IN ('win:5140', 'win:5145', 'win:4672') AND ts BETWEEN ? AND ?""",
                                         [h, r["logon_id"], ts - 5_000, ts + HOUR]).fetchall()
            if et in ("win:7045", "win:4697") and r.get("process"):
                img = service_image(r["process"])
                procs = con.execute("""SELECT src_file, line, process_guid FROM events WHERE host = ?
                    AND event_type IN ('sysmon:1', 'win:4688') AND lower(process) = ? AND ts BETWEEN ? AND ?""",
                                    [h, img, ts - 5_000, ts + 300_000]).fetchall()
                found += [(f, n) for f, n, _ in procs]
                guids = [g for _, _, g in procs if g]
                if guids:
                    found += con.execute(f"""SELECT src_file, line FROM events WHERE host = ? AND parent_guid IN
                        {_in(guids)} AND event_type IN ('sysmon:1', 'win:4688') AND ts BETWEEN ? AND ?""",
                                         [h, ts - 5_000, ts + HOUR]).fetchall()
                found += con.execute("""SELECT src_file, line FROM events WHERE host = ? AND event_type = 'win:4688'
                    AND lower(parent) = ? AND ts BETWEEN ? AND ?""", [h, img, ts - 5_000, ts + HOUR]).fetchall()
        new = [f"{f}:{n}" for f, n in dict.fromkeys(found) if f"{f}:{n}" not in have]
        if new:
            s["evidence"] = s["evidence"] + new[:50]
            s["corroborating"] = new[:50]
            added += len(new[:50])
    return added
