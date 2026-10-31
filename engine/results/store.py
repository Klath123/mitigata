"""Precomputed results: written once at the end of processing; the API only reads them."""
from __future__ import annotations

import json
import os


def write(run_dir: str, summary: dict, incidents: list[dict], review: list[dict], stats: dict) -> None:
    os.makedirs(os.path.join(run_dir, "incidents"), exist_ok=True)
    for inc in incidents + review:
        with open(os.path.join(run_dir, "incidents", f"{inc['incident_id']}.json"), "w", encoding="utf-8") as f:
            json.dump(inc, f, default=str)
    with open(os.path.join(run_dir, "incidents.json"), "w", encoding="utf-8") as f:
        json.dump({**summary, "incidents": incidents, "review": [_brief(i) for i in review]}, f, indent=1, default=str)
    with open(os.path.join(run_dir, "stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=1, default=str)


def _brief(i: dict) -> dict:
    return {k: i[k] for k in ("incident_id", "risk", "verdict", "score_breakdown", "alerts_merged", "stages",
                              "first_seen", "last_seen", "path") if k in i}


def load(run_dir: str) -> tuple[dict, dict[int, dict], dict]:
    with open(os.path.join(run_dir, "incidents.json"), encoding="utf-8") as f:
        summary = json.load(f)
    full = {}
    d = os.path.join(run_dir, "incidents")
    if os.path.isdir(d):
        for fn in os.listdir(d):
            if fn.endswith(".json"):
                with open(os.path.join(d, fn), encoding="utf-8") as f:
                    inc = json.load(f)
                full[int(inc["incident_id"])] = inc
    stats = {}
    sp = os.path.join(run_dir, "stats.json")
    if os.path.exists(sp):
        with open(sp, encoding="utf-8") as f:
            stats = json.load(f)
    return summary, full, stats


def write_evidence_index(con, run_dir: str, incidents: list[dict], max_ids: int = 200_000) -> int:
    """Every evidence line cited by any incident (steps, hops, context, excluded, injection flags), with its
    normalized fields and raw text, so the API's evidence drawer never touches Parquet or scans logs."""
    ids = set()
    for inc in incidents:
        for s in inc.get("steps", []):
            ids.update(s["evidence"])
        for h in inc.get("hops", []):
            ids.add(h["evidence"])
        for c in inc.get("context_events", []):
            ids.add(c["evidence"])
        for x in inc.get("excluded", []):
            ids.update(x["evidence"])
        for f in inc.get("injection_flags", []):
            ids.add(f["evidence"])
    ids = sorted(ids)[:max_ids]
    if not ids:
        with open(os.path.join(run_dir, "evidence.json"), "w") as f:
            json.dump({}, f)
        return 0
    con.execute("CREATE OR REPLACE TEMP TABLE ev_ids (src_file VARCHAR, line BIGINT)")
    con.executemany("INSERT INTO ev_ids VALUES (?, ?)", [(e.rpartition(":")[0], int(e.rpartition(":")[2])) for e in ids])
    cur = con.execute("""
        SELECT e.src_file, e.line, e.ts, e.host, e."user", e.event_type, e.format, e.src_ip, e.dst_ip, e.process,
               e.parent, e.cmdline, e.target, e.message, e."offset", e.raw
        FROM events e JOIN ev_ids USING (src_file, line)""")
    cols = [d[0] for d in cur.description]
    files = {}
    fp = os.path.join(run_dir, "files.json")
    if os.path.exists(fp):
        with open(fp) as f:
            files = json.load(f)
    handles = {}
    out = {}
    for row in cur.fetchall():
        r = dict(zip(cols, row))
        eid = f"{r['src_file']}:{r['line']}"
        raw = r.pop("raw")
        off = r.pop("offset")
        if raw is None and off is not None and off >= 0 and r["src_file"] in files:
            path = files[r["src_file"]]["path"]
            try:
                fh = handles.get(path) or handles.setdefault(path, open(path, "rb"))
                fh.seek(off)
                raw = fh.readline(64_000).decode("utf-8", "replace").rstrip("\r\n")
            except OSError:
                raw = None
        r["raw"] = raw
        out.setdefault(eid, r)
    for fh in handles.values():
        fh.close()
    with open(os.path.join(run_dir, "evidence.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, default=str)
    return len(out)
