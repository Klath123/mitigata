"""Hayabusa (Yamato Security) as the Windows-log detector: curated Sigma + Hayabusa rules, native speed.

Used when the binary is found ($ATTACKSTORY_HAYABUSA or `hayabusa` on PATH; its rules/ and config/ folders sit
next to it). It scans the dataset's EVTX files (and JSON event exports, -J), and every alert becomes a hit on the
exact evidence line: EVTX by (file, EventRecordID); JSON by (file, timestamp, event id). Our engine still owns
everything Hayabusa does not read (Linux, network, web, Splunk XML...) and all correlation.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time

import duckdb

LEVEL = {"info": 0.05, "informational": 0.05, "low": 0.15, "med": 0.3, "medium": 0.3, "high": 0.6, "crit": 0.8,
         "critical": 0.8, "emergency": 0.9}
TACTIC = {"recon": "Reconnaissance", "resdev": "Resource Development", "initaccess": "Initial Access",
          "exec": "Execution", "persis": "Persistence", "privesc": "Privilege Escalation", "evas": "Defense Evasion",
          "stealth": "Defense Evasion", "defimpair": "Defense Evasion", "credaccess": "Credential Access",
          "disc": "Discovery", "latmov": "Lateral Movement", "collect": "Collection", "c2": "Command and Control",
          "exfil": "Exfiltration", "impact": "Impact"}


def binary() -> str | None:
    p = os.environ.get("ATTACKSTORY_HAYABUSA") or shutil.which("hayabusa")
    return p if p and os.path.exists(p) else None


def run(dataset: str, out: str, log=print) -> str | None:
    """Scan the dataset; returns the alerts JSONL path (or None when Hayabusa is unavailable)."""
    exe = binary()
    if not exe:
        return None
    home = os.path.dirname(os.path.realpath(exe))
    dst = os.path.join(out, "hayabusa.jsonl")
    if os.path.exists(dst):
        os.remove(dst)                    # a re-run must not append to the previous run's alerts
    t0, n = time.time(), 0
    for mode, extra in (("evtx", []), ("json", ["-J"])):
        part = dst + f".{mode}"
        cmd = [exe, "dfir-timeline", "-d", os.path.abspath(dataset), *extra, "-t", "jsonl", "-o", part,
               "-p", "verbose", "-w", "-q", "-Q", "-K", "-U", "-O"]
        p = subprocess.run(cmd, cwd=home, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, check=False)
        if p.returncode != 0:                 # never a silent "0 alerts": say Hayabusa itself failed, and why
            err = (p.stderr or "").strip().splitlines()
            log(f"  ! hayabusa ({mode}) exited {p.returncode}: {err[-1][:200] if err else 'no message'}")
        if os.path.exists(part):
            with open(part, encoding="utf-8", errors="replace") as a, open(dst, "a", encoding="utf-8") as b:
                for line in a:
                    b.write(line)
                    n += 1
            os.remove(part)
    log(f"  hayabusa: {n:,} alerts in {time.time() - t0:.1f}s")
    return dst if n else None


def load_hits(con: duckdb.DuckDBPyConnection, alerts: str, dataset: str, hit_cols: list[str], log=print) -> dict:
    """Insert alerts as hits (kind 'hayabusa'), joined to their events. Returns per-rule stats."""
    root = os.path.abspath(dataset)
    rows = []
    with open(alerts, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                a = json.loads(line)
            except ValueError:
                continue
            src = os.path.abspath(str(a.get("EvtxFile") or ""))
            if not src.startswith(root):
                continue
            rel = os.path.relpath(src, root).replace("\\", "/")
            techs = [t.upper() for t in a.get("MitreTags") or [] if re.fullmatch(r"[Tt]\d{4}(\.\d{3})?", str(t))]
            tac = next((TACTIC[t.lower()] for t in a.get("MitreTactics") or [] if str(t).lower() in TACTIC), None)
            sub = next((t for t in techs if "." in t), None)
            rows.append((rel, int(a.get("RecordID") or 0), str(a.get("Timestamp") or ""), int(a.get("EventID") or 0),
                         "hayabusa_" + str(a.get("RuleID") or a.get("RuleTitle"))[:40], str(a.get("RuleTitle")),
                         (sub.split(".")[0] if sub else (techs[0] if techs else None)), sub, tac,
                         LEVEL.get(str(a.get("Level", "info")).lower(), 0.05)))
    if not rows:
        return {}
    con.execute("CREATE OR REPLACE TEMP TABLE hb (src VARCHAR, rid BIGINT, tss VARCHAR, eid INTEGER, rule_id VARCHAR, "
                "title VARCHAR, technique VARCHAR, sub_technique VARCHAR, tactic VARCHAR, severity DOUBLE)")
    con.executemany("INSERT INTO hb VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
    cols = ", ".join(f'e."{c}"' for c in hit_cols)
    # same file, same event id, same time: +-1 ms when Hayabusa gives sub-second time, else the same second
    # (our EVTX lines are record positions, not EventRecordIDs, so the id alone cannot be used)
    con.execute(f"""
        INSERT INTO hits
        WITH h AS (SELECT *, epoch_ms(TRY_CAST(replace(tss, 'Z', '') AS TIMESTAMP)) AS t__,
                          CASE WHEN tss LIKE '%.%' THEN 1 ELSE 999 END AS tol__ FROM hb),
        m AS (
          SELECT h.*, e.src_file AS ef, e.line AS el FROM h JOIN events e
            ON e.src_file = h.src AND e.event_type LIKE '%:' || CAST(h.eid AS VARCHAR)
           AND e.ts BETWEEN h.t__ - h.tol__ AND h.t__ + h.tol__)
        SELECT DISTINCT ON (m.rule_id, m.ef, m.el) m.rule_id, m.title, 'hayabusa', m.technique, m.sub_technique,
               m.tactic, m.severity, m.rule_id || '#' || m.ef || ':' || CAST(m.el AS VARCHAR), {cols}
        FROM m JOIN events e ON e.src_file = m.ef AND e.line = m.el""")
    stats = {rid: {"hits": n} for rid, n in con.execute(
        "SELECT rule_id, count(*) FROM hits WHERE kind = 'hayabusa' GROUP BY 1").fetchall()}
    unmatched = len(rows) - sum(v["hits"] for v in stats.values())
    log(f"  hayabusa: {len(rows):,} alerts -> {sum(v['hits'] for v in stats.values()):,} hits "
        f"({max(unmatched, 0):,} not matched to an event)")
    con.execute("DROP TABLE hb")
    return stats
