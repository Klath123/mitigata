"""Knowledge base: the engine's memory across runs, for logs that arrive in batches (e.g. 20 GB every hour).

    python -m engine.run <batch_dir> --out runs/<batch> --kb runs/kb     one batch, merged into the KB
    python -m engine.kb watch <inbox> --runs runs --kb runs/kb           every new batch that lands in <inbox>
    python -m engine.kb view runs/kb                                     rewrite the KB's UI view

Per batch:
1. carry_in (before correlation): detection hits of earlier batches from the last 24 h, plus every hit of a still-open
   KB incident, join this batch's hits. The same correlator then links an attack split across batches exactly as
   it links one inside a batch, and an open incident that grows is re-built with its new steps.
2. absorb (end of the run, DuckDB still open): this batch's hits go into the KB (a bounded sample per hit, with
   the raw line), entities update first/last seen. Hits older than the window that no open incident needs are
   pruned, so the KB stays the size of one day of hits.
3. merge (after checks): the batch's incidents merge into KB incidents by shared evidence. An incident that grew
   keeps its KB id; one that bridges two KB incidents absorbs the newer one. Incidents quiet for CLOSE_AFTER are
   closed and no longer carried.
4. view: the KB is written as a run folder (incidents.json, incidents/, evidence.json, graph/ with Neo4j CSV,
   entities.json), so the API and the UI show it like any run.

Evidence ids of earlier batches are 'kb:<batch>/<file>:<line>': files with the same name in different batches
never collide, and an id means the same line in every later batch.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time

import duckdb

HOUR = 3_600_000
WINDOW = 24 * HOUR                 # earlier hits that may still link to new activity
CLOSE_AFTER = 7 * 24 * HOUR        # an incident with no new step for this long is closed
ROWS_PER_HIT = 50                  # evidence rows kept per hit (first ones + the last): enough to link and cite
SIGMA_STEP_MIN = 0.6               # as graph/build.py: weaker Sigma hits are never steps, not worth carrying
DB = "kb.duckdb"


def gid(run: str, eid: str) -> str:
    """Global evidence id: lines of this batch get the batch prefix, carried lines already have one."""
    return eid if eid.startswith("kb:") else f"kb:{run}/{eid}"


def fingerprint(steps: list[dict], verdict: str | None) -> str:
    """Same steps on the same evidence = same story: an unchanged incident re-built in a later batch reuses its
    LLM report and review instead of paying for them every hour."""
    ev = sorted({e for s in steps for e in s.get("evidence", [])})
    return hashlib.sha1(json.dumps([ev, verdict]).encode()).hexdigest()


def _connect(kb_dir: str) -> duckdb.DuckDBPyConnection:
    os.makedirs(kb_dir, exist_ok=True)
    con = duckdb.connect(os.path.join(kb_dir, DB))
    _schema(con, "")
    return con


def _schema(con, p: str) -> None:
    con.execute(f"""
    CREATE TABLE IF NOT EXISTS {p}runs (run VARCHAR PRIMARY KEY, dataset VARCHAR, finished DOUBLE, events BIGINT,
        min_ts BIGINT, max_ts BIGINT, attack INTEGER, review INTEGER, carried_hits BIGINT);
    CREATE TABLE IF NOT EXISTS {p}incidents (kb_id INTEGER PRIMARY KEY, status VARCHAR, merged_into INTEGER,
        verdict VARCHAR, risk DOUBLE, first_seen VARCHAR, last_seen VARCHAR, last_ts BIGINT, created_run VARCHAR,
        updated_run VARCHAR, runs VARCHAR, fingerprint VARCHAR, data VARCHAR);
    CREATE TABLE IF NOT EXISTS {p}incident_ev (kb_id INTEGER, eid VARCHAR);
    CREATE TABLE IF NOT EXISTS {p}evidence (eid VARCHAR PRIMARY KEY, data VARCHAR);
    CREATE TABLE IF NOT EXISTS {p}entities (kind VARCHAR, name VARCHAR, first_seen BIGINT, last_seen BIGINT,
        hits BIGINT, batches INTEGER, PRIMARY KEY (kind, name));
    CREATE TABLE IF NOT EXISTS {p}signins (account VARCHAR, src_ip VARCHAR, first_seen BIGINT, last_seen BIGINT,
        n BIGINT, PRIMARY KEY (account, src_ip));
    """)


# ---------------------------------------------------------------------------------------------- inside a run
def _cols(con, table: str) -> list[str]:
    return [d[0] for d in con.execute(f"SELECT * FROM {table} LIMIT 0").description]


def attach(con, kb_dir: str) -> None:
    os.makedirs(kb_dir, exist_ok=True)
    con.execute(f"ATTACH '{os.path.join(kb_dir, DB)}' AS kb")
    _schema(con, "kb.")


def carry_in(con, run: str, log=print) -> int:
    """Earlier hits into this batch's `hits` table (call after detection, before correlation)."""
    if not con.execute("SELECT count(*) FROM duckdb_tables() WHERE database_name = 'kb' AND table_name = 'hits'") \
            .fetchone()[0]:
        return 0
    lo = con.execute("SELECT min(ts) FROM events WHERE ts IS NOT NULL").fetchone()[0]
    if lo is None:
        return 0
    have = _cols(con, "hits")
    sel = ", ".join(f'"{c}"' for c in _cols(con, "kb.hits") if c in have)
    n = con.execute(f"""
        INSERT INTO hits ({sel}) SELECT {sel} FROM kb.hits h
        WHERE h.run <> ? AND (h.ts >= ? OR h.src_file || ':' || h.line IN (
              SELECT e.eid FROM kb.incident_ev e JOIN kb.incidents i USING (kb_id) WHERE i.status = 'open'))
        """, [run, lo - WINDOW]).fetchone()[0]
    # "first time" rules (first_only: true): the first access of an account from an address happened in the batch
    # that holds it; this batch's first row of the same hit is not a second first time
    from .hunt.rules import load_rules
    first_only = [r["id"] for r in load_rules() if r.get("first_only")]
    if first_only:
        dup = con.execute(f"""
            DELETE FROM hits WHERE src_file NOT LIKE 'kb:%' AND rule_id IN ({", ".join("?" * len(first_only))})
              AND hit_key IN (SELECT hit_key FROM hits WHERE src_file LIKE 'kb:%')""", first_only).fetchone()[0]
        if dup:
            log(f"  knowledge base: {dup} first-time hit(s) already recorded in an earlier batch, not repeated")
    log(f"  knowledge base: {n:,} hit rows carried in from earlier batches")
    return n


# successful sign-ins from the internet (admin console, VPN, RDP/SSH exposed): who signs in from where
SIGNIN = ("""event_type IN ('auth:success', 'win:4624') AND "user" IS NOT NULL AND src_ip IS NOT NULL
             AND NOT is_internal(src_ip) AND src_ip NOT IN ('127.0.0.1', '::1', '-')""")
NEW_SOURCE_RULE = "kb_new_signin_source"


def history_hits(con, log=print) -> int:
    """First-seen against the whole history, not this batch: a known account signing in from an internet address
    it never used before. Needs no warm-up inside the batch and no public rule an attacker could read. An account
    with no history at all is not flagged (every account is new on day one). Medium severity: on its own it is a
    lead; linked to what that session did next it builds an incident."""
    n = con.execute(f"""
        INSERT INTO hits BY NAME
        SELECT '{NEW_SOURCE_RULE}' AS rule_id,
               'Known account signed in from an internet address it never used before (knowledge base)' AS rule_title,
               'known_bad' AS kind, 'T1078' AS technique, NULL AS sub_technique, 'Initial Access' AS tactic,
               0.6 AS severity, '{NEW_SOURCE_RULE}#' || e."user" || '|' || e.src_ip AS hit_key,
               e.src_file, e.line, e.ts, e.host, e."user", e.domain, e.src_ip, e.dst_ip, e.dst_port, e.src_host,
               e.dst_host, e.logon_type, e.logon_id, e.event_type, e.message, e.action,
               1.0 AS rarity, false AS noisy
        FROM events e
        WHERE {SIGNIN}
          AND e."user" IN (SELECT account FROM kb.signins)
          AND NOT EXISTS (SELECT 1 FROM kb.signins s WHERE s.account = e."user" AND s.src_ip = e.src_ip)
        QUALIFY row_number() OVER (PARTITION BY e."user", e.src_ip ORDER BY e.ts, e.line) <= 5""").fetchone()[0]
    log(f"  knowledge base: {n} sign-in(s) by known accounts from never-seen internet addresses")
    return n


def fill_evidence(con, out: str, incidents: list[dict]) -> int:
    """Raw lines of carried hits cited by this batch's incidents (they are not in this batch's events)."""
    p = os.path.join(out, "evidence.json")
    ev = json.load(open(p, encoding="utf-8")) if os.path.exists(p) else {}
    want = {e for inc in incidents for s in inc.get("steps", []) for e in s["evidence"]
            if e.startswith("kb:") and e not in ev}
    if not want:
        return 0
    con.execute("CREATE OR REPLACE TEMP TABLE kb_want (eid VARCHAR)")
    con.executemany("INSERT INTO kb_want VALUES (?)", [(e,) for e in sorted(want)])
    cur = con.execute("""
        SELECT DISTINCT ON (src_file, line) src_file, line, ts, host, "user", event_type, format, src_ip, dst_ip,
               process, parent, cmdline, target, message, raw
        FROM kb.hits WHERE src_file || ':' || line IN (SELECT eid FROM kb_want)""")
    cols = [d[0] for d in cur.description]
    n = 0
    for row in cur.fetchall():
        r = dict(zip(cols, row))
        ev[f"{r['src_file']}:{r['line']}"] = r
        n += 1
    with open(p, "w", encoding="utf-8") as f:
        json.dump(ev, f, default=str)
    return n


def absorb(con, run: str, log=print) -> None:
    """This batch's own hits (a bounded sample per hit, with the raw line) and entities into the KB."""
    con.execute("""CREATE TABLE IF NOT EXISTS kb.hits AS
                   SELECT h.*, ''::VARCHAR AS run, ''::VARCHAR AS raw, ''::VARCHAR AS format FROM hits h LIMIT 0""")
    con.execute("DELETE FROM kb.hits WHERE run = ?", [run])          # a re-run of the same batch replaces it
    kb_cols = set(_cols(con, "kb.hits"))
    cols = [c for c in _cols(con, "hits") if c in kb_cols and c != "src_file"]
    sel = ", ".join(f'h."{c}"' for c in cols)
    n = con.execute(f"""
        INSERT INTO kb.hits ({", ".join(f'"{c}"' for c in cols)}, src_file, run, raw, format)
        WITH h AS (SELECT *, row_number() OVER (PARTITION BY hit_key ORDER BY ts, src_file, line) AS rn__,
                             row_number() OVER (PARTITION BY hit_key ORDER BY ts DESC, src_file DESC, line DESC) AS rl__
                   FROM hits WHERE src_file NOT LIKE 'kb:%'
                     AND NOT (kind IN ('sigma', 'hayabusa') AND severity < {SIGMA_STEP_MIN}))
        SELECT {sel}, 'kb:' || $1 || '/' || h.src_file, $1, left(e.raw, 4000), e.format
        FROM h LEFT JOIN events e ON e.src_file = h.src_file AND e.line = h.line
        WHERE h.rn__ <= {ROWS_PER_HIT} OR h.rl__ = 1""", [run]).fetchone()[0]
    # entities: first / last seen across all batches (the endpoint of firewall traffic, as in graph/build.py)
    con.execute("""
        INSERT INTO kb.entities
        SELECT kind, name, min(ts), max(ts), count(*), 1 FROM (
            SELECT 'host' AS kind, host AS name, ts FROM hits WHERE host IS NOT NULL AND src_file NOT LIKE 'kb:%'
            UNION ALL SELECT 'account', "user", ts FROM hits WHERE "user" IS NOT NULL AND src_file NOT LIKE 'kb:%'
            UNION ALL SELECT 'external_ip', ip, ts FROM (SELECT unnest([src_ip, dst_ip]) AS ip, ts FROM hits
                                                         WHERE src_file NOT LIKE 'kb:%')
                      WHERE ip IS NOT NULL AND NOT is_internal(ip))
        GROUP BY ALL
        ON CONFLICT DO UPDATE SET first_seen = least(first_seen, excluded.first_seen),
            last_seen = greatest(last_seen, excluded.last_seen), hits = hits + excluded.hits, batches = batches + 1""")
    con.execute(f"""
        INSERT INTO kb.signins SELECT "user", src_ip, min(ts), max(ts), count(*) FROM events WHERE {SIGNIN} GROUP BY ALL
        ON CONFLICT DO UPDATE SET first_seen = least(first_seen, excluded.first_seen),
            last_seen = greatest(last_seen, excluded.last_seen), n = n + excluded.n""")
    hi = con.execute("SELECT max(ts) FROM kb.hits").fetchone()[0] or 0
    pruned = con.execute("""
        DELETE FROM kb.hits WHERE ts < ? AND src_file || ':' || line NOT IN (
            SELECT e.eid FROM kb.incident_ev e JOIN kb.incidents i USING (kb_id) WHERE i.status = 'open')""",
                         [hi - WINDOW]).fetchone()[0]
    log(f"  knowledge base: {n:,} hit rows kept from this batch, {pruned:,} older rows pruned")


# ---------------------------------------------------------------------------------------------- after a run
def _rewrite(x, ids: set, run: str):
    """Every evidence id inside an incident (steps, hops, context, report citations, graph ids) made global."""
    if isinstance(x, str):
        if x in ids:
            return gid(run, x)
        if x.startswith("ctx:") and x[4:] in ids:
            return "ctx:" + gid(run, x[4:])
        return x
    if isinstance(x, list):
        return [_rewrite(v, ids, run) for v in x]
    if isinstance(x, dict):
        return {k: _rewrite(v, ids, run) for k, v in x.items()}
    return x


def merge(out: str, kb_dir: str, log=print) -> dict:
    """The batch's incidents into the KB, then the KB view. Returns {batch incident id: kb id}."""
    from .results import store
    run = os.path.basename(os.path.abspath(out))
    summary, full, stats = store.load(out)
    ev = json.load(open(os.path.join(out, "evidence.json"), encoding="utf-8")) \
        if os.path.exists(os.path.join(out, "evidence.json")) else {}
    ids = set(ev)
    con = _connect(kb_dir)
    try:
        con.execute("BEGIN")
        kb_ev: dict[int, set] = {}
        for kid, eid in con.execute("""SELECT e.kb_id, e.eid FROM incident_ev e JOIN incidents i USING (kb_id)
                                       WHERE i.status = 'open'""").fetchall():
            kb_ev.setdefault(kid, set()).add(eid)
        next_id = (con.execute("SELECT max(kb_id) FROM incidents").fetchone()[0] or 0) + 1
        mapping, taken, new = {}, set(), 0
        for iid, inc in sorted(full.items(), key=lambda kv: -kv[1]["risk"]):
            g = _rewrite(inc, ids, run)
            mine = {e for s in g["steps"] for e in s["evidence"]}
            hits = sorted(k for k, es in kb_ev.items() if es & mine and k not in taken)
            if hits:
                kid, newer = hits[0], hits[1:]                     # the oldest KB incident keeps its id
                old = con.execute("SELECT created_run, runs, first_seen FROM incidents WHERE kb_id = ?",
                                  [kid]).fetchone()
                created, runs = old[0], json.loads(old[1])
                for k in newer:
                    runs += json.loads(con.execute("SELECT runs FROM incidents WHERE kb_id = ?", [k]).fetchone()[0])
                    con.execute("UPDATE incidents SET status = 'merged', merged_into = ? WHERE kb_id = ?", [kid, k])
                    kb_ev.pop(k, None)
                lost = kb_ev.get(kid, set()) - mine
                if lost:                                           # should not happen: open incidents are carried
                    g.setdefault("kb_notes", []).append(f"{len(lost)} evidence lines of the earlier version "
                                                        f"are no longer part of this incident")
            else:
                kid, next_id, created, runs, new = next_id, next_id + 1, run, [], new + 1
            taken.add(kid)
            runs = list(dict.fromkeys(runs + [run]))
            g["batch_incident_id"], g["incident_id"] = iid, kid
            g["report_url"] = f"/incidents/{kid}/report"
            g["kb"] = {"kb_id": kid, "created_run": created, "updated_run": run, "batches": runs,
                       "merged": [int(k) for k in (hits[1:] if hits else [])]}
            last_ts = max((s["ts"] for s in g["steps"]), default=0)
            con.execute("INSERT OR REPLACE INTO incidents VALUES (?, 'open', NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        [kid, g["verdict"], g["risk"], g.get("first_seen"), g.get("last_seen"), last_ts, created, run,
                         json.dumps(runs), fingerprint(g["steps"], g["verdict"]), json.dumps(g, default=str)])
            con.execute("DELETE FROM incident_ev WHERE kb_id = ?", [kid])
            con.executemany("INSERT INTO incident_ev VALUES (?, ?)", [(kid, e) for e in sorted(mine)])
            mapping[iid] = kid
        # cited raw lines (steps, hops, context) of this batch, under global ids
        rows = [(gid(run, e), json.dumps(r, default=str)) for e, r in ev.items()]
        con.executemany("INSERT OR REPLACE INTO evidence VALUES (?, ?)", rows)
        # close incidents with no new step for CLOSE_AFTER (measured in log time, not wall clock)
        hi = con.execute("SELECT max(last_ts) FROM incidents").fetchone()[0] or 0
        closed = con.execute("UPDATE incidents SET status = 'closed' WHERE status = 'open' AND last_ts < ?",
                             [hi - CLOSE_AFTER]).fetchone()[0]
        p = stats.get("processed", {})
        tb = stats.get("time_bounds") or {}
        con.execute("INSERT OR REPLACE INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [run, summary.get("dataset"), time.time(), p.get("events"), tb.get("ds_start"), tb.get("ds_end"),
                     len(summary.get("incidents", [])), len(summary.get("review", [])),
                     (stats.get("counts") or {}).get("carried_hits")])
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    finally:
        con.close()
    log(f"  knowledge base: {len(mapping)} incident(s) from this batch, {new} new, "
        f"{len(mapping) - new} updated in place, {closed} closed")
    view(kb_dir, log=log)
    return mapping


def earlier_batches(kb_dir: str | None, run: str) -> int:
    """How many other batches the KB already holds (0 = this batch starts the stream)."""
    if not kb_dir or not os.path.exists(os.path.join(kb_dir, DB)):
        return 0
    con = duckdb.connect(os.path.join(kb_dir, DB), read_only=True)
    try:
        return con.execute("SELECT count(*) FROM runs WHERE run <> ?", [run]).fetchone()[0]
    finally:
        con.close()


def llm_cache(kb_dir: str | None) -> dict:
    """fingerprint -> the report and review fields of a KB incident, for unchanged incidents in a later batch."""
    if not kb_dir or not os.path.exists(os.path.join(kb_dir, DB)):
        return {}
    con = duckdb.connect(os.path.join(kb_dir, DB), read_only=True)
    try:
        out = {}
        for fp, data in con.execute("SELECT fingerprint, data FROM incidents WHERE status = 'open'").fetchall():
            d = json.loads(data)
            out[fp] = {k: d[k] for k in ("report", "report_source", "report_dropped", "grounding_rate",
                                         "agent_review") if k in d}
        return out
    finally:
        con.close()


def view(kb_dir: str, log=print) -> None:
    """Write the KB as a run folder the API/UI can open (incidents.json, incidents/, evidence.json, graph/)."""
    from .graph import export as graph_export
    from .results import store
    from . import validate
    con = duckdb.connect(os.path.join(kb_dir, DB))
    try:
        incs = [json.loads(d) for (d,) in con.execute(
            "SELECT data FROM incidents WHERE status = 'open' ORDER BY risk DESC, kb_id").fetchall()]
        closed = con.execute("SELECT count(*) FROM incidents WHERE status = 'closed'").fetchone()[0]
        runs = con.execute("SELECT run, dataset, finished, events, attack, review FROM runs ORDER BY finished") \
            .fetchall()
        want = sorted({e for i in incs for e in _evidence_ids(i)})
        con.execute("CREATE TEMP TABLE w (eid VARCHAR)")
        con.executemany("INSERT INTO w VALUES (?)", [(e,) for e in want])
        evidence = {e: json.loads(d) for e, d in con.execute(
            "SELECT eid, data FROM evidence WHERE eid IN (SELECT eid FROM w)").fetchall()}
        entities = [dict(zip(("kind", "name", "first_seen", "last_seen", "hits", "batches"), r)) for r in con.execute(
            "SELECT kind, name, first_seen, last_seen, hits, batches FROM entities").fetchall()]
        latest = con.execute("SELECT min_ts FROM runs ORDER BY finished DESC LIMIT 1").fetchone()
        signins = dict(con.execute("SELECT account, count(*) FROM signins GROUP BY 1").fetchall())
    finally:
        con.close()
    with open(os.path.join(kb_dir, "evidence.json"), "w", encoding="utf-8") as f:
        json.dump(evidence, f, default=str)
    attack = [i for i in incs if i["verdict"] == "attack"]
    review = [i for i in incs if i["verdict"] != "attack"]
    events = sum(r[3] or 0 for r in runs)
    summary = {"dataset": f"knowledge base: {len(runs)} batches", "processed": {"events": events},
               "knowledge_base": {"batches": [{"run": r[0], "dataset": r[1], "finished": r[2], "events": r[3],
                                               "attack": r[4], "review": r[5]} for r in runs],
                                  "open_incidents": len(incs), "closed_incidents": closed}}
    store.write(kb_dir, summary, attack, review, {"dataset": summary["dataset"], "processed": {"events": events},
                                                  "counts": {"attack_incidents": len(attack), "review_incidents": len(review)},
                                                  "knowledge_base": summary["knowledge_base"]})
    member: dict[tuple, set] = {}
    for i in incs:
        br = (i.get("blast_radius") or {}).get("confirmed", {})
        keys = {("host", h) for h in [s["host"] for s in i["steps"]] + i.get("path", []) + br.get("hosts", []) if h}
        keys |= {("account", u) for u in [s["user"] for s in i["steps"]] + br.get("users", []) if u}
        keys |= {("external_ip", ip) for ip in br.get("external_ips", [])}
        for k in keys:
            member.setdefault(k, set()).add(i["incident_id"])
    lo = (latest or [None])[0]
    for e in entities:
        e["incidents"] = sorted(member.get((e["kind"], e["name"]), ()))
        e["new_in_latest_batch"] = bool(lo is not None and e["first_seen"] is not None and e["first_seen"] >= lo
                                        and e["batches"] == 1)
        if e["kind"] == "account":
            e["signin_sources"] = signins.get(e["name"], 0)
    entities.sort(key=lambda e: (-len(e["incidents"]), -(e["last_seen"] or 0)))
    entities = entities[:max(20_000, sum(bool(e["incidents"]) for e in entities))]   # incident entities always kept
    with open(os.path.join(kb_dir, "entities.json"), "w", encoding="utf-8") as f:
        json.dump(entities, f, default=str)
    g = graph_export.build(incs, None)
    mem = {(e["kind"], str(e["name"])): e for e in entities}
    kinds = {"Host": "host", "Account": "account", "ExternalIP": "external_ip"}
    for n, d in g.nodes(data=True):
        e = mem.get((kinds.get(d.get("label")), str(d.get("name"))))
        if e:
            d.update(first_seen=e["first_seen"], last_seen=e["last_seen"], batches=e["batches"], detections=e["hits"])
    graph_export.write(kb_dir, g)
    validate.run_dir(kb_dir, log=lambda *a: None)
    log(f"  knowledge base view: {len(attack)} attack + {len(review)} review open incidents over {len(runs)} "
        f"batches -> {kb_dir}")


def _evidence_ids(inc: dict) -> set:
    ids = set()
    for s in inc.get("steps", []):
        ids.update(s["evidence"])
    ids.update(h["evidence"] for h in inc.get("hops", []))
    ids.update(c["evidence"] for c in inc.get("context_events", []))
    for x in inc.get("excluded", []):
        ids.update(x["evidence"])
    ids.update(f["evidence"] for f in inc.get("injection_flags", []))
    return ids


# ---------------------------------------------------------------------------------------------- batches
def _settled(path: str, quiet: float) -> bool:
    """A batch still being copied in keeps changing: wait until nothing in it changed for `quiet` seconds."""
    newest = os.path.getmtime(path)
    for d, _, fs in os.walk(path):
        for f in fs:
            newest = max(newest, os.path.getmtime(os.path.join(d, f)))
    return time.time() - newest >= quiet


def watch(inbox: str, runs: str, kb_dir: str, every: float = 60, quiet: float = 120, once: bool = False,
          extra: list[str] | None = None, log=print) -> None:
    """Run every new batch (a file or a folder in `inbox`), oldest first, each merged into the KB."""
    os.makedirs(runs, exist_ok=True)
    done_p = os.path.join(kb_dir, "batches_done.txt")
    os.makedirs(kb_dir, exist_ok=True)
    while True:
        done = set(open(done_p).read().split("\n")) if os.path.exists(done_p) else set()
        todo = sorted((e for e in os.listdir(inbox) if not e.startswith(".") and e not in done),
                      key=lambda e: os.path.getmtime(os.path.join(inbox, e)))
        for e in todo:
            src = os.path.join(inbox, e)
            if not _settled(src, quiet):
                break                                  # keep batch order: wait for this one
            name = re.sub(r"[^A-Za-z0-9_.-]", "_", e.split(".")[0]) or "batch"
            out = os.path.join(runs, name)
            data = src
            if os.path.isfile(src):                    # the engine reads a folder: give the file one of its own
                data = os.path.join(runs, ".in", name)
                os.makedirs(data, exist_ok=True)
                link = os.path.join(data, e)
                if not os.path.exists(link):
                    os.symlink(os.path.abspath(src), link)
            log(f"[kb] batch {e} -> {out}")
            rc = subprocess.run([sys.executable, "-m", "engine.run", data, "--out", out, "--kb", kb_dir]
                                + (extra or [])).returncode
            if rc != 0:
                log(f"[kb] batch {e} failed (exit {rc}); it will be retried on the next pass")
                break
            with open(done_p, "a") as f:
                f.write(e + "\n")
        if once:
            return
        time.sleep(every)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("watch", help="process every new batch in an inbox folder, merged into the KB")
    w.add_argument("inbox")
    w.add_argument("--runs", required=True, help="folder for the per-batch run folders")
    w.add_argument("--kb", required=True, help="knowledge base folder")
    w.add_argument("--every", type=float, default=60, help="seconds between inbox checks")
    w.add_argument("--quiet", type=float, default=120, help="a batch must be unchanged this long before it runs")
    w.add_argument("--once", action="store_true", help="process what is there now, then exit")
    v = sub.add_parser("view", help="rewrite the KB's UI view")
    v.add_argument("kb")
    m = sub.add_parser("merge", help="merge a finished run into the KB (engine.run --kb does this itself)")
    m.add_argument("run")
    m.add_argument("--kb", required=True)
    a, extra = p.parse_known_args(argv)
    if a.cmd == "watch":
        watch(a.inbox, a.runs, a.kb, a.every, a.quiet, a.once, extra)
    elif a.cmd == "view":
        view(a.kb)
    else:
        merge(a.run, a.kb)


if __name__ == "__main__":
    main()
