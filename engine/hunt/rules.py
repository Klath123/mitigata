"""Hunt engine: load YAML/SQL rules (+ sequence DSL + Sigma) from rules/, run them over `events`,
and write every match into the `hits` table."""
from __future__ import annotations

import glob
import math
import os
import re
import time

import duckdb
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RULES_DIR = os.path.join(ROOT, "rules")
SEVERITY = {"info": 0.1, "informational": 0.1, "low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}

HIT_COLS = ["src_file", "line", "ts", "host", "user", "domain", "src_ip", "dst_ip", "dst_port", "src_host", "dst_host",
            "process", "parent", "process_guid", "parent_guid", "target_guid", "logon_id", "logon_type", "pid",
            "ppid", "target", "target_user", "group", "cmdline", "bytes_out", "event_type", "message", "action"]

HITS_DDL = """
CREATE OR REPLACE TABLE hits (
  rule_id VARCHAR, rule_title VARCHAR, kind VARCHAR, technique VARCHAR, sub_technique VARCHAR, tactic VARCHAR,
  severity DOUBLE, hit_key VARCHAR, src_file VARCHAR, line BIGINT, ts BIGINT, host VARCHAR, "user" VARCHAR,
  domain VARCHAR,
  src_ip VARCHAR, dst_ip VARCHAR, dst_port INTEGER, src_host VARCHAR, dst_host VARCHAR, process VARCHAR,
  parent VARCHAR, process_guid VARCHAR, parent_guid VARCHAR, target_guid VARCHAR, logon_id VARCHAR,
  logon_type INTEGER, pid BIGINT, ppid BIGINT, target VARCHAR, target_user VARCHAR, "group" VARCHAR,
  cmdline VARCHAR, bytes_out BIGINT, event_type VARCHAR, message VARCHAR, action VARCHAR)
"""


def _dur(s) -> int:
    if isinstance(s, (int, float)):
        return int(s * 1000)
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)", str(s).strip())
    if not m:
        raise ValueError(f"bad duration {s!r}")
    mult = {"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}[m.group(2)]
    return int(float(m.group(1)) * mult)


def compile_sequence(seq: dict) -> str:
    by = seq.get("by") or ["host"]
    keys = ", ".join(f'"{k}"' for k in by)
    gap = _dur(seq.get("gap", "5m"))
    within = _dur(seq.get("within", "30m"))
    min_count = int(seq.get("min_count", 5))
    emit = seq.get("emit", "first")
    notnull = " AND ".join(f'e."{k}" IS NOT NULL' for k in by)
    having = [f"count(*) >= {min_count}"]
    for col, n in (seq.get("min_distinct") or {}).items():
        having.append(f'count(DISTINCT "{col}") >= {int(n)}')
    join_keys = " AND ".join(f'b."{k}" = bu."{k}"' for k in by)
    # the follow-up must come from one of the failing sources (when sources are known)
    same_src = (" AND (len(bu.srcs__) = 0 OR list_contains(bu.srcs__, b.src_ip))"
                if seq.get("then_same_source", True) and "src_ip" not in by else "")
    sql = f"""
    WITH a AS (SELECT e.* FROM events e WHERE ({seq['first']}) AND {notnull}),
    s AS (SELECT a.*, CASE WHEN ts - lag(ts) OVER (PARTITION BY {keys} ORDER BY ts) <= {gap} THEN 0 ELSE 1 END AS nb__
          FROM a),
    g AS (SELECT s.*, sum(nb__) OVER (PARTITION BY {keys} ORDER BY ts ROWS UNBOUNDED PRECEDING) AS burst__ FROM s),
    bu AS (SELECT {keys}, burst__, min(ts) AS bstart__, max(ts) AS bend__,
                  list(DISTINCT src_ip) FILTER (WHERE src_ip IS NOT NULL) AS srcs__
           FROM g GROUP BY {keys}, burst__
           HAVING {' AND '.join(having)})"""
    key_expr = "concat_ws('|', " + ", ".join(f'CAST(bu."{k}" AS VARCHAR)' for k in by) + ", CAST(bu.burst__ AS VARCHAR))"
    if not seq.get("then"):
        return sql + f"""
    SELECT g.* EXCLUDE (nb__, burst__), {key_expr.replace('bu.', 'g.')} AS hit_key
    FROM g JOIN bu USING ({keys}, burst__)"""
    sql += f""",
    b AS (SELECT e.* FROM events e WHERE ({seq['then']}) AND {notnull}),
    m AS (SELECT bu.*, (SELECT min(b.ts) FROM b WHERE {join_keys} AND b.ts >= bu.bstart__
                        AND b.ts <= bu.bend__ + {within}{same_src}) AS succ__ FROM bu)"""
    first_sel = f"""SELECT g.* EXCLUDE (nb__, burst__), {key_expr.replace('bu.', 'g.')} AS hit_key
    FROM g JOIN m USING ({keys}, burst__) WHERE m.succ__ IS NOT NULL"""
    then_sel = f"""SELECT b.*, {key_expr} AS hit_key
    FROM m bu JOIN b ON {join_keys} AND b.ts = bu.succ__{same_src}"""
    if emit == "first":
        return sql + "\n" + first_sel
    if emit == "then":
        return sql + "\n" + then_sel
    return sql + f"\n{first_sel}\nUNION ALL BY NAME\n{then_sel}"


def load_rules(rules_dir: str = RULES_DIR) -> list[dict]:
    out = []
    for path in sorted(glob.glob(os.path.join(rules_dir, "detections", "*.y*ml"))
                       + glob.glob(os.path.join(rules_dir, "sequences", "*.y*ml"))):
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
        items = doc.get("rules", [doc] if "id" in doc else [])
        for r in items:
            r = dict(r)
            r["source"] = os.path.relpath(path, rules_dir)
            if r.get("disabled"):
                continue
            if "sequence" in r:
                r["sql"] = compile_sequence(r["sequence"])
                r.setdefault("kind", "sequence")
            out.append(r)
    sigma_dir = os.path.join(rules_dir, "sigma")
    if os.path.isdir(sigma_dir):
        from .sigma import load_sigma_dir
        out += load_sigma_dir(sigma_dir)
    return out


def load_macros(con: duckdb.DuckDBPyConnection, rules_dir: str = RULES_DIR) -> None:
    with open(os.path.join(rules_dir, "macros.sql"), encoding="utf-8") as f:
        text = f.read()
    for stmt in [s.strip() for s in text.split(";")]:
        lines = [ln for ln in stmt.splitlines() if not ln.strip().startswith("--")]
        if any(ln.strip() for ln in lines):
            con.execute("\n".join(lines))


def _sev(v) -> float:
    if isinstance(v, (int, float)):
        return float(v)
    return SEVERITY.get(str(v).lower(), 0.5)


def _lit(v) -> str:
    return "NULL" if v is None else "'" + str(v).replace("'", "''") + "'"


def run_rules(con: duckdb.DuckDBPyConnection, rules: list[dict] | None = None, log=print) -> dict:
    rules = rules if rules is not None else load_rules()
    con.execute(HITS_DDL)
    stats = {}
    noisy: dict[str, int] = {}
    for r in rules:
        t0 = time.time()
        try:
            cols = {c[0] for c in con.execute(f"DESCRIBE ({r['sql']})").fetchall()}
        except Exception as ex:                                # broken rule from config: skip, keep going
            stats[r["id"]] = {"error": str(ex).splitlines()[0][:300]}
            log(f"  rule {r['id']}: ERROR {stats[r['id']]['error']}")
            continue

        def ov(name, default):
            return f"coalesce(CAST(r.\"{name}\" AS VARCHAR), {_lit(default)})" if name in cols else _lit(default)

        sev = (f"coalesce(TRY_CAST(r.hit_severity AS DOUBLE), {_sev(r.get('severity'))})" if "hit_severity" in cols
               else str(_sev(r.get("severity"))))
        sel = []
        for c in HIT_COLS:
            q = f'"{c}"'
            if c == "host" and "hit_host" in cols:
                sel.append("coalesce(r.hit_host, r.host)")
            elif c == "user" and "hit_user" in cols:
                sel.append('coalesce(r.hit_user, r."user")')
            else:
                sel.append(f"r.{q}" if c in cols else "NULL")
        hk = "coalesce(CAST(r.hit_key AS VARCHAR), r.src_file || ':' || CAST(r.line AS VARCHAR))" \
            if "hit_key" in cols else "r.src_file || ':' || CAST(r.line AS VARCHAR)"
        sql = f"""INSERT INTO hits SELECT {_lit(r['id'])}, {_lit(r.get('title', r['id']))}, {_lit(r.get('kind', 'known_bad'))},
               {ov('technique', r.get('technique'))}, {ov('sub_technique', r.get('sub_technique'))},
               {ov('tactic', r.get('tactic'))}, {sev}, {_lit(r['id'])} || '#' || {hk}, {', '.join(sel)}
               FROM ({r['sql']}) r"""
        try:
            n0 = con.execute("SELECT count(*) FROM hits").fetchone()[0]
            con.execute(sql)
            n = con.execute("SELECT count(*) FROM hits").fetchone()[0] - n0
            stats[r["id"]] = {"hits": n, "seconds": round(time.time() - t0, 2)}
            agg = _aggregate_noisy(con, r["id"])
            if agg:
                stats[r["id"]]["aggregated"] = agg
                noisy[r["id"]] = agg["from"]
                log(f"  rule {r['id']}: {agg['from']:,} separate hits is noise at this volume, "
                    f"grouped by {agg['by']} into {agg['to']:,} (severity halved)")
        except Exception as ex:
            stats[r["id"]] = {"error": str(ex).splitlines()[0][:300]}
            log(f"  rule {r['id']}: ERROR {stats[r['id']]['error']}")
    # one row per (rule, evidence line); rarity = how unusual this rule+process signature is dataset-wide
    con.execute("""
    CREATE OR REPLACE TABLE hits AS
    WITH d AS (SELECT DISTINCT ON (rule_id, src_file, line) * FROM hits)
    SELECT d.*, 1.0 / (1 + log10(1 + count(DISTINCT hit_key) OVER (
                 PARTITION BY rule_id, coalesce(lower(regexp_extract(process, '[^\\\\/]+$')), event_type)))) AS rarity
    FROM d
    """)
    for rid, n_keys in noisy.items():            # rarity reflects how noisy the rule really was, not the grouping
        con.execute("UPDATE hits SET rarity = ? WHERE rule_id = ?", [1.0 / (1 + math.log10(1 + n_keys)), rid])
    return stats


MAX_HIT_KEYS = 2000          # more separate hits than this from one rule is noise, not a list to correlate
_DAY = "CAST(ts // 86400000 AS VARCHAR)"
_GROUPINGS = [("host+source+day", f"coalesce(host, '') || '|' || coalesce(src_ip, '') || '|' || {_DAY}"),
              ("host+day", f"coalesce(host, '') || '|' || {_DAY}")]


def _aggregate_noisy(con: duckdb.DuckDBPyConnection, rule_id: str) -> dict | None:
    """Group a flooding rule's hits per host/source/day (coarser if still too many). Every evidence row is kept."""
    n_keys = con.execute("SELECT count(DISTINCT hit_key) FROM hits WHERE rule_id = ?", [rule_id]).fetchone()[0]
    if n_keys <= MAX_HIT_KEYS:
        return None
    for i, (name, expr) in enumerate(_GROUPINGS):
        n_new = con.execute(f"SELECT count(DISTINCT {expr}) FROM hits WHERE rule_id = ?", [rule_id]).fetchone()[0]
        if n_new <= MAX_HIT_KEYS or i == len(_GROUPINGS) - 1:
            con.execute(f"UPDATE hits SET hit_key = rule_id || '#agg|' || {expr}, severity = severity * 0.5 "
                        "WHERE rule_id = ?", [rule_id])
            return {"from": n_keys, "to": n_new, "by": name}


__all__ = ["load_rules", "run_rules", "load_macros", "compile_sequence", "SEVERITY", "math"]
