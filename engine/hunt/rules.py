"""Hunt engine: load YAML/SQL rules (+ sequence DSL + Sigma) from rules/, run them over `events`,
and write every match into the `hits` table."""
from __future__ import annotations

import glob
import math
import os
import re
import time
from collections import defaultdict

import duckdb
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RULES_DIR = os.path.join(ROOT, "rules")
NOISY_MIN, NOISY_PER_HOST_DAY = 30, 0.5
PREVALENT_SHARE, PREVALENT_MIN = 0.2, 50   # a rule on >= 20% of all hosts/endpoints (and >= 50) is the environment
SIGMA_REPORT: dict = {}                    # filled by load_rules: Sigma rules loaded / refused and why
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


def _sigma_rules(sigma_dir: str) -> list[dict]:
    """Converted Sigma rules, cached in <sigma_dir>/.compiled.json (parsing ~3,000 YAML files cost ~25 s a run).
    The cache key covers every rule file (path, size, mtime) and the converter's own source."""
    import hashlib
    import json

    from . import sigma as sigma_mod
    h = hashlib.sha256(open(sigma_mod.__file__, "rb").read())
    for p in sorted(glob.glob(os.path.join(sigma_dir, "**", "*.y*ml"), recursive=True)):
        st = os.stat(p)
        h.update(f"{os.path.relpath(p, sigma_dir)}|{st.st_size}|{st.st_mtime_ns}".encode())
    key, cache = h.hexdigest(), os.path.join(sigma_dir, ".compiled.json")
    try:
        with open(cache, encoding="utf-8") as f:
            c = json.load(f)
        if c.get("key") == key:
            SIGMA_REPORT.update(c["report"])
            return c["rules"]
    except (OSError, ValueError, KeyError):
        pass
    rules = sigma_mod.load_sigma_dir(sigma_dir, SIGMA_REPORT)
    try:
        with open(cache, "w", encoding="utf-8") as f:
            json.dump({"key": key, "report": SIGMA_REPORT, "rules": rules}, f)
    except OSError:                                # read-only rules folder: just don't cache
        pass
    return rules


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
        SIGMA_REPORT.clear()
        seen = {r["id"] for r in out}
        for r in _sigma_rules(sigma_dir):
            if r["id"] not in seen:                    # the same Sigma rule shipped twice (ours + SigmaHQ)
                seen.add(r["id"])
                out.append(r)
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


BATCH = 150
_LOWER_COL = re.compile(r'lower\(CAST\(e\.("?)(\w+)\1 AS VARCHAR\)\)')


_REF_COL = re.compile(r'\be\."?(\w+)"?')


def _lc(match: str) -> str:
    return _LOWER_COL.sub(lambda m: f'e."{m.group(2)}__lc"', match)


def _run_grouped(con: duckdb.DuckDBPyConnection, rules: list[dict], stats: dict, log) -> None:
    """Rules that are a condition over one log source (Sigma): filter that source once, then evaluate up to
    BATCH conditions in a single pass (one CASE per rule) instead of one query per rule."""
    if not rules:
        return
    t0 = time.time()
    con.execute("CREATE OR REPLACE TEMP TABLE g_meta (ri INTEGER, id VARCHAR, title VARCHAR, kind VARCHAR, "
                "technique VARCHAR, sub_technique VARCHAR, tactic VARCHAR, severity DOUBLE)")
    con.executemany("INSERT INTO g_meta VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    [(i, r["id"], r.get("title", r["id"]), r.get("kind", "sigma"), r.get("technique"),
                      r.get("sub_technique"), r.get("tactic"), _sev(r.get("severity"))) for i, r in enumerate(rules)])
    con.execute("CREATE OR REPLACE TEMP TABLE g_match (key__ UBIGINT, ri INTEGER)")
    by_group: dict[str, list[int]] = defaultdict(list)
    for i, r in enumerate(rules):
        by_group[r["group"]].append(i)
    cols = ", ".join(f'e."{c}"' for c in HIT_COLS)
    # Sigma matching is case-insensitive: lower-case each referenced column once per log source,
    # not once per rule per row
    lc_cols = sorted({m.group(2) for r in rules for m in _LOWER_COL.finditer(r["match"])})
    counts: dict[int, int] = {}
    for gi, (g, idx) in enumerate(by_group.items()):
        tbl, tg = f"g_ls_{gi}", time.time()
        con.execute(f"CREATE OR REPLACE TEMP TABLE {tbl} AS SELECT * FROM events e WHERE {g}")
        n_rows = con.execute(f"SELECT count(*) FROM {tbl}").fetchone()[0]
        if not n_rows:
            for i in idx:
                stats[rules[i]["id"]] = {"hits": 0}
            con.execute(f"DROP TABLE {tbl}")
            continue
        # events identical in every column a rule looks at match it identically, so each distinct "shape" is
        # evaluated once. Rules are batched by the columns they reference, so a rule that reads hashes does not
        # stop every other rule from collapsing repeated process launches.
        refs_of = {i: tuple(sorted({m.group(1).removesuffix("__lc")
                                    for m in _REF_COL.finditer(_lc(rules[i]["match"]))} | {"event_type"}))
                   for i in idx}
        order = sorted(idx, key=lambda i: (len(refs_of[i]), refs_of[i]))
        shapes = 0
        for b in range(0, len(order), BATCH):
            part = order[b:b + BATCH]
            refs = sorted(set().union(*(refs_of[i] for i in part)))
            key = "hash(" + ", ".join(f'e."{c}"' for c in refs) + ")"
            con.execute(f"""CREATE OR REPLACE TEMP TABLE g_shp AS SELECT {key} AS key__,
                            {", ".join(f'any_value(e."{c}") AS "{c}"' for c in refs)}
                            {"".join(f', lower(CAST(any_value(e."{c}") AS VARCHAR)) AS "{c}__lc"' for c in lc_cols if c in refs)}
                            FROM {tbl} e GROUP BY 1""")
            shapes = max(shapes, con.execute("SELECT count(*) FROM g_shp").fetchone()[0])
            con.execute("DELETE FROM g_match")
            arr = ", ".join(f"CASE WHEN {_lc(rules[i]['match'])} THEN {i} END" for i in part)
            # the OR pre-filter drops non-matching shapes before any list is built (most match nothing)
            anyof = " OR ".join(f"({_lc(rules[i]['match'])})" for i in part)
            try:
                con.execute(f"INSERT INTO g_match SELECT key__, ri FROM (SELECT key__, unnest([{arr}]) AS ri "
                            f"FROM g_shp e WHERE {anyof}) WHERE ri IS NOT NULL")
            except Exception:                              # isolate the broken rule(s), keep the rest
                for i in part:
                    try:
                        con.execute(f"INSERT INTO g_match SELECT key__, {i} FROM g_shp e WHERE {_lc(rules[i]['match'])}")
                    except Exception as ex:
                        stats[rules[i]["id"]] = {"error": str(ex).splitlines()[0][:300]}
            if con.execute("SELECT count(*) FROM g_match").fetchone()[0]:
                con.execute(f"""INSERT INTO hits SELECT m.id, m.title, m.kind, m.technique, m.sub_technique, m.tactic,
                                m.severity, m.id || '#' || e.src_file || ':' || CAST(e.line AS VARCHAR), {cols}
                                FROM g_match x JOIN g_meta m USING (ri)
                                JOIN (SELECT {key} AS key__, * FROM {tbl} e) e ON e.key__ = x.key__""")
                for ri, n in con.execute(f"""SELECT x.ri, count(*) FROM g_match x
                                             JOIN (SELECT {key} AS key__ FROM {tbl} e) e ON e.key__ = x.key__
                                             GROUP BY 1""").fetchall():
                    counts[ri] = counts.get(ri, 0) + n
        con.execute("DROP TABLE IF EXISTS g_shp")
        con.execute(f"DROP TABLE {tbl}")
        if time.time() - tg > 2:
            log(f"    log source {g[:70]}: {len(idx)} rules, {n_rows:,} events (<= {shapes:,} distinct per batch), "
                f"{time.time() - tg:.1f}s")
    for i, r in enumerate(rules):
        if "error" not in stats.get(r["id"], {}):
            stats[r["id"]] = {"hits": counts.get(i, 0)}
    con.execute("DROP TABLE g_match")
    con.execute("DROP TABLE g_meta")
    log(f"  {len(rules)} grouped rules over {len(by_group)} log sources in {time.time() - t0:.1f}s")


def run_rules(con: duckdb.DuckDBPyConnection, rules: list[dict] | None = None, log=print, extra=None) -> dict:
    """extra(con) -> stats: more hits inserted before the final pass (e.g. Hayabusa alerts), so they get the
    same de-duplication, rarity, noise and baseline treatment as rule hits."""
    rules_loaded_here = rules is None
    rules = rules if rules is not None else load_rules()
    if rules_loaded_here and os.environ.get("ATTACKSTORY_SIGMA_WINDOWS") == "0":
        rules = [r for r in rules if not (r.get("kind") == "sigma" and r.get("product") == "windows")]
    con.execute(HITS_DDL)
    stats = {}
    have: dict[tuple, int] = {}
    aggregated: dict[str, int] = {}       # rule -> separate hits before grouping
    grouped = [r for r in rules if r.get("group") and r.get("match")]
    _run_grouped(con, grouped, stats, log)
    for r in grouped:
        if stats.get(r["id"], {}).get("hits", 0) > MAX_HIT_KEYS:
            agg = _aggregate_noisy(con, r["id"])
            if agg:
                stats[r["id"]]["aggregated"] = agg
                aggregated[r["id"]] = agg["from"]
    for r in rules:
        t0 = time.time()
        if r.get("group") and r.get("match"):
            continue
        req = r.get("requires") or {}
        if req:                           # telemetry the rule needs: say why it can't run instead of returning 0
            ets, flds = tuple(req.get("event_types") or ()), tuple(req.get("fields") or ())
            if (ets, flds) not in have:
                where = [f"event_type IN ({', '.join(_lit(e) for e in ets)})"] if ets else []
                where += [f'"{f}" IS NOT NULL' for f in flds]
                have[(ets, flds)] = con.execute("SELECT count(*) FROM (SELECT 1 FROM events WHERE "
                                                + (" AND ".join(where) or "TRUE") + " LIMIT 1)").fetchone()[0]
            if not have[(ets, flds)]:
                stats[r["id"]] = {"hits": 0, "disabled": f"no {'/'.join(ets) or 'events'} with "
                                                          f"{', '.join(flds) or 'any fields'}"}
                continue
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
                aggregated[r["id"]] = agg["from"]
                log(f"  rule {r['id']}: {agg['from']:,} separate hits is noise at this volume, "
                    f"grouped by {agg['by']} into {agg['to']:,} (severity halved)")
        except Exception as ex:
            stats[r["id"]] = {"error": str(ex).splitlines()[0][:300]}
            log(f"  rule {r['id']}: ERROR {stats[r['id']]['error']}")
    if extra:
        stats.update(extra(con) or {})
    # one row per (rule, evidence line); rarity = how unusual this rule+process signature is dataset-wide;
    # noisy = the rule fires far more often than an attack could, relative to hosts x days in THIS dataset:
    # such hits join an incident only through strong evidence links (graph/build.py WEAK_LINKS)
    try:
        hosts, days = con.execute("SELECT count(DISTINCT host), greatest(1, (max(ts) - min(ts)) / 86400000.0) "
                                  "FROM events WHERE ts IS NOT NULL").fetchone()
    except duckdb.CatalogException:       # rules run without an events table (unit use): size from the hits
        hosts, days = con.execute("SELECT count(DISTINCT host), greatest(1, (max(ts) - min(ts)) / 86400000.0) "
                                  "FROM hits WHERE ts IS NOT NULL").fetchone()
    noisy_at = max(NOISY_MIN, NOISY_PER_HOST_DAY * (hosts or 1) * (days or 1))
    # prevalence: a rule that fires on a large share of all entities describes the environment, not an attack
    # (hits of network events belong to the internal endpoint, as in graph/build.py)
    ent = ("CASE WHEN event_type IN ('net:flow', 'fw:flow', 'zeek:conn', 'fw:ips', 'fw:av', 'fw:web', 'fw:app', "
           "'dns:query') AND is_internal(src_ip) THEN src_ip ELSE host END")
    try:
        n_ent = con.execute(f"SELECT count(DISTINCT {ent}) FROM events").fetchone()[0] or 0
        common = [rid for (rid,) in con.execute(f"""SELECT rule_id FROM hits GROUP BY 1
                  HAVING count(DISTINCT {ent}) >= greatest({PREVALENT_MIN}, {PREVALENT_SHARE} * {n_ent})""").fetchall()]
    except duckdb.Error:                 # no events table / macros (unit use)
        common = []
    for rid in common:
        if rid in stats:
            stats[rid]["prevalent"] = f"fires on >= {PREVALENT_SHARE:.0%} of {n_ent} hosts/endpoints"
    # baseline: a rule that already fired for the same host + process during the warm-up is describing normal
    # activity of this environment, so its hits there are noisy too (the SOC tuning step, done from the data)
    con.execute("""
    CREATE OR REPLACE TABLE hits AS
    WITH d AS (SELECT DISTINCT ON (rule_id, src_file, line) *,
                      coalesce(lower(regexp_extract(process, '[^\\\\/]+$')), event_type) AS sig__ FROM hits),
    base AS (SELECT rule_id, host, sig__ FROM d
             WHERE ts <= getvariable('warmup_end') AND getvariable('warmup_end') <= getvariable('ds_end')
               AND kind NOT IN ('sequence')
             GROUP BY ALL HAVING count(DISTINCT hit_key) >= 2)
    SELECT d.* EXCLUDE (sig__), 1.0 / (1 + log10(1 + count(DISTINCT d.hit_key) OVER (
                 PARTITION BY d.rule_id, d.sig__))) AS rarity,
           count(DISTINCT d.hit_key) OVER (PARTITION BY d.rule_id) > """ + str(noisy_at) + """
             OR b.rule_id IS NOT NULL  OR d.rule_id IN (""" + (", ".join(_lit(k) for k in set(aggregated) | set(common)) or "''") + """) AS noisy
    FROM d LEFT JOIN base b ON b.rule_id = d.rule_id AND b.host IS NOT DISTINCT FROM d.host AND b.sig__ = d.sig__
    """)
    for rid, n_keys in aggregated.items():            # rarity reflects how noisy the rule really was, not the grouping
        con.execute("UPDATE hits SET rarity = ? WHERE rule_id = ?", [1.0 / (1 + math.log10(1 + n_keys)), rid])
    for rid, n in con.execute("SELECT rule_id, count(DISTINCT hit_key) FROM hits WHERE noisy GROUP BY 1").fetchall():
        if rid in stats:
            stats[rid]["noisy"] = f"{n} hits > {noisy_at:.0f} (hosts x days x {NOISY_PER_HOST_DAY})"
    if SIGMA_REPORT and rules_loaded_here:
        stats["_sigma"] = dict(SIGMA_REPORT)
    stats["_packs"] = _coverage(rules, stats)
    for name, p in sorted(stats["_packs"].items(), key=lambda x: -x[1]["hits"]):
        if p["fired"] or p["disabled"]:
            log(f"    pack {name:<28} {p['rules']:>5} rules, {p['fired']:>4} fired, {p['hits']:>8,} hits"
                + (f", {p['disabled']} disabled (no telemetry)" if p["disabled"] else ""))
    return stats


def _pack(r: dict) -> str:
    """Which detector pack a rule belongs to: Sigma by log family, our rules by file."""
    if r.get("kind") == "sigma":
        fam = r.get("product") or "generic"
        return f"sigma:{fam}"
    src = str(r.get("source") or "")
    return os.path.splitext(os.path.basename(src))[0] or r.get("kind", "rules")


def _coverage(rules: list[dict], stats: dict) -> dict:
    packs: dict[str, dict] = {}
    for r in rules:
        p = packs.setdefault(_pack(r), {"rules": 0, "fired": 0, "hits": 0, "disabled": 0, "errors": 0})
        s = stats.get(r["id"], {})
        p["rules"] += 1
        p["hits"] += s.get("hits", 0) or 0
        p["fired"] += bool(s.get("hits"))
        p["disabled"] += bool(s.get("disabled"))
        p["errors"] += "error" in s
    vendor = {k: v for k, v in stats.items() if not k.startswith("_") and k.startswith("hayabusa_")}
    if vendor:
        packs["hayabusa"] = {"rules": len(vendor), "fired": len(vendor), "disabled": 0, "errors": 0,
                             "hits": sum(v.get("hits", 0) for v in vendor.values())}
    return packs


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
