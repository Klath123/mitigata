"""Score an engine run over a labelled public corpus (see eval/corpora.py). Nobody on the team wrote these attacks.

python -m eval.blind <corpus.labels.json> <run_dir> [--json out.json]

Per labelled unit (one recording):
  detected        at least one hunt hit on the unit's events
  technique right a hit whose parent ATT&CK technique matches the label's (units with technique labels)
  tactic right    a hit whose tactic matches one of the label's tactics
  in incident     the unit's events appear in a reported attack incident (or in review)
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os

import duckdb

from engine.attack import stix


def parent(t: str | None) -> str | None:
    return t.split(".")[0] if t else None


def score(labels: dict, run: str) -> dict:
    units = labels["units"]
    con = duckdb.connect(os.path.join(run, "engine.duckdb"), read_only=True)
    rows = con.execute("SELECT src_file, rule_id, kind, technique, sub_technique, tactic FROM hits").fetchall()
    per = {u: {"hits": 0, "rules": collections.Counter(), "techs": set(), "tactics": set()} for u in units}
    for src, rule, kind, tech, sub, tac in rows:
        u = src.replace("\\", "/").split("/", 1)[0]
        if u not in per:
            continue
        p = per[u]
        p["hits"] += 1
        p["rules"][rule] += 1
        if tech:
            p["techs"].add(parent(tech))
            p["tactics"].update(stix.tactics(sub or tech) or [])
        if tac:
            p["tactics"].add(tac)
    inc_units = {"attack": set(), "review": set()}
    for f in glob.glob(os.path.join(run, "incidents", "*.json")):
        d = json.load(open(f))
        for s in d.get("steps", []):
            for e in s.get("evidence", []):
                inc_units[d["verdict"]].add(e.replace("\\", "/").split("/", 1)[0])
    res, by_tactic = {}, collections.defaultdict(lambda: [0, 0])
    rule_units, rule_right = collections.Counter(), collections.Counter()
    for u, lab in units.items():
        p = per[u]
        want_t = {parent(t) for t in lab["techniques"]}
        want_tac = set(lab["tactics"]) | {x for t in lab["techniques"] for x in (stix.tactics(t) or [])}
        r = {"detected": p["hits"] > 0,
             "technique_right": bool(want_t & p["techs"]) if want_t else None,
             "tactic_right": bool(want_tac & p["tactics"]) if want_tac else None,
             "in_attack_incident": u in inc_units["attack"], "in_review": u in inc_units["review"],
             "hits": p["hits"], "rules": dict(p["rules"].most_common(8)),
             "want": sorted(want_t) or sorted(want_tac), "got": sorted(p["techs"])}
        res[u] = r
        for tac in want_tac or {"?"}:
            by_tactic[tac][0] += 1
            by_tactic[tac][1] += bool(r["technique_right"] if want_t else r["tactic_right"])
        for rule in p["rules"]:
            rule_units[rule] += 1
            if r["technique_right"] or (not want_t and r["tactic_right"]):
                rule_right[rule] += 1

    def rate(key):
        vals = [r[key] for r in res.values() if r[key] is not None]
        return round(sum(vals) / len(vals), 3) if vals else None
    hits = sorted(r["hits"] for r in res.values())
    return {"corpus": labels["corpus"], "units": len(res),
            "detected": rate("detected"), "technique_right": rate("technique_right"),
            "tactic_right": rate("tactic_right"), "in_attack_incident": rate("in_attack_incident"),
            "in_attack_or_review": round(sum(r["in_attack_incident"] or r["in_review"] for r in res.values())
                                         / max(1, len(res)), 3),
            "median_hits_per_unit": hits[len(hits) // 2] if hits else 0,
            "by_tactic": {k: {"units": v[0], "right": v[1], "rate": round(v[1] / v[0], 3)}
                          for k, v in sorted(by_tactic.items())},
            "top_rules": [{"rule": k, "units": v, "right": rule_right[k]} for k, v in rule_units.most_common(25)],
            "per_unit": res}


def table(s: dict) -> str:
    pct = lambda x: "-" if x is None else f"{x * 100:.0f}%"
    out = [f"== {s['corpus']}: {s['units']} recordings",
           f"  detected (any hit)        {pct(s['detected'])}",
           f"  technique right           {pct(s['technique_right'])}",
           f"  tactic right              {pct(s['tactic_right'])}",
           f"  in attack incident        {pct(s['in_attack_incident'])}   (attack or review: {pct(s['in_attack_or_review'])})",
           f"  median hits per recording {s['median_hits_per_unit']}", "  by tactic:"]
    for k, v in s["by_tactic"].items():
        out.append(f"    {k:<22} {v['right']:>3}/{v['units']:<3} {pct(v['rate'])}")
    out.append("  top rules (recordings fired / right):")
    for r in s["top_rules"][:12]:
        out.append(f"    {r['units']:>3} / {r['right']:<3} {r['rule']}")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("labels")
    ap.add_argument("run")
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    s = score(json.load(open(a.labels)), a.run)
    print(table(s))
    if a.json:
        with open(a.json, "w") as f:
            json.dump(s, f, indent=1, default=list)


if __name__ == "__main__":
    main()
