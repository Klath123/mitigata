"""Score an external detector's alerts (Hayabusa JSONL) on a labelled corpus, with eval/blind.py's definitions.

python -m eval.tool_score <corpus.labels.json> <corpus_dir> <hayabusa.jsonl> [--min-level high] [--json out.json]

detected = any alert on the recording; technique right = an alert tagged with the label's parent technique;
tactic right = an alert tagged with one of the label's tactics. (No incidents: these tools only alert.)
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re

from engine.attack import stix

TACTIC = {"recon": "Reconnaissance", "resdev": "Resource Development", "initaccess": "Initial Access",
          "exec": "Execution", "persis": "Persistence", "privesc": "Privilege Escalation",
          "evas": "Defense Evasion", "credaccess": "Credential Access", "disc": "Discovery",
          "latmov": "Lateral Movement", "collect": "Collection", "c2": "Command and Control",
          "exfil": "Exfiltration", "impact": "Impact", "stealth": "Defense Evasion", "defimpair": "Defense Evasion"}
LEVELS = ["info", "informational", "low", "med", "medium", "high", "crit", "critical"]
RANK = {"info": 0, "informational": 0, "low": 1, "med": 2, "medium": 2, "high": 3, "crit": 4, "critical": 4}


def _list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [x.strip() for x in re.split(r"[¦,|]", str(v)) if x.strip()]


def score(labels: dict, corpus: str, alerts_path: str, min_level: str = "info") -> dict:
    units = labels["units"]
    root = os.path.abspath(corpus)
    per = {u: {"hits": 0, "techs": set(), "tactics": set(), "rules": collections.Counter()} for u in units}
    floor = RANK.get(min_level.lower(), 0)
    with open(alerts_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                a = json.loads(line)
            except ValueError:
                continue
            if RANK.get(str(a.get("Level", "info")).lower(), 0) < floor:
                continue
            src = os.path.abspath(str(a.get("EvtxFile") or ""))
            rel = os.path.relpath(src, root).replace("\\", "/") if src.startswith(root) else ""
            u = rel.split("/", 1)[0]
            if u not in per:
                continue
            p = per[u]
            p["hits"] += 1
            p["rules"][a.get("RuleTitle", "?")] += 1
            for t in _list(a.get("MitreTags")):
                m = re.fullmatch(r"(?:attack\.)?(t\d{4})(\.\d{3})?", t.lower())
                if m:
                    p["techs"].add(m.group(1).upper())
                    p["tactics"].update(stix.tactics((m.group(1) + (m.group(2) or "")).upper()) or [])
            for t in _list(a.get("MitreTactics")):
                if t.lower() in TACTIC:
                    p["tactics"].add(TACTIC[t.lower()])
    res = {}
    for u, lab in units.items():
        p = per[u]
        want_t = {t.split(".")[0] for t in lab["techniques"]}
        want_tac = set(lab["tactics"]) | {x for t in lab["techniques"] for x in (stix.tactics(t) or [])}
        res[u] = {"detected": p["hits"] > 0,
                  "technique_right": bool(want_t & p["techs"]) if want_t else None,
                  "tactic_right": bool(want_tac & p["tactics"]) if want_tac else None,
                  "hits": p["hits"], "rules": dict(p["rules"].most_common(5))}

    def rate(k):
        v = [r[k] for r in res.values() if r[k] is not None]
        return round(sum(v) / len(v), 3) if v else None
    hits = sorted(r["hits"] for r in res.values())
    return {"corpus": labels["corpus"], "tool": "hayabusa", "min_level": min_level, "units": len(res),
            "detected": rate("detected"), "technique_right": rate("technique_right"),
            "tactic_right": rate("tactic_right"), "median_hits_per_unit": hits[len(hits) // 2] if hits else 0,
            "per_unit": res}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("labels"); ap.add_argument("corpus"); ap.add_argument("alerts")
    ap.add_argument("--min-level", default="info"); ap.add_argument("--json")
    a = ap.parse_args(argv)
    s = score(json.load(open(a.labels)), a.corpus, a.alerts, a.min_level)
    pct = lambda x: "-" if x is None else f"{x * 100:.0f}%"
    print(f"== {s['corpus']} hayabusa (level >= {a.min_level}): {s['units']} recordings")
    print(f"  detected {pct(s['detected'])}  technique right {pct(s['technique_right'])}  "
          f"tactic right {pct(s['tactic_right'])}  median alerts/recording {s['median_hits_per_unit']}")
    if a.json:
        json.dump(s, open(a.json, "w"), indent=1)


if __name__ == "__main__":
    main()
