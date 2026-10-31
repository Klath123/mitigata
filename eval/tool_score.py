"""Score an external detector's alerts on a labelled corpus, with eval/blind.py's definitions.

python -m eval.tool_score <corpus.labels.json> <corpus_dir> <alerts> [--min-level high] [--json out.json]

<alerts>: Hayabusa JSONL (EvtxFile = path), or Zircolite JSON (list of rules with matches; run it on a staging
folder of links named <unit>@@<file> so OriginalLogfile names the unit).

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


def _alerts(path: str):
    """Yield (unit_or_path, level, title, techniques, tactics) from Hayabusa JSONL or Zircolite JSON."""
    with open(path, encoding="utf-8", errors="replace") as f:
        head = f.read(1).lstrip()
        f.seek(0)
        if head == "[":                                   # Zircolite: [{title, tags, rule_level, matches: [...]}]
            for rule in json.load(f):
                tags = [t.lower() for t in rule.get("tags") or []]
                techs = [t.split(".", 1)[1] for t in tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]
                tacs = [t.split(".", 1)[1].replace("-", "") for t in tags if t.startswith("attack.")
                        and not re.fullmatch(r"attack\.[tgs]\d{4}(\.\d{3})?", t)]
                for m in rule.get("matches") or []:
                    unit = str(m.get("OriginalLogfile") or "").split("@@", 1)[0]
                    yield "unit:" + unit, rule.get("rule_level", "info"), rule.get("title"), techs, tacs
            return
        for line in f:
            try:
                a = json.loads(line)
            except ValueError:
                continue
            yield (str(a.get("EvtxFile") or ""), a.get("Level", "info"), a.get("RuleTitle"),
                   _list(a.get("MitreTags")), _list(a.get("MitreTactics")))


ZTACTIC = {"credentialaccess": "Credential Access", "defenseevasion": "Defense Evasion", "stealth": "Defense Evasion",
           "defenseimpairment": "Defense Evasion", "privilegeescalation": "Privilege Escalation",
           "lateralmovement": "Lateral Movement", "commandandcontrol": "Command and Control",
           "initialaccess": "Initial Access", "resourcedevelopment": "Resource Development",
           "execution": "Execution", "persistence": "Persistence", "discovery": "Discovery",
           "collection": "Collection", "exfiltration": "Exfiltration", "impact": "Impact",
           "reconnaissance": "Reconnaissance"}


def score(labels: dict, corpus: str, alerts_path: str, min_level: str = "info") -> dict:
    units = labels["units"]
    root = os.path.abspath(corpus)
    per = {u: {"hits": 0, "techs": set(), "tactics": set(), "rules": collections.Counter()} for u in units}
    floor = RANK.get(min_level.lower(), 0)
    for where, level, title, techs, tacs in _alerts(alerts_path):
        if RANK.get(str(level or "info").lower(), 0) < floor:
            continue
        if where.startswith("unit:"):
            u = where[5:]
        else:
            src = os.path.abspath(where)
            u = os.path.relpath(src, root).replace("\\", "/").split("/", 1)[0] if src.startswith(root) else ""
        if u not in per:
            continue
        p = per[u]
        p["hits"] += 1
        p["rules"][title or "?"] += 1
        for t in techs:
            m = re.fullmatch(r"(?:attack\.)?(t\d{4})(\.\d{3})?", str(t).lower())
            if m:
                p["techs"].add(m.group(1).upper())
                p["tactics"].update(stix.tactics((m.group(1) + (m.group(2) or "")).upper()) or [])
        for t in tacs:
            k = str(t).lower()
            if k in TACTIC or k in ZTACTIC:
                p["tactics"].add(TACTIC.get(k) or ZTACTIC[k])
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
    return {"corpus": labels["corpus"], "tool": os.path.basename(alerts_path), "min_level": min_level, "units": len(res),
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
    print(f"== {s['corpus']} {s['tool']} (level >= {a.min_level}): {s['units']} recordings")
    print(f"  detected {pct(s['detected'])}  technique right {pct(s['technique_right'])}  "
          f"tactic right {pct(s['tactic_right'])}  median alerts/recording {s['median_hits_per_unit']}")
    if a.json:
        json.dump(s, open(a.json, "w"), indent=1)


if __name__ == "__main__":
    main()
