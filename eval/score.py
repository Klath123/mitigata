"""Score a run against ground truth with the PRD's definitions.

python -m eval.score <dataset_dir> <run_dir> [--json]

- step found:      an incident (verdict attack) contains an event from that step
- label right:     a step containing one of the GT step's events has the same parent technique
- path rebuilt:    every GT step found, in the right order, inside ONE incident
- false incident:  an attack incident with no planted event in it
Also: event precision/recall, hop recall, entry point, order accuracy, decoy inclusions, true-attack rank.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

TARGETS = {  # (good, great)
    "detection": (0.70, 0.90), "labels": (0.60, 0.85), "paths": (0.5, 1.0), "false_alarms": (0.30, 0.10),
    "seconds_15gb": (3 * 3600, 3600), "peak_memory_gb": (16, 8), "path_latency_ms": (2000, 500),
}


def load(dataset: str, run: str):
    with open(os.path.join(dataset, "ground_truth.json")) as f:
        gt = json.load(f)
    with open(os.path.join(run, "incidents.json")) as f:
        res = json.load(f)
    full = []
    for inc in res["incidents"]:
        p = os.path.join(run, "incidents", f"{inc['incident_id']}.json")
        if os.path.exists(p):
            with open(p) as f:
                full.append(json.load(f))
        else:
            full.append(inc)
    stats = {}
    if os.path.exists(os.path.join(run, "stats.json")):
        with open(os.path.join(run, "stats.json")) as f:
            stats = json.load(f)
    return gt, res, full, stats


def parent(t: str | None) -> str | None:
    return t.split(".")[0] if t else None


def score(gt: dict, incidents: list[dict], stats: dict) -> dict:
    ev2inc: dict[str, set[int]] = {}
    ev2labels: dict[str, set[str]] = {}
    ev2order: dict[tuple[int, str], int] = {}
    inc_events: dict[int, set[str]] = {}
    for inc in incidents:
        iid = inc["incident_id"]
        inc_events[iid] = set()
        for s in inc["steps"]:
            for e in s["evidence"]:
                ev2inc.setdefault(e, set()).add(iid)
                ev2labels.setdefault(e, set()).add(parent(s["technique"]))
                ev2order[(iid, e)] = min(ev2order.get((iid, e), 10**9), s["order"])
                inc_events[iid].add(e)
        for c in inc.get("context_events", []):
            inc_events[iid].add(c["evidence"])

    all_mal = set()
    steps_total = steps_found = labels_right = 0
    paths_ok = 0
    entry_ok = 0
    order_pairs = order_ok = 0
    hops_total = hops_found = 0
    per_attack = []
    for a in gt["attacks"]:
        found_in: dict[int, int] = {}
        a_found = a_right = 0
        positions = []
        for s in a["steps"]:
            ev = set(s["evidence"])
            all_mal |= ev
            steps_total += 1
            incs = set().union(*(ev2inc.get(e, set()) for e in ev))
            if incs:
                steps_found += 1
                a_found += 1
                for i in incs:
                    found_in[i] = found_in.get(i, 0) + 1
            labs = set().union(*(ev2labels.get(e, set()) for e in ev))
            if parent(s["technique"]) in labs:
                labels_right += 1
                a_right += 1
            if s["technique"] == "T1021":
                hops_total += 1
                hops_found += bool(incs)
        best = max(found_in, key=found_in.get) if found_in else None
        complete = best is not None and found_in[best] == len(a["steps"])
        if best is not None:
            for s in a["steps"]:
                o = min((ev2order.get((best, e), 10**9) for e in s["evidence"]), default=10**9)
                positions.append(o)
            seen = [p for p in positions if p < 10**9]
            pairs = [(x, y) for i, x in enumerate(seen) for y in seen[i + 1:]]
            order_pairs += len(pairs)
            order_ok += sum(1 for x, y in pairs if x <= y)
            in_order = all(x <= y for x, y in pairs)
            first_step_order = positions[0]
            entry = first_step_order == min(seen) if seen else False
            entry_ok += entry
            if complete and in_order:
                paths_ok += 1
        rank = None
        if best is not None:
            ranked = sorted(incidents, key=lambda i: -i["risk"])
            rank = 1 + [i["incident_id"] for i in ranked].index(best)
        per_attack.append({"attack_id": a["attack_id"], "scenario": a["scenario"], "steps": len(a["steps"]),
                           "found": a_found, "labels_right": a_right, "incident": best, "complete": complete,
                           "rank": rank})

    false_inc = [i["incident_id"] for i in incidents if not (inc_events[i["incident_id"]] & all_mal)]
    decoy_ev = {e: kind for kind, evs in (gt.get("decoys") or {}).items() for e in evs}
    step_events = {e for inc in incidents for s in inc["steps"] for e in s["evidence"]}
    decoys_in = sorted({decoy_ev[e] + ":" + e for e in step_events if e in decoy_ev})
    story = set().union(*inc_events.values()) if inc_events else set()
    proc = stats.get("processed", {})
    out = {
        "dataset": gt.get("dataset"),
        "attacks": len(gt["attacks"]), "incidents": len(incidents),
        "detection": steps_found / steps_total if steps_total else None,
        "labels": labels_right / steps_total if steps_total else None,
        "paths": paths_ok / len(gt["attacks"]) if gt["attacks"] else None,
        "false_alarms": len(false_inc) / len(incidents) if incidents else 0.0,
        "false_incident_ids": false_inc,
        "decoy_inclusions": len(decoys_in) if gt.get("decoys") is not None else None,
        "decoy_inclusion_list": decoys_in[:20],
        "entry_point": entry_ok / len(gt["attacks"]) if gt["attacks"] else None,
        "order_accuracy": order_ok / order_pairs if order_pairs else None,
        "hop_recall": hops_found / hops_total if hops_total else None,
        "event_recall": len(story & all_mal) / len(all_mal) if all_mal else None,
        "event_precision": len(story & all_mal) / len(story) if story else None,
        "clean_bundle_ok": (len(incidents) == 0) if not gt["attacks"] else None,
        "seconds": proc.get("seconds"), "peak_memory_gb": proc.get("peak_memory_gb"),
        "bytes": proc.get("bytes"), "mb_per_s": proc.get("mb_per_s"),
        "per_attack": per_attack,
    }
    if proc.get("bytes"):
        out["seconds_15gb"] = proc["seconds"] * (15 * 2**30) / proc["bytes"]
    return out


def table(s: dict) -> str:
    def pct(x):
        return "n/a" if x is None else f"{100 * x:.0f}%"

    def mark(key, val, higher=True):
        if val is None:
            return ""
        g, gr = TARGETS[key]
        if higher:
            return "GREAT" if val >= gr else ("good" if val > g else "below")
        return "GREAT" if val <= gr else ("good" if val < g else "below")

    rows = [
        ("Detection (planted steps found)", pct(s["detection"]), "> 70%", "> 90%", mark("detection", s["detection"])),
        ("Correct labels", pct(s["labels"]), "> 60%", "> 85%", mark("labels", s["labels"])),
        ("Attack paths (all steps, right order)", pct(s["paths"]), "half", "all", mark("paths", s["paths"])),
        ("False alarms", pct(s["false_alarms"]), "< 30%", "< 10%", mark("false_alarms", s["false_alarms"], False)),
        ("Processing time (this run)", f"{s['seconds']}s" if s["seconds"] else "n/a", "", "", ""),
        ("  extrapolated to 15 GB", f"{s.get('seconds_15gb', 0) / 60:.0f} min" if s.get("seconds_15gb") else "n/a",
         "< 3 h", "< 1 h", mark("seconds_15gb", s.get("seconds_15gb"), False)),
        ("Peak memory", f"{s['peak_memory_gb']} GB" if s["peak_memory_gb"] is not None else "n/a", "< 16 GB", "< 8 GB",
         mark("peak_memory_gb", s["peak_memory_gb"], False)),
    ]
    w = max(len(r[0]) for r in rows)
    lines = [f"{'Measure':{w}}  {'Result':>10}  {'Good':>7}  {'Great':>7}  Verdict", "-" * (w + 40)]
    lines += [f"{a:{w}}  {b:>10}  {c:>7}  {d:>7}  {e}" for a, b, c, d, e in rows]
    lines.append("")
    lines.append(f"entry point {pct(s['entry_point'])}  order accuracy {pct(s['order_accuracy'])}  hop recall "
                 f"{pct(s['hop_recall'])}  event recall {pct(s['event_recall'])}  event precision "
                 f"{pct(s['event_precision'])}  decoy inclusions "
                 f"{'n/a' if s['decoy_inclusions'] is None else s['decoy_inclusions']} (target 0)")
    for a in s["per_attack"]:
        lines.append(f"  attack {a['attack_id']} ({a['scenario']}): {a['found']}/{a['steps']} found, "
                     f"{a['labels_right']}/{a['steps']} labelled, incident #{a['incident']} rank {a['rank']}, "
                     f"{'complete' if a['complete'] else 'split/partial'}")
    if s["false_incident_ids"]:
        lines.append(f"  false incidents: {s['false_incident_ids']}")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("dataset")
    p.add_argument("run")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    gt, res, full, stats = load(a.dataset, a.run)
    s = score(gt, full, stats)
    print(json.dumps(s, indent=1) if a.json else table(s))
    return s


if __name__ == "__main__":
    main(sys.argv[1:])
