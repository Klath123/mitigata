"""Chain checks: is each incident's kill chain consistent with its own evidence?

    python -m engine.validate results/<run>        (also runs at the end of every engine run)

Reads only the run's output (incidents/*.json + evidence.json), so it re-checks a run independently of the code
that built it. Writes inc["validation"] into each incident and validation.json for the run. No answer key
needed: these are internal-consistency checks, not accuracy against ground truth.
"""
from __future__ import annotations

import json
import os
import sys
from collections import defaultdict

from .attack import stix
from .hunt import labels
from .narrate import checker
from .schema import TACTIC_INDEX

RANK = {"pass": 0, "warn": 1, "fail": 2}


def _c(name: str, status: str, detail: str, steps: list[int] | None = None) -> dict:
    return {"check": name, "status": status, "detail": detail, "steps": steps or []}


def step_rows(step: dict, evidence: dict, resolved: dict) -> list[dict]:
    """A step's cited raw events, with the host names the engine resolved from their IPs."""
    return [{**r, "src_h": resolved.get(r.get("src_ip")), "dst_h": resolved.get(r.get("dst_ip"))}
            for r in (evidence[e] for e in step["evidence"] if e in evidence)]


def check_incident(inc: dict, evidence: dict) -> dict:
    steps = inc.get("steps", [])
    resolved = inc.get("resolved_hosts") or {}
    out = []

    missing = sorted({e for s in steps for e in s["evidence"] if e not in evidence})
    out.append(_c("evidence_exists", "fail" if missing else "pass",
                  f"{len(missing)} cited log lines not in the evidence index, e.g. {missing[0]}" if missing
                  else "every cited log line resolves to a raw event"))

    unmatched = []
    for s in steps:
        rows = step_rows(s, evidence, resolved)
        want = [str(v).lower() for v in (s.get("host"), s.get("user")) if v]
        text = [" ".join(str(v) for v in r.values() if v is not None).lower() for r in rows]
        if rows and want and not any(w in t for w in want for t in text):
            unmatched.append(s["order"])
    out.append(_c("evidence_matches_step", "fail" if unmatched else "pass",
                  "cited lines name neither the step's host nor its account" if unmatched
                  else "each step's lines name its host or account", unmatched))

    back_t = [s["order"] for a, s in zip(steps, steps[1:]) if s["ts"] < a["ts"]]
    out.append(_c("time_order", "fail" if back_t else "pass",
                  "steps out of time order" if back_t else "steps are in time order", back_t))

    back_k = [s["order"] for a, s in zip(steps, steps[1:])
              if TACTIC_INDEX.get(s["stage"], 0) < TACTIC_INDEX.get(a["stage"], 0)]
    out.append(_c("killchain_order", "warn" if back_k else "pass",
                  "kill chain goes backwards here (can be real: attackers repeat stages; worth a look)" if back_k
                  else "tactics never go backwards", back_k))

    misfit = [s["order"] for s in steps
              if stix.tactics(s.get("sub_technique") or s["technique"])
              and s["stage"] not in stix.tactics(s.get("sub_technique") or s["technique"])]
    out.append(_c("technique_fits_stage", "warn" if misfit else "pass",
                  "stage is not one of the technique's ATT&CK tactics" if misfit
                  else "every technique belongs to its stage in ATT&CK", misfit))

    if len(steps) > 1:                     # union-find over the step graph's evidence edges
        parent = {s["order"]: s["order"] for s in steps}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x
        for e in (inc.get("graph") or {}).get("edges", []):
            if e.get("kind") == "evidence" and e["src"].startswith("step") and e["dst"].startswith("step"):
                a, b = int(e["src"][4:]), int(e["dst"][4:])
                if a in parent and b in parent:
                    parent[find(a)] = find(b)
        groups = defaultdict(list)
        for o in parent:
            groups[find(o)].append(o)
        loose = sorted(o for g in groups.values() if len(g) < max(map(len, groups.values())) for o in g)
        out.append(_c("steps_linked", "warn" if len(groups) > 1 else "pass",
                      f"{len(groups)} separate groups of steps: these steps have no evidence link to the main chain"
                      if len(groups) > 1 else "all steps are joined by evidence links", loose))

    dup = []
    ev = {s["order"]: set(s["evidence"]) for s in steps}
    for s in steps:
        for t in steps:
            if s["order"] != t["order"] and ev[s["order"]] and ev[s["order"]] <= ev[t["order"]] \
                    and (ev[s["order"]] != ev[t["order"]] or s["order"] > t["order"]):
                dup.append(s["order"])
                break
    out.append(_c("distinct_evidence", "warn" if dup else "pass",
                  "these steps only re-use log lines of another step (one event counted as two steps)" if dup
                  else "every step has log lines of its own", dup))

    # labels: a step's own change events, re-labelled from the shared table (rules/mappings/attack_labels.yaml), must
    # agree with the step. T1078 is about WHO / FROM WHERE, not what was changed, so it fits any change.
    wrong = []
    for s in steps:
        mine = {s["technique"]} | {a["technique"] for a in s.get("also", [])}
        if "T1078" in mine:
            continue
        for r in step_rows(s, evidence, resolved):
            et = str(r.get("event_type") or "")
            if not (et.endswith(":config") or et in ("cloud:audit", "audit:config")):
                continue
            key = labels.key_of(labels.text_of(r))
            if not key:
                continue
            src = labels.source_of(et)
            ok = {labels.resolve(key, src)["technique"], labels.resolve(key, src, recently_created=True)["technique"]}
            if not ok & mine:
                wrong.append((s["order"], labels.resolve(key, src)["name"], sorted(ok)))
                break
    out.append(_c("label_matches_evidence", "warn" if wrong else "pass",
                  f"step {wrong[0][0]}'s log line is '{wrong[0][1]}' ({'/'.join(wrong[0][2])}) in the label table, "
                  f"not what the step says" if wrong else "every change step carries the label its log lines get "
                  "from the shared ATT&CK table", [w[0] for w in wrong]))

    if inc.get("verdict") == "attack":
        n_st = len({st for s in steps for st in [s["stage"]] + [a["stage"] for a in s.get("also", [])]})
        ok = len(steps) >= 2 and n_st >= 2
        out.append(_c("verdict_rules", "pass" if ok else "fail",
                      f"attack verdict with {len(steps)} steps over {n_st} stages"
                      + ("" if ok else ": needs at least 2 of each")))

    rows_steps = [{**s, "_rows": step_rows(s, evidence, resolved)} for s in steps]
    story = checker.Story(rows_steps)
    sents = [s for s in inc.get("report", []) if not s.get("unchecked_entities")]
    bad = [(s["text"][:80], why) for s in sents if (why := checker.check_sentence(s, story))]
    out.append(_c("report_grounded", "fail" if bad else "pass",
                  f"{len(bad)} of {len(sents)} report sentences fail a re-check, e.g. \"{bad[0][0]}...\": {bad[0][1]}"
                  if bad else f"all {len(sents)} report sentences re-checked against the raw events"
                  + (f" (written by {inc.get('report_source')})" if inc.get("report_source") else "")))

    rv = inc.get("agent_review")
    if rv:                                 # engine/verify_agent.py: advisory second opinion, already code-checked
        high = [i for i in rv["issues"] if i["severity"] == "high"]
        bad = rv["verdict"] == "disagree" or bool(high)
        out.append(_c("agent_review", "warn" if bad else "pass",
                      f"verification agent ({rv.get('model')}): {rv['verdict']}, false-positive likelihood "
                      f"{rv['false_positive_likelihood']}" + (f"; {high[0]['text'][:160]}" if high else ""),
                      sorted({i["step"] for i in high if i["step"]})))

    worst = max((c["status"] for c in out), key=RANK.get, default="pass")
    return {"status": worst, **{k: sum(c["status"] == k for c in out) for k in RANK}, "checks": out}


def run_dir(run: str, log=print) -> dict:
    from .results import store
    summary, full, stats = store.load(run)
    p = os.path.join(run, "evidence.json")
    evidence = json.load(open(p, encoding="utf-8")) if os.path.exists(p) else {}
    result = {}
    for iid, inc in sorted(full.items()):
        inc["validation"] = v = check_incident(inc, evidence)
        result[iid] = {"verdict": inc["verdict"], **{k: v[k] for k in ("status", "pass", "warn", "fail")},
                       "issues": [f"{c['check']}: {c['detail']}" + (f" (steps {c['steps']})" if c["steps"] else "")
                                  for c in v["checks"] if c["status"] != "pass"]}
        with open(os.path.join(run, "incidents", f"{iid}.json"), "w", encoding="utf-8") as f:
            json.dump(inc, f, default=str)
    with open(os.path.join(run, "validation.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1)
    for iid, r in result.items():
        log(f"  incident {iid} ({r['verdict']}): {r['status'].upper()}  {r['pass']} pass, {r['warn']} warn, {r['fail']} fail")
        for i in r["issues"]:
            log(f"      - {i}")
    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m engine.validate results/<run>")
    run_dir(sys.argv[1])
