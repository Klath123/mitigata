"""Re-write the reports of a finished run (no hunt, no correlation):  python -m engine.narrate results/<run>

Uses the run's own incidents/*.json and evidence.json, so a prompt or model change costs seconds, not a rerun.
Then refresh the UI (or POST /reload).
"""
import argparse
import json
import os

from ..results import store
from . import llm, report
from ..validate import run_dir as validate_run, step_rows

p = argparse.ArgumentParser(prog="python -m engine.narrate")
p.add_argument("run")
p.add_argument("--no-llm", action="store_true", help="template reports only")
a = p.parse_args()

summary, full, stats = store.load(a.run)
with open(os.path.join(a.run, "evidence.json"), encoding="utf-8") as f:
    evidence = json.load(f)
for iid, inc in sorted(full.items()):
    steps = [{**s, "_rows": step_rows(s, evidence, inc.get("resolved_hosts") or {})} for s in inc["steps"]]
    report.write(inc, steps, use_llm=not a.no_llm)
    print(f"incident {iid} ({inc['verdict']}): {inc['report_source']}, {len(inc['report'])} sentences, "
          f"grounding {inc['grounding_rate']}")
incidents = [i for i in full.values() if i["verdict"] == "attack"]
review = [i for i in full.values() if i["verdict"] != "attack"]
store.write(a.run, summary, sorted(incidents, key=lambda i: i["incident_id"]),
            sorted(review, key=lambda i: i["incident_id"]), stats)
print(f"rewrote {len(full)} incidents in {a.run} (model {llm.MODEL})")
validate_run(a.run)
