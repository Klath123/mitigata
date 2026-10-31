"""Template narrator: a plain-English report built from the steps, no LLM. Always available."""
from __future__ import annotations

from datetime import datetime, timezone


def _t(ts: int) -> str:
    return datetime.fromtimestamp(ts / 1000, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _cover_hosts(steps: list[dict], path: list[str]) -> list[str]:
    """First evidence on each host named in the summary, plus the first and last step."""
    cites = [steps[0]["evidence"][0]]
    for h in path:
        s = next((x for x in steps if x["host"] == h), None)
        if s and s["evidence"][0] not in cites:
            cites.append(s["evidence"][0])
    if steps[-1]["evidence"][0] not in cites:
        cites.append(steps[-1]["evidence"][0])
    return cites


def narrate(inc: dict, steps: list[dict]) -> list[dict]:
    if not steps:
        return []
    out = []
    first, last = steps[0], steps[-1]
    stages = []
    for s in steps:
        if s["stage"] not in stages:
            stages.append(s["stage"])
    path = " -> ".join(inc.get("path") or [])
    out.append({"text": f"Between {_t(first['ts'])} and {_t(last['ts'])} an attacker moved through {len(stages)} "
                        f"kill-chain stages ({', '.join(stages)}) across {path or first['host']}.",
                "citations": _cover_hosts(steps, inc.get("path") or []), "kind": "observed", "section": "summary"})
    for s in steps:
        who = f" as {s['user']}" if s.get("user") else ""
        name = s.get("technique_name") or s["technique"]
        tech = s.get("sub_technique") or s["technique"]
        out.append({"text": f"{_t(s['ts'])}: on {s['host']}{who}, {s['summary']} "
                            f"[{tech} {name}, {s['stage']}].",
                    "citations": s["evidence"][:3], "kind": "observed", "section": "timeline"})
    for h in inc.get("hops", []):
        if h.get("external"):
            txt = f"The attacker came in from the internet address {h['from']} to {h['to']} as {h['user']}."
        else:
            txt = f"The attacker moved from {h['from']} to {h['to']} using the account {h['user']}."
        out.append({"text": txt, "citations": [h["evidence"]], "kind": "observed", "section": "movement"})
    cite_all = [s["evidence"][0] for s in steps]
    for la in inc.get("look_ahead", [])[:3]:
        out.append({"text": f"Possible next targets for {la['account']}: {', '.join(la['can_reach'][:6])}. "
                            f"{la['why']}.", "citations": cite_all[-1:], "kind": "inferred", "section": "look_ahead",
                    "unchecked_entities": True})
    for g in inc.get("gaps", [])[:3]:
        out.append({"text": f"{g['host']} sent no logs from {g['start']} to {g['end']}; links across this window are "
                            f"inferred, not observed.", "citations": cite_all[:1], "kind": "inferred",
                    "section": "gaps", "unchecked_entities": True})
    return out
