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


def _hm(ts: int) -> str:
    return datetime.fromtimestamp(ts / 1000, timezone.utc).strftime("%H:%M UTC")


def _when(a: int, b: int) -> str:
    if abs(b - a) < 60_000:
        return f"At {_t(a)}"
    same_day = _t(a)[:10] == _t(b)[:10]
    return f"From {_t(a)} to {_hm(b) if same_day else _t(b)}"


def narrate(inc: dict, steps: list[dict]) -> list[dict]:
    if not steps:
        return []
    out = []
    first, last = steps[0], steps[-1]
    stages = list(dict.fromkeys(s["stage"] for s in steps))
    hosts = list(dict.fromkeys(inc.get("path") or [s["host"] for s in steps if s["host"]]))
    users = list(dict.fromkeys(s["user"] for s in steps if s.get("user")))
    where = ", ".join(hosts[:4]) or first["host"]
    who = f" by the account{'s' if len(users) > 1 else ''} {', '.join(users[:3])}" if users else ""
    n = len(steps)
    if inc.get("verdict") == "attack":
        text = (f"{_when(first['ts'], last['ts'])}, {where} saw {n} linked suspicious action{'s' if n > 1 else ''}"
                f"{who}, covering {len(stages)} attack stage{'s' if len(stages) > 1 else ''}: "
                f"{', '.join(x.lower() for x in stages)}.")
    else:
        text = (f"{_when(first['ts'], last['ts'])}, {where} saw {n} suspicious action{'s' if n > 1 else ''}{who} "
                f"({', '.join(x.lower() for x in stages)}). This is not confirmed as an attack: a person should check it.")
    out.append({"text": text, "citations": _cover_hosts(steps, inc.get("path") or []), "kind": "observed",
                "section": "summary"})
    for s in steps:
        actor = f"{s['user']} on {s['host']}" if s.get("user") else s["host"]
        name = ", ".join(x.get("technique_name") or x["technique"] for x in [s] + s.get("also", []))
        out.append({"text": f"{_hm(s['ts'])}: {actor}: {s['summary']} ({name}).",
                    "citations": s["evidence"][:3], "kind": "observed", "section": "timeline"})
    for h in inc.get("hops", []):
        if h.get("external"):
            txt = f"The internet address {h['from']} reached {h['to']}" + (f" as {h['user']}." if h.get("user") else ".")
        else:
            txt = f"Activity moved from {h['from']} to {h['to']}" + (f" using the account {h['user']}." if h.get("user") else ".")
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
