"""ATT&CK Navigator layer export for one incident."""
from __future__ import annotations

from . import stix


def layer(incident: dict) -> dict:
    counts: dict[str, dict] = {}
    for s in incident.get("steps", []):
        labels = [(s.get("sub_technique") or s.get("technique"), s.get("stage"))] + \
                 [(a.get("sub_technique") or a.get("technique"), a.get("stage")) for a in s.get("also", [])]
        for tid, stage in labels:
            if not tid:
                continue
            c = counts.setdefault(tid, {"n": 0, "stage": stage, "hosts": set()})
            c["n"] += 1
            if s.get("host"):
                c["hosts"].add(s["host"])
    mx = max((c["n"] for c in counts.values()), default=1)
    techniques = []
    for tid, c in counts.items():
        techniques.append({
            "techniqueID": tid,
            "tactic": (c["stage"] or "").lower().replace(" ", "-"),
            "score": c["n"],
            "color": "",
            "comment": f"{stix.name(tid) or tid} on {', '.join(sorted(c['hosts']))}",
            "enabled": True,
        })
    return {
        "name": f"AttackStory incident {incident.get('incident_id')}",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Risk {incident.get('risk')}: {', '.join(incident.get('path', []))}",
        "techniques": techniques,
        "gradient": {"colors": ["#fde0dd", "#c51b8a"], "minValue": 0, "maxValue": mx},
        "legendItems": [],
    }
