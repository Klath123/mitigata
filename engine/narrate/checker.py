"""Citation checker (plain code has the last word over the narrator).

1 every sentence cites at least one event
2 every cited event exists in the story
3 every host, user, IP and file named in the sentence appears in a cited event
4 every ATT&CK ID named matches a cited step's label
5 every time named matches a cited event within one minute
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TIME = re.compile(r"\b(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d)(?::\d\d)?|\b(\d\d:\d\d)(?::\d\d)? ?UTC\b")


class Story:
    """Lookup structures over the incident's evidence for checking."""

    def __init__(self, steps: list[dict]):
        self.rows: dict[str, dict] = {}
        self.labels: dict[str, set[str]] = {}
        for s in steps:
            for r in s["_rows"]:
                e = f"{r['src_file']}:{r['line']}"
                self.rows[e] = r
                self.labels.setdefault(e, set()).update(filter(None, [s["technique"], s.get("sub_technique")]))
        self.hosts = {str(r.get(k)) for r in self.rows.values() for k in ("host", "src_h", "dst_h") if r.get(k)}
        self.users = {str(r.get(k)) for r in self.rows.values() for k in ("user", "target_user") if r.get(k)}

    def values(self, eids: list[str]) -> str:
        parts = []
        for e in eids:
            r = self.rows.get(e, {})
            parts += [str(v) for v in r.values() if v is not None]
        return " ".join(parts).lower()


def check_sentence(s: dict, story: Story) -> str | None:
    """Returns None if the sentence passes, else the reason it fails."""
    cites = s.get("citations") or []
    if not cites:
        return "no citation"
    missing = [c for c in cites if c not in story.rows]
    if missing:
        return f"cites unknown event {missing[0]}"
    text = s.get("text", "")
    blob = story.values(cites)
    low = text.lower()
    for h in story.hosts:
        if re.search(rf"\b{re.escape(h.lower())}\b", low) and h.lower() not in blob:
            return f"names host {h} not in cited events"
    for u in story.users:
        if len(u) > 2 and re.search(rf"\b{re.escape(u.lower())}\b", low) and u.lower() not in blob:
            return f"names account {u} not in cited events"
    for ip in IP.findall(text):
        if ip not in blob:
            return f"names IP {ip} not in cited events"
    for t in TECH.findall(text):
        labels = set().union(*(story.labels.get(c, set()) for c in cites))
        if t not in labels and t.split(".")[0] not in {x.split(".")[0] for x in labels}:
            return f"names {t} but cited steps are labelled {sorted(labels)}"
    for m in TIME.finditer(text):
        tss = [story.rows[c]["ts"] for c in cites if story.rows[c].get("ts") is not None]
        if not tss:
            return "names a time but cited events have none"
        if m.group(1):
            want = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
            want_ms = int(want.timestamp() * 1000)
            if not any(abs(t - want_ms) <= 120_000 for t in tss):
                return f"time {m.group(0)} not within a minute of cited events"
        else:
            hhmm = m.group(3)
            if not any(abs(_minutes(datetime.fromtimestamp(t / 1000, timezone.utc).strftime("%H:%M")) - _minutes(hhmm)) <= 1
                       for t in tss):
                return f"time {m.group(0)} not within a minute of cited events"
    return None


def _minutes(hhmm: str) -> int:
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def check(sentences: list[dict], story: Story) -> tuple[list[dict], list[dict]]:
    ok, dropped = [], []
    for s in sentences:
        why = check_sentence(s, story)
        if why:
            dropped.append({**s, "dropped_because": why})
        else:
            ok.append(s)
    return ok, dropped
