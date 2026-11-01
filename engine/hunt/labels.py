"""ATT&CK labels for change events: one table (rules/mappings/attack_labels.yaml), one meaning everywhere.

The same table drives detection (DuckDB macro `change_label(text)` + table `change_labels`, used by the
config_change rule) and the chain check that re-labels a step's own log lines (engine/validate.py), so a label can
never depend on which rule or vendor happened to report the change.
"""
from __future__ import annotations

import os
import re
from functools import lru_cache

import yaml

PATH = os.path.join(os.path.dirname(__file__), "..", "..", "rules", "mappings", "attack_labels.yaml")
SOURCES = {"fw": "fw", "win": "win", "sysmon": "win", "ps": "win", "audit": "linux", "linux": "linux",
           "syslog": "linux", "auth": "linux", "cloud": "cloud", "aws": "cloud", "azure": "cloud", "gcp": "cloud",
           "o365": "cloud", "okta": "cloud"}
CHANGE_EVENTS = "(e.event_type LIKE '%:config' OR e.event_type IN ('cloud:audit', 'audit:config'))"


@lru_cache(maxsize=1)
def load(path: str = PATH) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)["labels"]


def source_of(event_type: str | None) -> str:
    p = (event_type or "").split(":", 1)[0].lower()
    return SOURCES.get(p, p)


def text_of(row: dict) -> str:
    return " ".join(str(row.get(k) or "") for k in ("message", "action", "target")).lower()


def split(tid: str) -> tuple[str, str | None]:
    return (tid.split(".")[0], tid if "." in tid else None)


def key_of(text: str) -> str | None:
    """Which change kind a text describes (first match wins), or None."""
    for e in load():
        if any(re.search(rx, text) for rx in e["match"]) and not (e.get("unless") and re.search(e["unless"], text)):
            return e["key"]
    return None


def resolve(key: str, source: str | None = None, recently_created: bool = False) -> dict:
    e = next(x for x in load() if x["key"] == key)
    tid, stage, sev, name = e["technique"], e["stage"], e["severity"], e["name"]
    if recently_created and e.get("recently_created"):
        rc = e["recently_created"]
        tid, stage, sev, name = rc["technique"], rc["stage"], rc["severity"], rc["name"]
    else:
        tid = (e.get("by_source") or {}).get(source or "", tid)
    tech, sub = split(tid)
    return {"key": key, "name": name, "technique": tech, "sub_technique": sub, "stage": stage, "severity": sev}


def classify(text: str, source: str | None = None, recently_created: bool = False) -> dict | None:
    k = key_of(text.lower())
    return resolve(k, source, recently_created) if k else None


def _q(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def install(con) -> None:
    """DuckDB side: macro change_label(text) -> key, change_source(event_type) -> source, table change_labels."""
    whens = []
    for e in load():
        cond = "(" + " OR ".join(f"regexp_matches(t, {_q(rx)})" for rx in e["match"]) + ")"
        if e.get("unless"):
            cond += f" AND NOT regexp_matches(t, {_q(e['unless'])})"
        whens.append(f"WHEN {cond} THEN {_q(e['key'])}")
    con.execute(f"CREATE OR REPLACE MACRO change_label(t) AS CASE {' '.join(whens)} ELSE NULL END")
    con.execute("CREATE OR REPLACE MACRO change_source(et) AS CASE "
                + " ".join(f"WHEN split_part(lower(et), ':', 1) = {_q(k)} THEN {_q(v)}" for k, v in SOURCES.items())
                + " ELSE split_part(lower(et), ':', 1) END")
    rows = []
    for e in load():
        for src in ["*"] + list(e.get("by_source") or {}):
            r = resolve(e["key"], None if src == "*" else src)
            rows.append((e["key"], src, r["technique"], r["sub_technique"], r["stage"], r["severity"], r["name"]))
        if e.get("recently_created"):
            r = resolve(e["key"], None, recently_created=True)
            rows.append((e["key"] + ":recent", "*", r["technique"], r["sub_technique"], r["stage"], r["severity"],
                         r["name"]))
    con.execute("CREATE OR REPLACE TABLE change_labels (key VARCHAR, source VARCHAR, technique VARCHAR, "
                "sub_technique VARCHAR, stage VARCHAR, severity DOUBLE, name VARCHAR)")
    con.executemany("INSERT INTO change_labels VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
