"""Kill-chain stage choice for each step, and ordering helpers.

A technique that belongs to several tactics (Valid Accounts, Scheduled Task...) gets its stage
from its position in the incident: the first logon from the internet is Initial Access; the same
account used later on another host is Lateral Movement.
"""
from __future__ import annotations

from ..entities.resolve import is_external
from ..schema import TACTIC_INDEX, TACTICS
from . import stix


def choose_stage(technique: str | None, rule_tactic: str | None, step: dict, first_host: str | None,
                 seen_hosts: set[str]) -> str:
    tid = technique or ""
    if tid == "T1078":
        src = step.get("src_ip")
        if is_external(src):
            return "Initial Access"
        if step.get("host") and first_host and step["host"] != first_host and step["host"] not in seen_hosts:
            return "Lateral Movement"
        return rule_tactic or "Defense Evasion"
    if rule_tactic:
        return rule_tactic
    t = stix.tactics(tid)
    return t[0] if t else "Execution"


def order_score(stages: list[str]) -> float:
    """Share of consecutive step pairs (in time order) whose tactics do not go backwards."""
    idx = [TACTIC_INDEX.get(s, 0) for s in stages]
    if len(idx) < 2:
        return 1.0 if idx else 0.0
    ok = sum(1 for a, b in zip(idx, idx[1:]) if b >= a)
    return ok / (len(idx) - 1)


def out_of_order_flags(steps: list[dict]) -> list[int]:
    """Indices of steps whose tactic precedes the previous step's tactic (shown, not reordered)."""
    flags = []
    for i in range(1, len(steps)):
        if TACTIC_INDEX.get(steps[i]["stage"], 0) < TACTIC_INDEX.get(steps[i - 1]["stage"], 0):
            flags.append(i)
    return flags


__all__ = ["choose_stage", "order_score", "out_of_order_flags", "TACTICS"]
