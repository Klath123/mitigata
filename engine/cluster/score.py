"""Cluster risk score and incident assembly (steps, hops, path, blast radius, excluded lookalikes).

S = 0.35*T/Tmax + 0.20*O + 0.15*min(H,3)/3 + 0.20*V + 0.10*R
T distinct tactics, O kill-chain order share, H hosts, V max severity, R mean rarity.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from ..attack import stix
from ..attack.killchain import choose_stage, order_score
from ..entities.resolve import is_external, is_internal, is_system_account
from ..graph.build import Node

T_MAX = 6
STEP_GAP = 15 * 60_000
REPORT = 0.7
REVIEW = 0.4
HOP_TECH = {"T1021", "T1078"}


def iso(ts: int | None) -> str:
    if ts is None:
        return ""
    return datetime.fromtimestamp(ts / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts % 1000:03d}Z"


def score(nodes: list[Node], stages: list[str]) -> tuple[float, dict]:
    labelled = [n for n in nodes if n.technique]
    T = len(set(stages))
    O = order_score(stages)
    hosts = set().union(*(n.hosts for n in nodes)) if nodes else set()
    H = len(hosts)
    V = max((n.severity for n in nodes), default=0.0)
    R = sum(n.rarity for n in nodes) / len(nodes) if nodes else 0.0
    S = 0.35 * min(T, T_MAX) / T_MAX + 0.20 * O + 0.15 * min(H, 3) / 3 + 0.20 * V + 0.10 * R
    if T < 2:                         # a single tactic is noise, however severe (spec: require >=2 linked tactics)
        S = min(S, REVIEW - 0.01)
    if len(labelled) < 2:
        S = min(S, REVIEW - 0.01)
    return round(S, 3), {"tactics": T, "order": round(O, 3), "hosts": H, "severity": round(V, 3),
                         "rarity": round(R, 3)}


def _step_user(rows: list[dict]) -> str | None:
    c = Counter(r["user"] for r in rows if r.get("user") and not is_system_account(r["user"]))
    if c:
        return c.most_common(1)[0][0]
    c = Counter(r["user"] for r in rows if r.get("user"))
    return c.most_common(1)[0][0] if c else None


def _summary(n: Node, rows: list[dict]) -> str:
    r = rows[0]
    bits = [n.title]
    detail = r.get("cmdline") or r.get("target") or r.get("message")
    if r.get("event_type") in ("win:4624", "auth:success") and r.get("src_ip"):
        detail = f"logon type {r.get('logon_type')} from {r.get('src_h') or r['src_ip']}"
    if r.get("event_type") in ("net:flow", "zeek:conn"):
        total = sum(x.get("bytes_out") or 0 for x in rows)
        detail = f"{total / 2**20:.0f} MB to {r.get('dst_ip')}:{r.get('dst_port')}"
    if detail:
        bits.append(str(detail)[:160])
    if len(rows) > 1:
        bits.append(f"({len(rows)} events)")
    return " - ".join(bits)


def build_steps(nodes: list[Node]) -> list[dict]:
    """Merge hits of the same technique on the same host within STEP_GAP into one step, in time order."""
    items = []
    for n in nodes:
        if not n.technique:
            continue
        rows = sorted((r for r in n.rows if r["ts"] is not None), key=lambda r: r["ts"])
        if rows:
            items.append((rows[0]["ts"], n, rows))
    items.sort(key=lambda x: x[0])
    steps: list[dict] = []
    open_steps: dict[tuple, dict] = {}
    for ts, n, rows in items:
        host = Counter(r["host"] for r in rows if r.get("host")).most_common(1)
        host = host[0][0] if host else None
        key = (n.technique, host)
        s = open_steps.get(key)
        if s and ts - s["_end"] <= STEP_GAP:
            s["_rows"] += rows
            s["_nodes"].append(n)
            s["_end"] = max(s["_end"], rows[-1]["ts"])
            continue
        s = {"_rows": list(rows), "_nodes": [n], "_end": rows[-1]["ts"], "ts": ts, "host": host,
             "technique": n.technique}
        open_steps[key] = s
        steps.append(s)
    first_host = steps[0]["host"] if steps else None
    seen: set[str] = set()
    out = []
    for i, s in enumerate(sorted(steps, key=lambda s: s["ts"]), 1):
        rows = sorted(s["_rows"], key=lambda r: (r["ts"], r["src_file"], r["line"]))
        best = max(s["_nodes"], key=lambda n: (n.severity, bool(n.sub_technique)))
        subs = Counter(n.sub_technique for n in s["_nodes"] if n.sub_technique)
        src_ip = next((r["src_ip"] for r in rows if r.get("src_ip") and r.get("event_type") in
                       ("win:4624", "auth:success")), None)
        stage = choose_stage(s["technique"], best.tactic, {"host": s["host"], "src_ip": src_ip}, first_host, seen)
        if s["host"]:
            seen.add(s["host"])
        sub = subs.most_common(1)[0][0] if subs else None
        ev = []
        for r in rows:
            e = f"{r['src_file']}:{r['line']}"
            if e not in ev:
                ev.append(e)
        out.append({
            "order": i, "ts": s["ts"], "time": iso(s["ts"]), "host": s["host"], "user": _step_user(rows),
            "technique": s["technique"], "sub_technique": sub,
            "technique_name": stix.name(sub) or stix.name(s["technique"]), "stage": stage,
            "label_source": {"sigma": "sigma", "vendor": "vendor", "behavioural": "behavioural"}.get(best.kind, "rule"),
            "rule": ", ".join(sorted({n.rule_id for n in s["_nodes"]})),
            "summary": _summary(best, rows), "evidence": ev[:500],
            "_rows": rows, "_nodes": [n.key for n in s["_nodes"]], "_src_ip": src_ip,
        })
    return out


def build_hops(steps: list[dict]) -> list[dict]:
    hops = []
    for s in steps:
        for r in s["_rows"]:
            if r.get("event_type") in ("win:4624", "auth:success", "win:5140") and r.get("src_h") \
                    and r["src_h"] != r.get("host"):
                hops.append({"from": r["src_h"], "to": r["host"], "user": r.get("user"), "time": iso(r["ts"]),
                             "ts": r["ts"], "evidence": f"{r['src_file']}:{r['line']}", "technique": s["technique"]})
                break
            if r.get("event_type") in ("win:4624", "auth:success") and r.get("src_ip") \
                    and is_external(r["src_ip"]) and s["technique"] in HOP_TECH | {"T1110"}:
                hops.append({"from": r["src_ip"], "to": r["host"], "user": r.get("user"), "time": iso(r["ts"]),
                             "ts": r["ts"], "evidence": f"{r['src_file']}:{r['line']}", "external": True,
                             "technique": s["technique"]})
                break
    seen = set()
    out = []
    for h in sorted(hops, key=lambda h: h["ts"]):
        k = (h["from"], h["to"])
        if k not in seen:
            seen.add(k)
            out.append(h)
    return out


def build_path(steps: list[dict], hops: list[dict]) -> list[str]:
    internal_hops = [h for h in hops if not h.get("external")]
    if not steps:
        return []
    start = steps[0]["host"]
    if internal_hops and internal_hops[0]["from"] != start and not any(s["host"] == internal_hops[0]["from"]
                                                                       for s in steps[:1]):
        # the earliest hop's source counts as the start if it appears in the incident before the hop
        if any(s["host"] == internal_hops[0]["from"] and s["ts"] <= internal_hops[0]["ts"] for s in steps):
            start = internal_hops[0]["from"]
    path = [start] if start else []
    for h in internal_hops:
        if h["from"] not in path:
            path.append(h["from"])
        if not path or path[-1] != h["to"]:
            if h["to"] not in path:
                path.append(h["to"])
    for s in steps:                                       # hosts touched without an observed hop
        if s["host"] and s["host"] not in path:
            path.append(s["host"])
    return path


def blast_radius(steps: list[dict], nodes: list[Node]) -> dict:
    users, hosts, files, ext = set(), set(), set(), set()
    for s in steps:
        for r in s["_rows"]:
            if r.get("user") and not is_system_account(r["user"]):
                users.add(r["user"])
            if r.get("target_user"):
                users.add(r["target_user"])
            if r.get("host"):
                hosts.add(r["host"])
            t = r.get("target") or ""
            if r.get("event_type") in ("win:5140", "win:5145", "sysmon:11", "audit:write", "audit:read") and t:
                files.add(t)
            for ip in (r.get("src_ip"), r.get("dst_ip")):
                if is_external(ip):
                    ext.add(ip)
    return {"users": sorted(users), "hosts": sorted(hosts), "files_and_shares": sorted(files)[:200],
            "external_ips": sorted(ext)}


def excluded_lookalikes(inc_nodes: set[str], all_nodes: dict[str, Node], steps: list[dict],
                        attribution: dict[str, str], member_of: dict[str, int]) -> list[dict]:
    """Hits that look like this incident's techniques but have no evidence link to it."""
    if not steps:
        return []
    techs = {s["technique"] for s in steps}
    lo, hi = steps[0]["ts"] - 6 * 3_600_000, steps[-1]["ts"] + 6 * 3_600_000
    out = []
    for k, n in all_nodes.items():
        if k in inc_nodes or n.technique not in techs or n.severity < 0.4 or not (lo <= n.ts <= hi):
            continue
        reason = attribution.get(k) or "same technique, but no process, session, account or host link to this incident"
        users = sorted(n.users) or sorted(n.vals("user"))
        out.append({"evidence": n.evidence[:20], "technique": n.technique, "host": next(iter(sorted(n.hosts)), None),
                    "user": users[0] if users else None, "rule": n.rule_id,
                    "reason": reason, "other_cluster": member_of.get(k)})
    return out[:50]
