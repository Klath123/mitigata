"""Cluster risk score and incident assembly (steps, hops, path, blast radius, excluded lookalikes).

S = 0.35*T/Tmax + 0.20*O + 0.15*min(H,3)/3 + 0.20*V + 0.10*R
T distinct tactics, O kill-chain order share, H hosts, V max severity, R mean rarity.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from ..attack import stix
from ..attack.killchain import choose_stage, order_score
from ..entities.resolve import is_external, is_internal, is_network_device, is_system_account
from ..graph.build import Node
from ..schema import TACTIC_INDEX

T_MAX = 6
STEP_GAP = 15 * 60_000
REPORT = 0.7
REVIEW = 0.4
SEVERITY_REVIEW = 0.75       # "high": enough on its own to reach review, never the attack list
HOP_TECH = {"T1021", "T1078"}


def iso(ts: int | None) -> str:
    if ts is None:
        return ""
    return datetime.fromtimestamp(ts / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts % 1000:03d}Z"


CRITICAL_ASSET = 0.8        # dc 1.0, firewall 0.9, file / database server 0.85, backup 0.8
ESCALATING_TACTICS = {"Defense Evasion", "Credential Access", "Impact", "Exfiltration", "Collection"}


def score(nodes: list[Node], stages: list[str], criticality: dict[str, float] | None = None) -> tuple[float, dict]:
    labelled = [n for n in nodes if n.technique]
    T = len(set(stages))
    O = order_score(stages)
    hosts = set().union(*(n.hosts for n in nodes)) if nodes else set()
    H = len(hosts)
    V = max((n.severity for n in nodes), default=0.0)
    R = sum(n.rarity for n in nodes) / len(nodes) if nodes else 0.0
    S = 0.35 * min(T, T_MAX) / T_MAX + 0.20 * O + 0.15 * min(H, 3) / 3 + 0.20 * V + 0.10 * R
    # a single tactic is never a confident incident (spec: require >=2 linked tactics). A high-severity one
    # driven from the internet (an account logging on from outside) still goes to an analyst for review:
    # often the perimeter is all the logs show. Internal single-tactic admin work stays out.
    external = V >= SEVERITY_REVIEW and any(is_external(r.get("src_ip")) for n in nodes for r in n.rows)
    cap = REPORT - 0.01 if external else REVIEW - 0.01
    if T < 2:
        S = min(S, cap)
    if len(labelled) < 2:
        S = min(S, cap)
    # escalation (outside the spec formula, reported separately): a multi-tactic chain with a high-severity step
    # on a critical asset is an attack even on one machine - a compromised DC or firewall is often the whole story
    C = max(((criticality or {}).get(h, 0.0) for h in hosts), default=0.0)
    # the severe step must be one admins do not do: execution / lateral movement / services on a server are daily
    # admin work (PsExec, remote logons), so they never escalate on their own
    severe_on_critical = any(n.severity >= SEVERITY_REVIEW and n.tactic in ESCALATING_TACTICS
                             and any((criticality or {}).get(h, 0.0) >= CRITICAL_ASSET for h in n.hosts)
                             for n in nodes)
    escalated = T >= 2 and len(labelled) >= 2 and severe_on_critical and S < REPORT
    if escalated:
        S = REPORT
    return round(S, 3), {"tactics": T, "order": round(O, 3), "hosts": H, "severity": round(V, 3),
                         "rarity": round(R, 3), "asset_criticality": round(C, 2),
                         "escalated_critical_asset": escalated}


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
        lt = f"logon type {r['logon_type']} " if r.get("logon_type") is not None else "sign-in "
        detail = f"{lt}from {r.get('src_h') or r['src_ip']}"
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
    # same-second steps: earlier kill-chain tactic first (a logon before what it was used for), then technique,
    # so the order is stable run to run and never reads backwards by accident
    def chain_pos(s):
        return min(TACTIC_INDEX.get(n.tactic, len(TACTIC_INDEX)) for n in s["_nodes"])
    for i, s in enumerate(sorted(steps, key=lambda s: (s["ts"], chain_pos(s), s["technique"])), 1):
        rows = sorted(s["_rows"], key=lambda r: (r["ts"], r["src_file"], r["line"]))
        best = max(s["_nodes"], key=lambda n: (n.severity, bool(n.sub_technique)))
        subs = Counter(n.sub_technique for n in s["_nodes"] if n.sub_technique)
        src_ip = next((r["src_ip"] for r in rows if r.get("src_ip") and r.get("event_type") in
                       ("win:4624", "auth:success")), None)
        stage = choose_stage(s["technique"], best.tactic, {"host": s["host"], "src_ip": src_ip}, first_host, seen)
        if s["host"]:
            seen.add(s["host"])
        sub = subs.most_common(1)[0][0] if subs else None
        ev = list(dict.fromkeys(f"{r['src_file']}:{r['line']}" for r in rows))    # unique, in order
        out.append({
            "order": i, "ts": s["ts"], "time": iso(s["ts"]), "host": s["host"], "user": _step_user(rows),
            "technique": s["technique"], "sub_technique": sub,
            "technique_name": stix.name(sub) or stix.name(s["technique"]), "stage": stage,
            "label_source": {"sigma": "sigma", "vendor": "vendor", "behavioural": "behavioural"}.get(best.kind, "rule"),
            "rule": ", ".join(sorted({n.rule_id for n in s["_nodes"]})),
            "summary": _summary(best, rows), "evidence": ev[:500],
            "_rows": rows, "_nodes": [n.key for n in s["_nodes"]], "_src_ip": src_ip, "_sev": best.severity,
            "_best": best,
        })
    return merge_same_evidence(out)


def _label(s: dict) -> dict:
    return {k: s.get(k) for k in ("technique", "sub_technique", "technique_name", "stage", "rule")}


def _take_lines(big: dict, lines: set) -> None:
    """Remove lines from a step and refresh what was derived from them (time, account, summary)."""
    rows = [r for r in big["_rows"] if f"{r['src_file']}:{r['line']}" not in lines]
    big["_rows"] = rows
    big["evidence"] = [e for e in big["evidence"] if e not in lines]
    big["ts"] = rows[0]["ts"]
    big["time"] = iso(big["ts"])
    big["user"] = _step_user(rows)
    big["summary"] = _summary(big["_best"], rows)


def merge_same_evidence(steps: list[dict]) -> list[dict]:
    """One log line is one step.
    1. A step whose lines all sit inside a bigger step owns them: the bigger step (a broad label grouped from
       several hits, e.g. 'access from the internet') gives them up and keeps its own lines; its label is carried on
       the smaller step in `also`.
    2. Two steps on exactly the same lines become one step with the more severe label; the other goes in `also`.
    The chain never counts one event twice, and every stage still counts for the score."""
    for small in sorted(steps, key=lambda x: len(x["evidence"])):
        ev = set(small["evidence"])
        for big in steps:
            if big is small or big["host"] != small["host"] or not ev or not ev < set(big["evidence"]):
                continue
            _take_lines(big, ev)
            small.setdefault("also", []).append(_label(big))
    out: list[dict] = []
    for s in steps:
        t = next((m for m in out if m["host"] == s["host"] and set(m["evidence"]) == set(s["evidence"])), None)
        if t is None:
            out.append(s)
            continue
        main, other = (s, t) if (s["_sev"], TACTIC_INDEX.get(s["stage"], 0)) > \
            (t["_sev"], TACTIC_INDEX.get(t["stage"], 0)) else (t, s)
        main.setdefault("also", []).extend([_label(other)] + other.get("also", []))
        main["_nodes"] = main["_nodes"] + [k for k in other["_nodes"] if k not in main["_nodes"]]
        main["rule"] = ", ".join(sorted(set(main["rule"].split(", ")) | set(other["rule"].split(", "))))
        out[out.index(t)] = main
    for s in out:                                  # a label never repeats on one step
        seen = {(s["technique"], s.get("sub_technique"))}
        s["also"] = [a for a in s.get("also", [])
                     if (a["technique"], a.get("sub_technique")) not in seen and not seen.add((a["technique"], a.get("sub_technique")))]
    out.sort(key=lambda s: (s["ts"], TACTIC_INDEX.get(s["stage"], 99), s["technique"]))   # times may have moved
    for i, s in enumerate(out, 1):
        s["order"] = i
    return out


def step_stages(steps: list[dict]) -> list[str]:
    """Every stage the steps show, including labels merged into a step (`also`), in step order."""
    return [st for s in steps for st in [s["stage"]] + [a["stage"] for a in s.get("also", [])]]


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
    users, hosts, files, ext, devices = set(), set(), set(), set(), set()
    for s in steps:
        for r in s["_rows"]:
            if r.get("user") and not is_system_account(r["user"]):
                users.add(r["user"])
            if r.get("target_user"):
                users.add(r["target_user"])
            if r.get("host"):
                hosts.add(r["host"])
            if r.get("reporter"):                 # the device that logged traffic: a firewall/sensor
                devices.add(r["reporter"])
            t = r.get("target") or ""
            if r.get("event_type") in ("win:5140", "win:5145", "sysmon:11", "audit:write", "audit:read") and t:
                files.add(t)
            for ip in (r.get("src_ip"), r.get("dst_ip")):
                if is_external(ip):
                    ext.add(ip)
    # firewalls / VPN gateways are protected (restrict admin access, review config), never isolated
    infra = sorted(h for h in hosts if h in devices or is_network_device(h))
    return {"users": sorted(users), "hosts": sorted(hosts), "infrastructure": infra,
            "files_and_shares": sorted(files)[:200], "external_ips": sorted(ext)}


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
