"""What the attacker could reach next (FR-6), as reachability on a privilege graph (NetworkX).

Directed graph built once per run from the logs alone (no AD query):
  host:H    -> account:A   'exposed'   A logged on interactively to H (its credentials can be stolen there)
  account:A -> host:H      'admin'     A was seen with admin rights on H (4672, sudo, root login)
  account:A -> host:H      'group'     A was added to a domain-wide admin group (all servers)
  host:H    -> host:J      'network'   H already reached J over SMB/RDP/SSH/WinRM (reported, not chained)
Every edge carries the time it was first observed; an incident only uses edges seen before it ended.
From the compromised set (touched hosts + accounts the attacker used/created) the shortest credential
chains to untouched hosts are the look-ahead, ranked by host criticality, each with its chain as the reason.
"""
from __future__ import annotations

import duckdb
import networkx as nx

from ..entities.resolve import is_system_account
from .privmap import ADMIN_PORTS

MAX_CHAIN = 6          # graph hops: host -> account -> host -> account -> host -> account -> host


def build_graph(con: duckdb.DuckDBPyConnection, hosts_info: dict) -> nx.DiGraph:
    g = nx.DiGraph()

    def edge(a, b, kind, ts, n=1, how=""):
        if g.has_edge(a, b):
            d = g[a][b]
            d["first_ts"] = min(d["first_ts"], ts)
            d["n"] += n
        else:
            g.add_edge(a, b, kind=kind, first_ts=ts, n=n, how=how)

    for acct, host, ts, n in con.execute(
            "SELECT account, host, min(ts), count(*) FROM interactive_logons GROUP BY ALL").fetchall():
        edge(f"host:{host}", f"account:{acct}", "exposed", ts, n, "interactive logon")
    for acct, host, ts, n, how in con.execute(
            "SELECT account, host, min(first_ts), sum(n), min(how) FROM priv_admin GROUP BY account, host").fetchall():
        edge(f"account:{acct}", f"host:{host}", "admin", ts, int(n), how)
    servers = [h for h, v in hosts_info.items() if v["role"] not in ("workstation", "unknown")]
    for acct, grp, ts in con.execute(
            "SELECT account, \"group\", min(ts) FROM priv_groups WHERE lower(\"group\") IN "
            "('domain admins','enterprise admins') GROUP BY ALL").fetchall():
        for h in servers:
            edge(f"account:{acct}", f"host:{h}", "group", ts, 1, f"member of {grp}")
    ports = ",".join(str(p) for p in ADMIN_PORTS)
    for src, dst, ts, n in con.execute(f"""
            SELECT host_of(src_ip, ts) AS s, host_of(dst_ip, ts) AS d, min(ts), count(*) FROM events
            WHERE event_type IN ('net:flow','zeek:conn','sysmon:3') AND dst_port IN ({ports})
              AND is_internal(src_ip) AND is_internal(dst_ip)
              AND coalesce(lower(action), 'allow') NOT IN ('deny','drop','block','blocked','reject')
            GROUP BY 1, 2""").fetchall():
        if src and dst and src != dst:
            edge(f"host:{src}", f"host:{dst}", "network", ts, n, "admin-protocol connection")
    for n in g.nodes:
        kind, name = n.split(":", 1)
        g.nodes[n]["kind"] = kind
        g.nodes[n]["name"] = name
        if kind == "host":
            g.nodes[n]["criticality"] = hosts_info.get(name, {}).get("criticality", 0.4)
            g.nodes[n]["role"] = hosts_info.get(name, {}).get("role", "unknown")
    return g


def _describe(g: nx.DiGraph, chain: list[str]) -> str:
    parts = []
    for a, b in zip(chain, chain[1:]):
        k = g[a][b]["kind"]
        an, bn = a.split(":", 1)[1], b.split(":", 1)[1]
        if k == "exposed":
            parts.append(f"{bn}'s credentials were exposed on {an}")
        elif k == "admin":
            parts.append(f"{an} has observed admin access on {bn} ({g[a][b]['how']})")
        elif k == "group":
            parts.append(f"{an} is a domain-wide admin ({g[a][b]['how']}), which includes {bn}")
    return "; ".join(parts)


def look_ahead(g: nx.DiGraph, steps: list[dict], path: list[str], hosts_info: dict) -> tuple[list[dict], dict]:
    if not steps:
        return [], {}
    t_end = max(s["ts"] for s in steps)
    touched = {s["host"] for s in steps if s.get("host")} | set(path)
    used = set()
    for s in steps:
        for r in s["_rows"]:
            for u in (r.get("user"), r.get("target_user")):
                if u and not is_system_account(u):
                    used.add(u)
    sources = [f"host:{h}" for h in touched if g.has_node(f"host:{h}")] + \
              [f"account:{a}" for a in used if g.has_node(f"account:{a}")]
    if not sources:
        return [], {"potential_hosts": [], "at_risk_accounts": sorted(used), "chains": []}

    # credential graph as of the end of the incident (network edges are not chained)
    view = nx.subgraph_view(g, filter_edge=lambda a, b: g[a][b]["first_ts"] <= t_end and g[a][b]["kind"] != "network")
    work = nx.DiGraph(view)
    work.add_node("__attacker__")
    for s in sources:
        work.add_edge("__attacker__", s)
    paths = nx.single_source_shortest_path(work, "__attacker__", cutoff=MAX_CHAIN + 1)

    crit = {h: v["criticality"] for h, v in hosts_info.items()}
    # every at-risk account (reachable through stolen/exposed credentials) and everything it unlocks:
    # chain = how the attacker gets the credential + the admin edge it opens
    chains = []
    at_risk = set(used)
    for node, p in paths.items():
        if not node.startswith("account:"):
            continue
        acct = node.split(":", 1)[1]
        at_risk.add(acct)
        for _, tgt, d in work.out_edges(node, data=True):
            host = tgt.split(":", 1)[1]
            if not tgt.startswith("host:") or host in touched:
                continue
            chain = p[1:] + [tgt]
            chains.append({"target": host, "criticality": crit.get(host, 0.4),
                           "role": hosts_info.get(host, {}).get("role"), "pivot_account": acct,
                           "chain": [c.split(":", 1)[1] for c in chain], "hops": len(chain) - 1,
                           "why": _describe(g, chain)})
    chains.sort(key=lambda c: (-c["criticality"], c["hops"], c["target"]))

    # group by pivot account (the credential the attacker would use)
    by_acct: dict[str, list[dict]] = {}
    for c in chains:
        by_acct.setdefault(c["pivot_account"] or "(unknown)", []).append(c)
    out = []
    for acct, cs in by_acct.items():
        first = cs[0]
        exposed_on = [first["chain"][i - 1] for i, x in enumerate(first["chain"]) if x == acct and i > 0]
        if acct in used:
            why = f"{acct} is already controlled by the attacker. {first['why']}"
        else:
            why = first["why"]
        out.append({"account": acct, "can_reach": [c["target"] for c in cs][:25], "why": why,
                    "kind": "observed admin access", "exposed_on": exposed_on,
                    "max_criticality": max(c["criticality"] for c in cs), "shortest_hops": min(c["hops"] for c in cs)})

    # one-hop network reach from compromised hosts (credentials still needed)
    net = set()
    for h in touched:
        n = f"host:{h}"
        if g.has_node(n):
            for _, d, data in g.out_edges(n, data=True):
                if data["kind"] == "network" and data["first_ts"] <= t_end:
                    t = d.split(":", 1)[1]
                    if t not in touched:
                        net.add(t)
    if net:
        nr = sorted(net, key=lambda h: (-crit.get(h, 0.4), h))
        out.append({"account": "(network)", "can_reach": nr[:25], "kind": "observed network reach",
                    "why": "compromised hosts already connected to these over SMB/RDP/SSH/WinRM; credentials still needed",
                    "exposed_on": [], "max_criticality": crit.get(nr[0], 0.4), "shortest_hops": 1})
    out.sort(key=lambda x: (-x["max_criticality"], x["shortest_hops"], -len(x["can_reach"])))
    potential = sorted({c["target"] for c in chains} | net, key=lambda h: -crit.get(h, 0.4))
    return out, {"potential_hosts": potential, "at_risk_accounts": sorted(at_risk), "chains": chains[:50]}
