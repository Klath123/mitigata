"""Export the run as one property graph: GraphML (Gephi / yEd / NetworkX) and Neo4j CSV + load.cypher.

Nodes: Incident, Step, Host, Account, ExternalIP, Technique, Indicator
Relationships:
  (Incident)-[:HAS_STEP]->(Step)          (Step)-[:NEXT]->(Step)            (Step)-[:LINKED {confidence}]->(Step)
  (Step)-[:ON_HOST]->(Host)               (Step)-[:BY_ACCOUNT]->(Account)   (Host)-[:LOGON {user,time}]->(Host)
  (ExternalIP)-[:LOGON]->(Host)           (Incident)-[:HAS_INDICATOR]->(Indicator)
  (Incident)-[:COULD_REACH {via}]->(Host)
  privilege map: (Host)-[:EXPOSES]->(Account)  (Account)-[:ADMIN_ON]->(Host)  (Account)-[:DOMAIN_ADMIN_ON]->(Host)
                 (Host)-[:NETWORK_REACH]->(Host)
The engine never needs Neo4j; this is for analysts and demos (docker compose --profile neo4j up).
"""
from __future__ import annotations

import csv
import json
import os

import networkx as nx

PRIV_REL = {"exposed": "EXPOSES", "admin": "ADMIN_ON", "group": "DOMAIN_ADMIN_ON", "network": "NETWORK_REACH"}


def build(incidents: list[dict], reach_g: nx.DiGraph | None) -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()

    def node(nid, label, **props):
        if nid in g:
            g.nodes[nid].update({k: v for k, v in props.items() if v not in (None, "")})
        else:
            g.add_node(nid, label=label, **props)

    for inc in incidents:
        iid = inc["incident_id"]
        inode = f"incident:{iid}"
        node(inode, "Incident", name=f"Incident {iid}", risk=inc["risk"], verdict=inc["verdict"],
             first_seen=inc.get("first_seen", ""), last_seen=inc.get("last_seen", ""),
             path=" -> ".join(inc.get("path", [])), alerts_merged=inc.get("alerts_merged", 0))
        prev = None
        for s in inc["steps"]:
            sid = f"step:{iid}:{s['order']}"
            node(sid, "Step", name=f"{s.get('sub_technique') or s['technique']} {s.get('technique_name') or ''}".strip(),
                 order=s["order"], time=s["time"], technique=s["technique"], sub_technique=s.get("sub_technique") or "",
                 stage=s["stage"], summary=s["summary"][:300], evidence=";".join(s["evidence"][:20]),
                 label_source=s.get("label_source", ""))
            g.add_edge(inode, sid, type="HAS_STEP")
            if s.get("host"):
                node(f"host:{s['host']}", "Host", name=s["host"])
                g.add_edge(sid, f"host:{s['host']}", type="ON_HOST")
            if s.get("user"):
                node(f"account:{s['user']}", "Account", name=s["user"])
                g.add_edge(sid, f"account:{s['user']}", type="BY_ACCOUNT")
            # ATT&CK techniques as shared nodes: incidents that used the same technique meet there
            for lab in [s] + s.get("also", []):
                tid = lab.get("sub_technique") or lab.get("technique")
                if tid:
                    node(f"technique:{tid}", "Technique", name=f"{tid} {lab.get('technique_name') or ''}".strip(),
                         technique=tid, stage=lab.get("stage", ""))
                    g.add_edge(sid, f"technique:{tid}", type="USES")
            if prev:
                g.add_edge(prev, sid, type="NEXT")
            prev = sid
        for e in inc.get("graph", {}).get("edges", []):
            if e.get("kind") == "evidence":
                a = f"step:{iid}:{e['src'][4:]}"
                b = f"step:{iid}:{e['dst'][4:]}"
                g.add_edge(a, b, type="LINKED", confidence=e["confidence"], reasons=",".join(e.get("reasons", [])),
                           inferred=bool(e.get("inferred")))
        for h in inc.get("hops", []):
            src = f"ip:{h['from']}" if h.get("external") else f"host:{h['from']}"
            node(src, "ExternalIP" if h.get("external") else "Host", name=h["from"])
            node(f"host:{h['to']}", "Host", name=h["to"])
            g.add_edge(src, f"host:{h['to']}", type="LOGON", user=h.get("user") or "", time=h["time"],
                       evidence=h["evidence"], incident=iid)
        # internet addresses the incident's activity came from or went to (firewall-only data has no logon hops)
        for ip in (inc.get("blast_radius") or {}).get("confirmed", {}).get("external_ips", []):
            node(f"ip:{ip}", "ExternalIP", name=ip)
            g.add_edge(inode, f"ip:{ip}", type="INVOLVES_ADDRESS")
        for ind in inc.get("indicators", []):
            nid = f"ioc:{ind['type']}:{ind['value']}"
            node(nid, "Indicator", name=str(ind["value"])[:200], kind=ind["type"])
            g.add_edge(inode, nid, type="HAS_INDICATOR", hits=ind["hits"], hosts=ind["hosts"])
        for la in inc.get("look_ahead", []):
            for h in la["can_reach"]:
                node(f"host:{h}", "Host", name=h)
                g.add_edge(inode, f"host:{h}", type="COULD_REACH", via=la["account"], why=la["why"][:300])
    if reach_g is not None:
        for n, d in reach_g.nodes(data=True):
            node(n, "Host" if d.get("kind") == "host" else "Account", name=d.get("name", n.split(":", 1)[1]),
                 role=d.get("role", ""), criticality=d.get("criticality", ""))
        for a, b, d in reach_g.edges(data=True):
            g.add_edge(a, b, type=PRIV_REL[d["kind"]], first_ts=d["first_ts"], count=d["n"], how=d.get("how", ""))
    return g


def _clean(v):
    if v is None:
        return ""
    if isinstance(v, (list, tuple, set)):
        return ";".join(map(str, v))
    if isinstance(v, (str, int, float, bool)):
        return v
    return str(v)


def write(run_dir: str, g: nx.MultiDiGraph) -> dict:
    out = os.path.join(run_dir, "graph")
    neo = os.path.join(out, "neo4j")
    os.makedirs(neo, exist_ok=True)
    gg = nx.MultiDiGraph()
    for n, d in g.nodes(data=True):
        gg.add_node(n, **{k: _clean(v) for k, v in d.items()})
    for a, b, d in g.edges(data=True):
        gg.add_edge(a, b, **{k: _clean(v) for k, v in d.items()})
    nx.write_graphml(gg, os.path.join(out, "attackstory.graphml"))
    # the same graph for the UI (GET /graph): plain nodes + edges
    with open(os.path.join(out, "graph.json"), "w", encoding="utf-8") as f:
        json.dump({"nodes": [{"id": n, **d} for n, d in gg.nodes(data=True)],
                   "edges": [{"source": a, "target": b, **d} for a, b, d in gg.edges(data=True)]}, f, default=str)

    # Neo4j: one CSV per label / relationship type (LOAD CSV needs static labels without APOC)
    by_label: dict[str, list] = {}
    for n, d in gg.nodes(data=True):
        by_label.setdefault(d.get("label", "Node"), []).append((n, d))
    by_type: dict[str, list] = {}
    for a, b, d in gg.edges(data=True):
        by_type.setdefault(d.get("type", "REL"), []).append((a, b, d))
    cypher = ["// Load with: cypher-shell -u neo4j -p <password> -f load.cypher  (files in Neo4j's import dir)",
              "CREATE CONSTRAINT entity_id IF NOT EXISTS FOR (n:Entity) REQUIRE n.id IS UNIQUE;"]
    for label, items in by_label.items():
        cols = sorted({k for _, d in items for k in d if k != "label"})
        fn = f"nodes_{label}.csv"
        with open(os.path.join(neo, fn), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["id"] + cols)
            for n, d in items:
                w.writerow([n] + [d.get(c, "") for c in cols])
        sets = ", ".join([f"n:{label}"] + [f"n.{c} = row.{c}" for c in cols])
        cypher.append(f"LOAD CSV WITH HEADERS FROM 'file:///{fn}' AS row MERGE (n:Entity {{id: row.id}}) SET {sets};")
    for rtype, items in by_type.items():
        cols = sorted({k for _, _, d in items for k in d if k != "type"})
        fn = f"rels_{rtype}.csv"
        with open(os.path.join(neo, fn), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["start", "end"] + cols)
            for a, b, d in items:
                w.writerow([a, b] + [d.get(c, "") for c in cols])
        sets = ", ".join(f"r.{c} = row.{c}" for c in cols)
        cypher.append(f"LOAD CSV WITH HEADERS FROM 'file:///{fn}' AS row MATCH (a:Entity {{id: row.start}}), "
                      f"(b:Entity {{id: row.end}}) CREATE (a)-[r:{rtype}]->(b)" + (f" SET {sets};" if sets else ";"))
    cypher += [
        "// Example queries:",
        "// MATCH (i:Incident)-[:HAS_STEP]->(s:Step)-[:ON_HOST]->(h:Host) RETURN i, s, h ORDER BY s.order;",
        "// MATCH p = (a:Host {name:'WS-HR-015'})-[:EXPOSES|ADMIN_ON*..4]->(dc:Host {role:'dc'}) RETURN p LIMIT 5;",
    ]
    with open(os.path.join(neo, "load.cypher"), "w", encoding="utf-8") as f:
        f.write("\n".join(cypher) + "\n")
    return {"nodes": gg.number_of_nodes(), "edges": gg.number_of_edges(), "labels": sorted(by_label),
            "relationship_types": sorted(by_type)}
