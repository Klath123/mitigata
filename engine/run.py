"""AttackStory pipeline: raw logs -> ranked incidents with paths, look-ahead and reports.

python -m engine.run <dataset_dir> --out results/<run> [--workers N] [--memory 6GB] [--no-llm]
"""
from __future__ import annotations

import argparse
import json
import os
import threading
import time
from collections import defaultdict

import psutil

from .attack import navigator
from .cluster.score import (REPORT, REVIEW, blast_radius, build_hops, build_path, build_steps, excluded_lookalikes,
                            iso, score)
from .entities.resolve import IpResolver, build_hosts, build_ip_map
from .graph.build import Linker, components, load_nodes, to_networkx
from .graph.confidence import POSSIBLE, SOLID, noisy_or
from .graph import export as graph_export
from .graph.gaps import crosses, find_gaps, host_rates
from .graph.tracer import corroborate, trace
from .hunt import hayabusa
from .hunt.rules import HIT_COLS, load_macros, run_rules
from .ingest.to_parquet import ingest
from .lookahead import privmap
from .lookahead.reach import build_graph as build_reach_graph, look_ahead
import networkx as nx
from . import quality
from .narrate import checker, guard, llm, template
from .results import manifest, store
from .store.db import connect, set_dataset_vars


class PeakMemory:
    """Samples RSS of this process and its children (the ingest pool) every 0.2 s."""

    def __init__(self):
        self.peak = 0
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        me = psutil.Process()
        while not self._stop.is_set():
            try:
                rss = me.memory_info().rss + sum(c.memory_info().rss for c in me.children(recursive=True))
                self.peak = max(self.peak, rss)
            except psutil.Error:
                pass
            self._stop.wait(0.2)

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *a):
        self._stop.set()
        self._t.join()


def _strip(step: dict) -> dict:
    return {k: v for k, v in step.items() if not k.startswith("_")}


def key_entities(sub: nx.Graph, nodes) -> dict:
    """Which hosts/accounts hold the incident together: entity graph (hit -- host, hit -- account),
    ranked by betweenness centrality (degree as tie-break)."""
    eg = nx.Graph()
    for k in sub.nodes:
        n = nodes[k]
        for h in n.hosts:
            eg.add_edge(k, f"host:{h}")
        for u in n.users:
            eg.add_edge(k, f"account:{u}")
    for a, b in sub.edges:
        eg.add_edge(a, b)
    if eg.number_of_nodes() > 3000:
        bc = nx.betweenness_centrality(eg, k=300, seed=0)
    else:
        bc = nx.betweenness_centrality(eg)
    deg = dict(eg.degree())
    out = {"hosts": [], "accounts": []}
    for node in sorted((x for x in eg.nodes if ":" in x and x.split(":", 1)[0] in ("host", "account")),
                       key=lambda x: (-bc.get(x, 0), -deg.get(x, 0))):
        kind, name = node.split(":", 1)
        lst = out["hosts" if kind == "host" else "accounts"]
        if len(lst) < 8:
            lst.append({"name": name, "centrality": round(bc.get(node, 0), 4), "hits": deg.get(node, 0)})
    return out


def build_incidents(con, log=print, use_llm: bool = True, q: dict | None = None) -> tuple[list[dict], list[dict], dict]:
    resolver = IpResolver(con)
    hosts_info = build_hosts(con)
    nodes = load_nodes(con, resolver)
    linker = Linker(nodes, con)
    edges = linker.link_all()
    g = to_networkx(nodes, edges, linker.reasons, POSSIBLE)
    comps = components(g)
    log(f"  graph: {g.number_of_nodes()} hits, {g.number_of_edges()} links, {len(comps)} clusters")

    ip_of_host: dict[str, list[str]] = defaultdict(list)
    for ip, segs in resolver.segs.items():
        for _, _, h in segs:
            if ip not in ip_of_host[h]:
                ip_of_host[h].append(ip)
    rates = host_rates(con)
    reach_g = build_reach_graph(con, hosts_info)
    log(f"  privilege graph: {reach_g.number_of_nodes()} hosts/accounts, {reach_g.number_of_edges()} edges")

    scored = []
    for comp in comps:
        ns = [nodes[k] for k in comp]
        steps = build_steps(ns)
        S, br = score(ns, [s["stage"] for s in steps])
        scored.append((S, br, comp, steps))
    scored.sort(key=lambda x: -x[0])
    member_of = {}
    cid = 0
    candidates = []
    for S, br, comp, steps in scored:
        if S < REVIEW:
            continue
        cid += 1
        for k in comp:
            member_of[k] = cid
        candidates.append((cid, S, br, comp, steps))

    incidents, review = [], []
    for cid, S, br, comp, steps in candidates:
        ns = [nodes[k] for k in comp]
        hops = build_hops(steps)
        path = build_path(steps, hops)
        inc = {"incident_id": cid, "risk": S, "verdict": "attack" if S >= REPORT else "review",
               "score_breakdown": br, "alerts_merged": sum(len(n.rows) for n in ns),
               "hits_merged": len(ns),
               "stages": list(dict.fromkeys(s["stage"] for s in steps)),
               "first_seen": steps[0]["time"] if steps else "", "last_seen": steps[-1]["time"] if steps else "",
               "path": path, "hops": [{k: v for k, v in h.items() if k != "ts"} for h in hops],
               "report_url": f"/incidents/{cid}/report"}
        # gaps
        lo, hi = steps[0]["ts"], steps[-1]["ts"]
        gaps = find_gaps(con, sorted({s["host"] for s in steps if s["host"]}), lo, hi, rates)
        inc["gaps"] = [{"host": g["host"], "start": iso(g["start_ts"]), "end": iso(g["end_ts"]),
                        "expected_events": g["expected_events"], "crosses_edges": []} for g in gaps]
        # step-level graph: nodes = steps + hosts + accounts + external IPs; edges with confidence
        node_step = {}
        for s in steps:
            for k in s["_nodes"]:
                node_step[k] = s["order"]
        pair: dict[tuple[int, int], list[float]] = defaultdict(list)
        why: dict[tuple[int, int], set] = defaultdict(set)
        for (a, b), c in edges.items():
            if a in node_step and b in node_step and node_step[a] != node_step[b] and c >= POSSIBLE:
                x, y = sorted((node_step[a], node_step[b]))
                pair[(x, y)].append(c)
                why[(x, y)].update(linker.reasons[(a, b) if (a, b) in linker.reasons else (b, a)].keys())
        st = {s["order"]: s for s in steps}
        g_edges = []
        for (x, y), cs in pair.items():
            c = round(min(1.0, max(cs) if len(cs) == 1 else noisy_or(cs[:3])), 3)
            inferred = crosses(gaps, st[x]["host"], st[x]["ts"], st[y]["host"], st[y]["ts"])
            e = {"src": f"step{x}", "dst": f"step{y}", "kind": "evidence", "confidence": c,
                 "style": "solid" if c >= SOLID else "dashed", "reasons": sorted(why[(x, y)]), "inferred": inferred}
            g_edges.append(e)
            if inferred:
                for gg in inc["gaps"]:
                    gg["crosses_edges"].append(f"step{x}->step{y}")
        g_nodes = [{"id": f"step{s['order']}", "type": "step", "label": s.get("sub_technique") or s["technique"],
                    "stage": s["stage"], "host": s["host"], "user": s["user"], "time": s["time"]} for s in steps]
        for h in sorted({s["host"] for s in steps if s["host"]} | set(path)):
            g_nodes.append({"id": f"host:{h}", "type": "host", "label": h,
                            "role": hosts_info.get(h, {}).get("role", "external" if "." in h else "unknown")})
        for hp in hops:
            g_edges.append({"src": f"host:{hp['from']}", "dst": f"host:{hp['to']}", "kind": "logon",
                            "user": hp["user"], "time": hp["time"], "confidence": 0.8, "style": "solid",
                            "evidence": hp["evidence"]})
            if hp.get("external") and not any(n["id"] == f"host:{hp['from']}" for n in g_nodes):
                g_nodes.append({"id": f"host:{hp['from']}", "type": "external", "label": hp["from"]})
        # tracer context
        ctx = trace(con, steps, hops, {h: ips[-1] for h, ips in ip_of_host.items()})
        inc["corroborating_events"] = corroborate(con, steps, {h: ips[-1] for h, ips in ip_of_host.items()})
        for r in ctx[:150]:
            g_nodes.append({"id": f"ctx:{r['evidence']}", "type": "context", "label": r["event_type"],
                            "host": r["host"], "time": iso(r["ts"]), "why": r["why"], "evidence": r["evidence"]})
        inc["graph"] = {"nodes": g_nodes, "edges": g_edges}
        inc["context_events"] = [{"evidence": r["evidence"], "time": iso(r["ts"]), "host": r["host"],
                                  "event_type": r["event_type"], "why": r["why"],
                                  "summary": (r.get("cmdline") or r.get("target") or r.get("process") or "")[:200]}
                                 for r in ctx]
        # look-ahead, blast radius, exclusions, injection flags
        la, potential = look_ahead(reach_g, steps, path, hosts_info)
        inc["look_ahead"] = la
        inc["blast_radius"] = {"confirmed": blast_radius(steps, ns), "potential": potential}
        inc["excluded"] = excluded_lookalikes(comp, nodes, steps, linker.attribution, member_of)
        rows = [r for s in steps for r in s["_rows"]]
        inc["injection_flags"] = guard.scan_rows(rows)
        # campaign indicators shared by this incident's hits (what to block / hunt for)
        inds = []
        for (kind, val), members in getattr(linker, "iocs", {}).items():
            inside = [m for m in members if m in comp]
            if len(inside) >= 2:
                hosts_ = sorted(set().union(*(nodes[m].hosts for m in inside)))
                inds.append({"type": kind, "value": val, "hits": len(inside), "hosts": len(hosts_),
                             "host_list": hosts_[:50]})
        inc["indicators"] = sorted(inds, key=lambda x: (-x["hosts"], -x["hits"]))[:50]
        inc["key_entities"] = key_entities(g.subgraph(comp), nodes)
        inc["data_quality"] = quality.for_incident(q or {}, steps, inc["gaps"])
        # narration: template always; LLM if available, checked by code
        story = checker.Story(steps)
        tmpl = template.narrate(inc, steps)
        t_ok = [s for s in tmpl if s.get("unchecked_entities") and all(c in story.rows for c in s["citations"])]
        t_chk, t_drop = checker.check([s for s in tmpl if not s.get("unchecked_entities")], story)
        report, source, dropped = t_chk + t_ok, "template", t_drop
        if use_llm and S >= REPORT:
            for attempt in range(2):
                sents = llm.narrate(inc, steps)
                if not sents:
                    break
                ok, bad = checker.check(sents, story)
                if len(bad) <= 0.2 * len(sents):
                    report, source, dropped = ok, f"llm:{llm.MODEL}", bad
                    break
        inc["report"] = sorted(report, key=lambda s: ["summary", "timeline", "movement", "impact", "look_ahead",
                                                      "gaps", "recommendations"].index(s.get("section", "timeline"))
                               if s.get("section", "timeline") in ("summary", "timeline", "movement", "impact",
                                                                    "look_ahead", "gaps", "recommendations") else 9)
        inc["report_source"] = source
        inc["report_dropped"] = dropped
        inc["grounding_rate"] = round(1 - len(dropped) / max(1, len(report) + len(dropped)), 3)
        inc["steps"] = [_strip(s) for s in steps]
        inc["navigator_layer"] = navigator.layer(inc)
        (incidents if inc["verdict"] == "attack" else review).append(inc)
    counts = {"hits": len(nodes), "raw_hit_rows": sum(len(n.rows) for n in nodes.values()), "clusters": len(comps),
              "attack_incidents": len(incidents), "review_incidents": len(review),
              "excluded_clusters": len(comps) - len(candidates),
              "privilege_graph": {"nodes": reach_g.number_of_nodes(), "edges": reach_g.number_of_edges()}}
    return incidents, review, counts, reach_g


def run(dataset: str, out: str, workers: int | None = None, memory: str = "6GB", use_llm: bool = True,
        skip_ingest: bool = False, log=print, hash_full: bool = False) -> dict:
    os.makedirs(out, exist_ok=True)
    stages = {}
    t_all = time.time()
    with PeakMemory() as pm:
        t = time.time()
        if skip_ingest and os.path.isdir(os.path.join(out, "events")):
            with open(os.path.join(out, "ingest_report.json")) as f:
                rep = json.load(f)
        else:
            log("[1/6] ingest")
            rep = ingest(dataset, out, workers=workers, log=log)
        stages["ingest"] = round(time.time() - t, 2)
        t = time.time()
        hb_alerts = hayabusa.run(dataset, out, log=log)      # Windows-log detector, when installed
        stages["hayabusa"] = round(time.time() - t, 2)
        log(f"  {rep['rows']:,} events from {len(rep['files'])} files, {rep['bytes'] / 2**20:.0f} MB, "
            f"{rep['unparsed']} unparsed")

        t = time.time()
        log("[2/6] store + entities")
        db_path = os.path.join(out, "engine.duckdb")
        if os.path.exists(db_path):
            os.remove(db_path)
        con = connect(out, memory_limit=memory)
        dvars = set_dataset_vars(con)
        n_ip = build_ip_map(con)
        build_hosts(con)
        load_macros(con)
        privmap.build(con)
        stages["entities"] = round(time.time() - t, 2)
        log(f"  {n_ip} IPs resolved over time")

        t = time.time()
        q = quality.compute(con, rep)
        quality.write(out, q)
        stages["data_quality"] = round(time.time() - t, 2)
        qs = q["summary"]
        log(f"  data quality {q['quality_score']}/100: {qs['successfully_parsed']:,}/{qs['total_records']:,} parsed, "
            f"{qs['records_excluded_from_detection']:,} excluded, {qs['duplicate_records']:,} duplicates, "
            f"{qs['late_arriving_events']:,} late, {qs['unknown_event_types']:,} unknown types")
        for w in q["warnings"]:
            log(f"  ! [{w['level']}] {w['text']}")

        t = time.time()
        log("[3/6] hunt")
        rule_stats = run_rules(con, log=log, extra=(lambda c: hayabusa.load_hits(c, hb_alerts, dataset, HIT_COLS, log))
                               if hb_alerts else None)
        quality.add_disabled(q, rule_stats)
        quality.write(out, q)
        stages["detection"] = round(time.time() - t, 2)
        n_hits = con.execute("SELECT count(*) FROM hits").fetchone()[0]
        log(f"  {n_hits} hit rows from {len(rule_stats)} rules")

        t = time.time()
        log("[4/6] correlate, trace, look-ahead, narrate")
        incidents, review, counts, reach_g = build_incidents(con, log=log, use_llm=use_llm, q=q)
        graph_info = graph_export.write(out, graph_export.build(incidents + review, reach_g))
        counts["export_graph"] = graph_info
        counts["evidence_indexed"] = store.write_evidence_index(con, out, incidents + review)
        log(f"  graph export: {graph_info['nodes']} nodes, {graph_info['edges']} relationships -> graph/")
        stages["correlation_and_reports"] = round(time.time() - t, 2)
        con.close()

        seconds = round(time.time() - t_all, 2)
    stats = {"dataset": os.path.basename(os.path.abspath(dataset)),
             "processed": {"bytes": rep["bytes"], "events": rep["rows"], "seconds": seconds,
                           "peak_memory_gb": round(pm.peak / 2**30, 3), "unparsed": rep["unparsed"],
                           "mb_per_s": round(rep["bytes"] / 2**20 / max(seconds, 1e-6), 2)},
             "stages_seconds": stages, "counts": counts,
             "data_quality": {"score": q["quality_score"], **q["summary"], "warnings": q["warnings"]}, "rules": rule_stats, "time_bounds": dvars,
             "files": {k: {"format": v["format"], "rows": v["rows"], "unparsed": v["unparsed"]}
                       for k, v in rep["files"].items()}}
    summary = {"dataset": stats["dataset"], "processed": stats["processed"]}
    log("[5/6] write results")
    store.write(out, summary, incidents, review, stats)
    man = manifest.write(out, dataset, t_all, time.time(), rep, stats, full_hash=hash_full)
    log(f"  run manifest: run {man['run_id'][:8]}, engine {str(man['engine']['git_commit'])[:8]}"
        f"{' +uncommitted changes' if man['engine']['uncommitted_changes'] else ''}, config {man['config']['sha256'][:12]}, "
        f"{len(man['inputs'])} input files hashed ({'full' if hash_full else 'fast'})")
    log(f"[6/6] done in {seconds}s, peak memory {stats['processed']['peak_memory_gb']} GB: "
        f"{len(incidents)} attack incident(s), {len(review)} for review")
    for i in incidents:
        log(f"  #{i['incident_id']} risk {i['risk']}  {' -> '.join(i['path'])}  {len(i['steps'])} steps  "
            f"{i['alerts_merged']} alerts merged")
    return stats


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("dataset")
    p.add_argument("--out", required=True)
    p.add_argument("--workers", type=int)
    p.add_argument("--memory", default="6GB")
    p.add_argument("--no-llm", action="store_true")
    p.add_argument("--skip-ingest", action="store_true", help="reuse existing Parquet in --out")
    p.add_argument("--hash-full", action="store_true", help="full SHA-256 of every input file in run_manifest.json")
    a = p.parse_args(argv)
    run(a.dataset, a.out, a.workers, a.memory, not a.no_llm, a.skip_ingest, hash_full=a.hash_full)


if __name__ == "__main__":
    main()
