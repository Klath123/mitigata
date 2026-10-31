"""AttackStory API (FR-7). Serves precomputed results only: opening an incident never re-scans logs.

ATTACKSTORY_RUN=results/<run> uvicorn engine.api.app:app --port 8000
"""
from __future__ import annotations

import json
import os
import time
from collections import OrderedDict

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from ..results import store

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
UI = os.path.join(ROOT, "ui", "index.html")
DIST = os.path.join(ROOT, "frontend", "dist")  # React build (cd frontend && npm run build); falls back to ui/index.html


class Results:
    """Everything the API serves, loaded once into memory (a few MB even for a 50 GB dataset)."""

    def __init__(self, run_dir: str):
        self.run_dir = run_dir
        self.summary, self.full, self.stats = store.load(run_dir)
        ev = os.path.join(run_dir, "evidence.json")
        self.evidence = json.load(open(ev, encoding="utf-8")) if os.path.exists(ev) else {}
        self.loaded_at = time.time()

    def incident(self, iid: int) -> dict:
        inc = self.full.get(iid)
        if inc is None:
            raise HTTPException(404, f"incident {iid} not found")
        return inc


def create_app(run_dir: str | None = None) -> FastAPI:
    run_dir = run_dir or os.environ.get("ATTACKSTORY_RUN", os.path.join(ROOT, "results", "latest"))
    app = FastAPI(title="AttackStory", version="1.0",
                  description="Logs-to-incidents engine: ranked incidents, attack paths, look-ahead and reports.")
    state = {"r": None}

    def R() -> Results:
        if state["r"] is None:
            if not os.path.exists(os.path.join(run_dir, "incidents.json")):
                raise HTTPException(503, f"no results in {run_dir}; run `python -m engine.run <logs> --out {run_dir}`")
            state["r"] = Results(run_dir)
        return state["r"]

    @app.middleware("http")
    async def timing(request: Request, call_next):
        t = time.perf_counter()
        resp = await call_next(request)
        resp.headers["X-Response-Time-ms"] = f"{(time.perf_counter() - t) * 1000:.1f}"
        return resp

    if os.path.isdir(os.path.join(DIST, "assets")):
        app.mount("/assets", StaticFiles(directory=os.path.join(DIST, "assets")), name="assets")

    @app.get("/", include_in_schema=False)
    def ui():
        for page in (os.path.join(DIST, "index.html"), UI):
            if os.path.exists(page):
                return FileResponse(page)
        return JSONResponse({"see": "/docs"})

    @app.get("/health")
    def health():
        ok = os.path.exists(os.path.join(run_dir, "incidents.json"))
        return {"ok": ok, "run_dir": run_dir}

    @app.get("/incidents")
    def incidents(include_review: bool = Query(False, description="also list clusters scored 0.4-0.7"),
                  min_risk: float = 0.0):
        r = R()
        items = []
        for inc in sorted(r.full.values(), key=lambda i: -i["risk"]):
            if inc["verdict"] != "attack" and not include_review:
                continue
            if inc["risk"] < min_risk:
                continue
            items.append(OrderedDict(
                incident_id=inc["incident_id"], risk=inc["risk"], verdict=inc["verdict"],
                alerts_merged=inc["alerts_merged"], hits_merged=inc.get("hits_merged"),
                stages=inc["stages"], stages_covered=len(inc["stages"]), path=inc["path"],
                hosts=len(inc.get("blast_radius", {}).get("confirmed", {}).get("hosts", [])),
                steps=len(inc["steps"]), first_seen=inc["first_seen"], last_seen=inc["last_seen"],
                score_breakdown=inc.get("score_breakdown"), injection_flags=len(inc.get("injection_flags", [])),
                entry=(inc["steps"][0].get("technique_name") or inc["steps"][0]["technique"]) if inc["steps"] else None,
                outcome=(inc["steps"][-1].get("technique_name") or inc["steps"][-1]["technique"]) if inc["steps"] else None,
                could_reach=len(inc.get("blast_radius", {}).get("potential", {}).get("potential_hosts", [])),
                external_source=next((h["from"] for h in inc.get("hops", []) if h.get("external")), None),
                report_url=inc.get("report_url")))
        return {"dataset": r.summary.get("dataset"), "count": len(items), "incidents": items}

    @app.get("/incidents/{iid}")
    def incident(iid: int):
        return R().incident(iid)

    @app.get("/incidents/{iid}/path")
    def path(iid: int):
        inc = R().incident(iid)
        timeline = [{"order": s["order"], "time": s["time"], "stage": s["stage"], "host": s["host"],
                     "technique": s.get("sub_technique") or s["technique"], "summary": s["summary"]}
                    for s in inc["steps"]]
        return {"incident_id": iid, "risk": inc["risk"], "path": inc["path"], "steps": inc["steps"],
                "hops": inc.get("hops", []), "graph": inc.get("graph", {}), "timeline": timeline,
                "gaps": inc.get("gaps", []), "excluded": inc.get("excluded", []),
                "context_events": inc.get("context_events", [])}

    @app.get("/incidents/{iid}/lookahead")
    def lookahead(iid: int):
        inc = R().incident(iid)
        return {"incident_id": iid, "look_ahead": inc.get("look_ahead", []),
                "blast_radius": inc.get("blast_radius", {}), "key_entities": inc.get("key_entities", {}),
                "indicators": inc.get("indicators", [])}

    @app.get("/incidents/{iid}/report")
    def report(iid: int, format: str = Query("json", pattern="^(json|md|text)$")):
        inc = R().incident(iid)
        if format == "json":
            return {"incident_id": iid, "source": inc.get("report_source"), "grounding_rate": inc.get("grounding_rate"),
                    "sentences": inc.get("report", []), "dropped": inc.get("report_dropped", []),
                    "injection_flags": inc.get("injection_flags", []), "actions": recommended_actions(inc)}
        return PlainTextResponse(render_markdown(inc), media_type="text/markdown")

    @app.get("/incidents/{iid}/navigator")
    def navigator(iid: int):
        inc = R().incident(iid)
        return JSONResponse(inc.get("navigator_layer", {}),
                            headers={"Content-Disposition": f'attachment; filename="incident-{iid}-layer.json"'})

    @app.get("/events/{evidence_id:path}")
    def event(evidence_id: str):
        ev = R().evidence.get(evidence_id)
        if ev is None:
            raise HTTPException(404, "evidence id is not part of any incident")
        return {"evidence_id": evidence_id, **ev}

    @app.get("/stats")
    def stats():
        r = R()
        s = r.stats
        return {"dataset": s.get("dataset"), "processed": s.get("processed"), "stages_seconds": s.get("stages_seconds"),
                "counts": s.get("counts"), "files": s.get("files"), "data_quality": s.get("data_quality"),
                "rules": {k: v for k, v in (s.get("rules") or {}).items() if v.get("hits") or v.get("error")}}

    @app.get("/quality")
    def data_quality():
        p = os.path.join(R().run_dir, "quality.json")
        if not os.path.exists(p):
            raise HTTPException(404, "no data-quality report for this run")
        with open(p, encoding="utf-8") as f:
            return json.load(f)

    @app.post("/reload")
    def reload():
        state["r"] = None
        R()
        return {"reloaded": True}

    return app


def render_markdown(inc: dict) -> str:
    lines = [f"# Incident {inc['incident_id']} - risk {inc['risk']}", ""]
    lines.append(f"**Path:** {' -> '.join(inc['path'])}  ")
    lines.append(f"**Stages:** {', '.join(inc['stages'])}  ")
    lines.append(f"**Window:** {inc['first_seen']} to {inc['last_seen']}  ")
    lines.append(f"**Alerts merged:** {inc['alerts_merged']}  ")
    lines.append(f"**Narrative source:** {inc.get('report_source')} (grounding rate {inc.get('grounding_rate')})")
    if inc.get("injection_flags"):
        lines += ["", "> **Instruction-like text was found in log fields** and treated as attacker data:"]
        for f in inc["injection_flags"][:5]:
            lines.append(f"> - `{f['evidence']}` ({f['field']}): \"{f['match']}\"")
    for section, title in (("summary", "Executive summary"), ("timeline", "What happened"),
                           ("movement", "Movement between hosts"), ("look_ahead", "What the attacker could reach next"),
                           ("gaps", "Logging gaps")):
        sents = [s for s in inc.get("report", []) if s.get("section", "timeline") == section]
        if not sents:
            continue
        lines += ["", f"## {title}", ""]
        for s in sents:
            tag = " *(inferred)*" if s.get("kind") == "inferred" else ""
            cites = ", ".join(f"`{c}`" for c in s["citations"][:3])
            lines.append(f"- {s['text']}{tag} [{cites}]")
    lines += ["", "## ATT&CK techniques", "", "| # | Time | Host | Technique | Stage |", "|---|---|---|---|---|"]
    for s in inc["steps"]:
        lines.append(f"| {s['order']} | {s['time']} | {s['host']} | {s.get('sub_technique') or s['technique']} "
                     f"{s.get('technique_name') or ''} | {s['stage']} |")
    br = inc.get("blast_radius", {}).get("confirmed", {})
    lines += ["", "## Blast radius", "", f"- Hosts: {', '.join(br.get('hosts', []))}",
              f"- Accounts: {', '.join(br.get('users', []))}", f"- External IPs: {', '.join(br.get('external_ips', []))}"]
    if inc.get("indicators"):
        lines += ["", "## Indicators to block / hunt", ""]
        for i in inc["indicators"][:15]:
            lines.append(f"- {i['type']}: `{i['value']}` ({i['hits']} hits on {i['hosts']} hosts)")
    lines += ["", "## Recommended actions", ""]
    for a in recommended_actions(inc):
        lines.append(f"- [ ] {a}")
    return "\n".join(lines) + "\n"


def recommended_actions(inc: dict) -> list[str]:
    br = inc.get("blast_radius", {}).get("confirmed", {})
    out = []
    if br.get("hosts"):
        out.append(f"Isolate: {', '.join(br['hosts'][:10])}")
    if br.get("users"):
        out.append(f"Reset credentials and revoke sessions: {', '.join(br['users'][:10])}")
    for la in inc.get("look_ahead", [])[:3]:
        if la["account"] != "(network)":
            out.append(f"Reset {la['account']} (could reach {', '.join(la['can_reach'][:4])})")
    if br.get("external_ips"):
        out.append(f"Block at the perimeter: {', '.join(br['external_ips'][:10])}")
    techs = {s["technique"] for s in inc["steps"]}
    if techs & {"T1547", "T1053", "T1543", "T1505", "T1136", "T1098"}:
        out.append("Remove persistence: run keys, scheduled tasks/cron, services, web shells, and backdoor accounts")
    if "T1486" in techs or "T1490" in techs:
        out.append("Restore encrypted data from offline backups; shadow copies were deleted")
    out.append("Hunt the indicators above across all hosts, including hosts with no alerts")
    return out


app = create_app()
