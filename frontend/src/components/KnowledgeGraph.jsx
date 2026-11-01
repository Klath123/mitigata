import { useEffect, useMemo, useState } from "react";
import Cy from "./Cy.jsx";
import { get, cssVar, tacticColor } from "../lib.js";

// The run's knowledge graph (GET /graph, written by engine/graph/export.py; the same graph as the Neo4j / GraphML
// export). Incidents connect to the hosts, accounts and internet addresses they touched and to the ATT&CK techniques
// they used, so incidents that share any of these meet in the picture.
const KIND = {
  Incident: { shape: "round-rectangle", w: 90, h: 34 },
  Step: { shape: "ellipse", w: 18, h: 18 },
  Host: { shape: "round-rectangle", w: 30, h: 30 },
  Account: { shape: "ellipse", w: 30, h: 30 },
  ExternalIP: { shape: "diamond", w: 32, h: 32 },
  Technique: { shape: "hexagon", w: 34, h: 30 },
  Indicator: { shape: "triangle", w: 26, h: 26 },
};
const KIND_LABEL = { Incident: "incident", Step: "step", Host: "host / device", Account: "account", ExternalIP: "internet address",
  Technique: "ATT&CK technique", Indicator: "indicator" };
const MAX_NODES = 1500;

export default function KnowledgeGraph({ onSelect }) {
  const [g, setG] = useState(null);
  const [steps, setSteps] = useState(false);
  const [picked, setPicked] = useState(null);
  useEffect(() => { get("/graph").then(setG).catch(() => setG(false)); }, []);

  const C = useMemo(() => Object.fromEntries(["text", "muted", "panel", "line2", "accent", "crit", "high", "med", "low", "edge"]
    .map((k) => [k, cssVar(`--${k}`)])), [g]);
  const color = (n) => n.label === "Incident" ? (n.verdict === "attack" ? C.crit : C.med)
    : n.label === "Technique" || n.label === "Step" ? tacticColor(n.stage)
    : n.label === "ExternalIP" ? C.high : n.label === "Account" ? C.accent : n.label === "Indicator" ? C.low : C.muted;

  const elements = useMemo(() => {
    if (!g) return [];
    const byId = Object.fromEntries(g.nodes.map((n) => [n.id, n]));
    let nodes = g.nodes, edges = g.edges;
    if (!steps) {
      // without step nodes, an incident links straight to what its steps touched (host, account, technique)
      const owner = {};
      for (const e of g.edges) if (e.type === "HAS_STEP") owner[e.target] = e.source;
      const seen = new Set();
      edges = [];
      for (const e of g.edges) {
        if (["HAS_STEP", "NEXT", "LINKED"].includes(e.type)) continue;
        const src = owner[e.source] || e.source;
        if (byId[src]?.label === "Step") continue;
        const k = `${src}|${e.target}|${e.type}`;
        if (src !== e.target && !seen.has(k)) { seen.add(k); edges.push({ ...e, source: src }); }
      }
      nodes = g.nodes.filter((n) => n.label !== "Step");
    }
    nodes = nodes.slice(0, MAX_NODES);
    const keep = new Set(nodes.map((n) => n.id));
    return [
      ...nodes.map((n) => ({ data: { ...n, kind: n.label, text: n.label === "Incident" ? n.name : String(n.name || n.id).slice(0, 40),
        color: color(n), shape: (KIND[n.label] || KIND.Host).shape, w: (KIND[n.label] || KIND.Host).w, h: (KIND[n.label] || KIND.Host).h } })),
      ...edges.filter((e) => keep.has(e.source) && keep.has(e.target))
        .map((e, i) => ({ data: { id: `e${i}`, source: e.source, target: e.target, rel: e.type } })),
    ];
  }, [g, steps, C]);

  const style = useMemo(() => [
    { selector: "node", style: { "background-color": "data(color)", shape: "data(shape)", width: "data(w)", height: "data(h)",
      label: "data(text)", color: C.text, "font-size": 9, "text-valign": "bottom", "text-margin-y": 4, "text-wrap": "ellipsis",
      "text-max-width": 120, "border-width": 1, "border-color": C.line2 } },
    { selector: 'node[kind = "Incident"]', style: { "text-valign": "center", "text-margin-y": 0, color: "#fff", "font-weight": 700, "font-size": 10 } },
    { selector: "edge", style: { "curve-style": "bezier", width: 1.2, "line-color": C.edge, "target-arrow-shape": "triangle",
      "target-arrow-color": C.edge, "arrow-scale": 0.7, label: "data(rel)", "font-size": 7, color: C.muted, "text-rotation": "autorotate" } },
    { selector: "node.picked", style: { "border-color": C.accent, "border-width": 4 } },
  ], [C]);
  const layout = useMemo(() => ({ name: "cose", animate: false, nodeRepulsion: 9000, idealEdgeLength: 90, padding: 30 }), [elements]);

  if (g === false) return <div className="warn-item med">No knowledge graph for this run (runs made before 2026-11-01 have only the incident graphs).</div>;
  if (!g) return <div className="muted small">Loading the knowledge graph…</div>;
  const counts = g.nodes.reduce((a, n) => ({ ...a, [n.label]: (a[n.label] || 0) + 1 }), {});
  const shown = picked && Object.entries(picked).filter(([k, v]) => !["color", "shape", "w", "h", "text", "kind", "label", "id"].includes(k) && v !== "" && v != null);

  return (
    <>
      <div className="section-row">
        <h2>Knowledge graph</h2>
        <span className="muted small">{Object.entries(counts).map(([k, v]) => `${v} ${KIND_LABEL[k] || k}`).join(" · ")}</span>
      </div>
      <div className="kb-filters">
        <label className="small row" style={{ gap: 5 }}><input type="checkbox" checked={steps} onChange={(e) => setSteps(e.target.checked)} /> show every step (otherwise incidents link straight to what they touched)</label>
        <span className="small muted">Click an incident to open it, any other node for its details. The same graph is exported for Gephi / yEd (GraphML) and Neo4j in the run's graph folder.</span>
      </div>
      <div className="grid-kg">
        <Cy elements={elements} style={style} layout={layout} height={560} selected={picked?.id}
            onTap={(d) => { if (d?.kind === "Incident") onSelect(Number(String(d.id).split(":")[1])); else setPicked(d?.source ? null : d); }}
            legend={Object.keys(KIND).filter((k) => counts[k] && (steps || k !== "Step")).map((k) => <span key={k}><span className="swatch" style={{ background: k === "Incident" ? C.crit : k === "ExternalIP" ? C.high : k === "Account" ? C.accent : k === "Indicator" ? C.low : C.muted }} /> {KIND_LABEL[k]}</span>)} />
        {picked && (
          <div className="card kg-side">
            <div className="card-h"><h3>{String(picked.name || picked.id)}</h3><span className="sub">{KIND_LABEL[picked.kind] || picked.kind}</span></div>
            <table className="tbl"><tbody>{shown.map(([k, v]) => (
              <tr key={k}><td className="muted small">{k.replace(/_/g, " ")}</td>
                <td className="small">{/_seen$/.test(k) && Number(v) > 1e11 ? new Date(Number(v)).toISOString().slice(0, 16).replace("T", " ") + " UTC" : String(v)}</td></tr>))}</tbody></table>
          </div>
        )}
      </div>
    </>
  );
}
