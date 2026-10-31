import { useMemo, useState } from "react";
import Cy from "./Cy.jsx";
import { cssVar, tacticColor, hhmm, fmtTime, critLevel } from "../lib.js";

const palette = () => Object.fromEntries(
  ["text", "muted", "faint", "panel", "panel2", "panel3", "line", "line2", "accent", "crit", "high", "med", "low", "edge", "edge-dash"]
    .map((k) => [k.replace("-d", "D"), cssVar(`--${k}`)]));

const baseStyle = (C) => [
  { selector: "node", style: { color: C.text, "font-family": "Inter, system-ui, sans-serif", "font-size": 10, "text-valign": "center", "text-halign": "center" } },
  { selector: "edge", style: { "curve-style": "bezier", "target-arrow-shape": "triangle", "arrow-scale": 0.9, "line-color": C.edge, "target-arrow-color": C.edge, width: 1.6 } },
  { selector: ".ghost", style: { opacity: 0.13 } },
  { selector: "node.picked", style: { "border-color": C.accent, "border-width": 4, "z-index": 99 } },
  { selector: "edge.picked", style: { "line-color": C.accent, "target-arrow-color": C.accent, width: 4, "z-index": 99 } },
];
const edgeLabel = (C) => ({ label: "data(label)", "font-size": 10, color: C.text, "text-background-color": C.panel, "text-background-opacity": 1, "text-background-padding": 3, "text-background-shape": "roundrectangle", "text-rotation": "autorotate" });

/* ---------------------------------------------------------------- attack graph
   Steps grouped inside their host (compound nodes), linked by evidence edges with noisy-OR confidence;
   logon edges join the hosts. "Flow" puts each host in a column with time running downwards. */
export function AttackGraph({ inc, theme, minConf, replay, selected, onTap }) {
  const [flow, setFlow] = useState(true);
  const [showCtx, setShowCtx] = useState(true);
  const C = useMemo(palette, [theme]);

  const elements = useMemo(() => {
    const g = inc.graph || { nodes: [], edges: [] };
    const roles = Object.fromEntries(g.nodes.filter((x) => x.type === "host").map((x) => [x.label, x.role]));
    const hosts = [];
    const add = (h) => h && !hosts.includes(h) && hosts.push(h);
    inc.steps.forEach((s) => add(s.host));
    const ctx = showCtx ? g.nodes.filter((x) => x.type === "context") : [];
    ctx.forEach((c) => add(c.host));
    const colX = (h) => hosts.indexOf(h) * 250;
    const ts = inc.steps.map((s) => Date.parse(s.time));
    const Y = 70;
    const rowOf = (t) => Math.max(0, ts.findLastIndex((x) => x <= t));
    const els = hosts.map((h) => ({ data: { id: `host:${h}`, kind: "host", label: roles[h] ? `${h}  ·  ${roles[h]}` : h }, classes: "host" }));
    const ghost = new Set();
    for (const s of inc.steps) {
      const id = `step${s.order}`;
      if (s.order > replay) ghost.add(id);
      els.push({
        data: { id, parent: `host:${s.host}`, kind: "step", order: s.order, color: tacticColor(s.stage),
          label: `${s.order}. ${s.sub_technique || s.technique}\n${(s.technique_name || s.stage).slice(0, 24)}` },
        position: { x: colX(s.host), y: (s.order - 1) * Y }, classes: `step${ghost.has(id) ? " ghost" : ""}`,
      });
    }
    for (const c of ctx) {
      els.push({ data: { id: c.id, parent: `host:${c.host}`, kind: "context", label: c.label, evidence: c.evidence, why: c.why },
        position: { x: colX(c.host) + 108, y: rowOf(Date.parse(c.time)) * Y + Y / 2 }, classes: "context" });
    }
    const ids = new Set(els.map((e) => e.data.id));
    for (const x of g.nodes.filter((x) => x.type === "external")) {
      const hop = (inc.hops || []).find((h) => `host:${h.from}` === x.id);
      els.push({ data: { id: x.id, kind: "external", label: x.label }, classes: "external",
        position: { x: -230, y: hop ? rowOf(Date.parse(hop.time)) * Y : 0 } });
      ids.add(x.id);
    }
    g.edges.forEach((e, i) => {
      if (!ids.has(e.src) || !ids.has(e.dst)) return;
      if (e.kind === "logon") {
        els.push({ data: { id: `l${i}`, source: e.src, target: e.dst, kind: "logon", user: e.user, time: e.time, evidence: e.evidence,
          confidence: e.confidence, label: `${e.user || "?"} · ${hhmm(e.time)}` }, classes: "logon" });
      } else if (e.confidence >= minConf) {
        const gh = ghost.has(e.src) || ghost.has(e.dst);
        els.push({ data: { id: `e${i}`, source: e.src, target: e.dst, kind: "evidence", confidence: e.confidence, reasons: e.reasons || [], inferred: !!e.inferred },
          classes: [e.style === "dashed" ? "dashed" : "", e.inferred ? "inferred" : "", gh ? "ghost" : ""].join(" ") });
      }
    });
    return els;
  }, [inc, minConf, replay, showCtx]);

  const style = useMemo(() => [
    ...baseStyle(C),
    { selector: "node.host", style: { label: "data(label)", "text-valign": "top", "text-halign": "center", "text-margin-y": -6, shape: "round-rectangle",
      "background-color": C.panel2, "background-opacity": 0.55, "border-color": C.line2, "border-width": 1, padding: 22, "font-size": 11.5, "font-weight": 600, color: C.muted } },
    { selector: "node.step", style: { label: "data(label)", shape: "round-rectangle", width: 140, height: 46, "background-color": C.panel, "border-width": 2, "border-color": "data(color)",
      "text-wrap": "wrap", "text-max-width": 130, "font-size": 10, "line-height": 1.3 } },
    { selector: "node.context", style: { label: "data(label)", width: 12, height: 12, "background-color": C.faint, "text-valign": "bottom", "text-margin-y": 3, "font-size": 8.5, color: C.muted } },
    { selector: "node.external", style: { label: "data(label)", shape: "diamond", width: 36, height: 36, "background-color": C.crit, "text-valign": "bottom", "text-margin-y": 6, "font-size": 10.5, "font-weight": 600 } },
    { selector: "edge[kind = 'evidence']", style: { width: "mapData(confidence, 0.4, 1, 1, 3.2)" } },
    { selector: "edge.dashed", style: { "line-style": "dashed", "line-color": C.edgeDash, "target-arrow-color": C.edgeDash } },
    { selector: "edge.inferred", style: { "line-style": "dotted" } },
    { selector: "edge.logon", style: { ...edgeLabel(C), color: C.accent, "line-color": C.accent, "target-arrow-color": C.accent, width: 3, "curve-style": "straight" } },
    ...baseStyle(C).slice(-2),
  ], [C]);

  const layout = useMemo(() => (flow ? { name: "preset", padding: 40 }
    : { name: "cose", animate: false, randomize: false, padding: 40, nodeRepulsion: () => 12000, idealEdgeLength: () => 90, nestingFactor: 1.1, gravity: 0.4 }), [flow]);

  return (
    <>
      <div className="row" style={{ marginBottom: 10 }}>
        <div className="row" style={{ gap: 2 }}>
          <button className={`btn sm ${flow ? "on" : ""}`} onClick={() => setFlow(true)}>Host columns</button>
          <button className={`btn sm ${!flow ? "on" : ""}`} onClick={() => setFlow(false)}>Force layout</button>
        </div>
        <label className="small muted row" style={{ gap: 6 }}>
          <input type="checkbox" checked={showCtx} onChange={(e) => setShowCtx(e.target.checked)} /> traced context events
        </label>
        <span className="small faint">Each column is a host, time runs downwards. Click any node or edge for its evidence.</span>
      </div>
      <Cy elements={elements} style={style} layout={layout} onTap={onTap} selected={selected} height={Math.max(480, Math.min(940, 170 + inc.steps.length * 72))}
        legend={<>
          <span><span className="swatch-line" /> linked (≥ 0.7)</span>
          <span><span className="swatch-line dash" /> possible (0.4–0.7)</span>
          <span><span className="swatch-line dot" /> inferred across gap</span>
          <span><span className="swatch-line" style={{ borderColor: "var(--accent)", borderTopWidth: 3 }} /> logon hop</span>
          <span><span className="dot" style={{ background: "var(--faint)" }} /> context event</span>
          <span><span className="dot" style={{ background: "var(--crit)", borderRadius: 1, transform: "rotate(45deg)" }} /> external source</span>
        </>} />
    </>
  );
}

/* ---------------------------------------------------------------- host-hop view
   Machines only, ordered by when the attacker first reached them, with the account used on each hop. */
export function HostHops({ inc, theme, onEvidence }) {
  const C = useMemo(palette, [theme]);
  const hops = useMemo(() => [...(inc.hops || [])].sort((a, b) => a.time.localeCompare(b.time)), [inc]);
  const elements = useMemo(() => {
    const roles = Object.fromEntries((inc.graph?.nodes || []).filter((x) => x.type === "host").map((x) => [x.label, x.role]));
    const ext = new Set(hops.filter((h) => h.external).map((h) => h.from));
    const order = [];
    const add = (h) => h && !order.includes(h) && order.push(h);
    hops.forEach((h) => { add(h.from); add(h.to); });
    inc.path.forEach(add);
    const steps = {};
    inc.steps.forEach((s) => { steps[s.host] = (steps[s.host] || 0) + 1; });
    const els = order.map((h, i) => ({
      data: { id: `h:${h}`, kind: "hophost", label: `${h}\n${ext.has(h) ? "internet" : roles[h] || "host"}${steps[h] ? ` · ${steps[h]} steps` : ""}` },
      position: { x: i * 240, y: i % 2 ? 70 : 0 },
      classes: ext.has(h) ? "ext" : roles[h] || "other",
    }));
    hops.forEach((h, i) => {
      const d = order.indexOf(h.to) - order.indexOf(h.from);
      els.push({ data: { id: `hop${i}`, source: `h:${h.from}`, target: `h:${h.to}`, kind: "hop", evidence: h.evidence, label: `${i + 1}. ${h.user || "?"} · ${hhmm(h.time)}`,
        cpd: (i % 2 ? 1 : -1) * (20 + 18 * Math.abs(d)) } });
    });
    return els;
  }, [inc, hops]);
  const style = useMemo(() => [
    ...baseStyle(C),
    { selector: "node", style: { label: "data(label)", "text-wrap": "wrap", "text-valign": "bottom", "text-margin-y": 8, "font-size": 11, "font-weight": 600,
      width: 58, height: 58, "background-color": C.panel3, "border-width": 2, "border-color": C.line2 } },
    { selector: "node.dc", style: { shape: "hexagon", "border-color": C.crit, "background-color": C.panel2 } },
    { selector: "node.fileserver", style: { shape: "barrel", "border-color": C.high } },
    { selector: "node.workstation", style: { shape: "round-rectangle", "border-color": C.accent } },
    { selector: "node.ext", style: { shape: "diamond", "background-color": C.crit, "border-color": C.crit } },
    { selector: "edge", style: { ...edgeLabel(C), "curve-style": "unbundled-bezier", "control-point-distances": "data(cpd)", "control-point-weights": 0.5,
      width: 3, "line-color": C.accent, "target-arrow-color": C.accent, "arrow-scale": 1.2 } },
  ], [C]);
  const layout = useMemo(() => ({ name: "preset", padding: 60 }), []);

  if (!hops.length) return <div className="card empty">No host-to-host movement was observed for this incident.</div>;
  return (
    <>
      <Cy elements={elements} style={style} layout={layout} height={340} onTap={(d) => d?.evidence && onEvidence([d.evidence], `Logon hop ${d.label}`)}
        legend={<>
          <span><span className="dot" style={{ background: "var(--crit)", borderRadius: 1, transform: "rotate(45deg)" }} /> internet source</span>
          <span>⬡ domain controller</span><span>▭ workstation</span><span>◯ server</span>
        </>} />
      <div className="card" style={{ marginTop: 14 }}>
        <div className="card-h"><h3>Hops</h3><span className="sub">{hops.length} authenticated moves between machines</span></div>
        <table className="tbl">
          <thead><tr><th>#</th><th>Time (UTC)</th><th>From</th><th>To</th><th>Account</th><th>Technique</th><th>Evidence</th></tr></thead>
          <tbody>{hops.map((h, i) => (
            <tr key={i} className="click" onClick={() => onEvidence([h.evidence], `Logon hop ${h.from} → ${h.to}`)}>
              <td>{i + 1}</td><td className="mono">{fmtTime(h.time)}</td>
              <td>{h.external ? <span className="chip crit">{h.from}</span> : h.from}</td><td><b>{h.to}</b></td>
              <td>{h.user || "—"}</td><td><code>{h.technique}</code></td><td><span className="cite">{h.evidence.split("/").pop()}</span></td>
            </tr>))}
          </tbody>
        </table>
      </div>
    </>
  );
}

/* ---------------------------------------------------------------- look-ahead reach graph
   compromised hosts → accounts whose credentials are controlled/exposed → hosts those accounts administer. */
export function ReachGraph({ inc, theme }) {
  const C = useMemo(palette, [theme]);
  const [pick, setPick] = useState(null);
  const br = inc.blast_radius || {};
  const chains = br.potential?.chains || [];
  const elements = useMemo(() => {
    const owned = new Set(br.confirmed?.hosts || []);
    const ownedUsers = new Set(br.confirmed?.users || []);
    const targets = new Map();
    const accounts = new Set(ownedUsers);
    const edges = new Map();
    for (const c of chains) {
      targets.set(c.target, c);
      const kinds = c.chain.map((x) => (x === c.target || owned.has(x) ? "host" : "account"));
      c.chain.forEach((x, i) => { if (kinds[i] === "account") accounts.add(x); });
      for (let i = 1; i < c.chain.length; i++) {
        const a = c.chain[i - 1], b = c.chain[i];
        const id = `${a}->${b}`;
        if (!edges.has(id)) edges.set(id, { a, b, kind: kinds[i - 1] === "host" ? "exposed" : "admin" });
      }
    }
    const col = (items, x, mk) => items.map((it, i) => mk(it, { x, y: (i - (items.length - 1) / 2) * 70 }));
    const nid = (x, kind) => `${kind}:${x}`;
    const kindOf = (x) => (accounts.has(x) && !targets.has(x) && !owned.has(x) ? "acct" : "host");
    const els = [
      ...col([...owned], 0, (h, p) => ({ data: { id: nid(h, "host"), label: h, kind: "owned" }, position: p, classes: "owned" })),
      ...col([...accounts], 320, (a, p) => ({ data: { id: nid(a, "acct"), label: a, kind: "acct" }, position: p, classes: ownedUsers.has(a) ? "acct ownedacct" : "acct" })),
      ...col([...targets.values()].filter((t) => !owned.has(t.target)).sort((a, b) => b.criticality - a.criticality), 680, (t, p) => ({
        data: { id: nid(t.target, "host"), label: `${t.target}\n${t.role || ""}`, kind: "target", crit: t.criticality }, position: p, classes: `target ${critLevel(t.criticality)}` })),
    ];
    const ids = new Set(els.map((e) => e.data.id));
    for (const [id, e] of edges) {
      const s = nid(e.a, kindOf(e.a)), t = nid(e.b, kindOf(e.b));
      if (ids.has(s) && ids.has(t)) els.push({ data: { id, source: s, target: t, label: e.kind === "exposed" ? "creds exposed" : "admin on" }, classes: e.kind });
    }
    return els;
  }, [inc]);
  const style = useMemo(() => [
    ...baseStyle(C),
    { selector: "node", style: { label: "data(label)", "text-wrap": "wrap", "text-valign": "center", "text-halign": "right", "text-margin-x": 10, "font-size": 11, width: 26, height: 26 } },
    { selector: "node.owned", style: { shape: "round-rectangle", "background-color": C.crit, "text-halign": "left", "text-margin-x": -10, "font-weight": 600 } },
    { selector: "node.acct", style: { shape: "ellipse", "background-color": C.med, width: 20, height: 20 } },
    { selector: "node.ownedacct", style: { "background-color": C.crit } },
    { selector: "node.target", style: { shape: "round-rectangle", "background-color": C.panel3, "border-width": 3, "border-color": C.low } },
    { selector: "node.target.crit", style: { "border-color": C.crit } }, { selector: "node.target.high", style: { "border-color": C.high } },
    { selector: "node.target.med", style: { "border-color": C.med } },
    { selector: "edge", style: { width: 1.5, "line-color": C.line2, "target-arrow-color": C.line2, "curve-style": "bezier" } },
    { selector: "edge.exposed", style: { "line-style": "dashed", "line-color": C.med, "target-arrow-color": C.med } },
    ...baseStyle(C).slice(-1),
  ], [C]);
  const layout = useMemo(() => ({ name: "preset", padding: 50 }), []);
  if (!chains.length) return null;
  const name = pick ? pick.split(":").slice(1).join(":") : null;
  const why = name ? chains.filter((c) => c.chain.includes(name)) : [];
  return (
    <>
      <Cy elements={elements} style={style} layout={layout} height={Math.min(620, 160 + 70 * Math.max(4, elements.filter((e) => !e.data.source).length / 2.4))}
        onTap={(d) => setPick(d && !d.source ? d.id : null)}
        selected={pick}
        legend={<>
          <span><span className="dot" style={{ background: "var(--crit)", borderRadius: 2 }} /> compromised</span>
          <span><span className="dot" style={{ background: "var(--med)" }} /> at-risk account</span>
          <span><span className="swatch-line dash" style={{ borderColor: "var(--med)" }} /> credentials exposed</span>
          <span><span className="swatch-line" /> observed admin access</span>
          <span>border = target criticality</span>
        </>} />
      {pick && (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="card-h"><h3>{name}</h3><span className="sub">{why.length} reach chain(s) through this node</span>
            <span className="spacer" /><button className="btn sm ghost" onClick={() => setPick(null)}>Close</button></div>
          {why.slice(0, 12).map((c, i) => <div key={i} className="warn-item low"><b>{c.chain.join(" → ")}</b><div className="muted small">{c.why}</div></div>)}
        </div>
      )}
    </>
  );
}
