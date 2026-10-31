import { useMemo } from "react";
import { TACTICS, tacticColor, fmtTime } from "../lib.js";

const CW = 160, NW = 146, NH = 46, GAP = 8, LX = 150, TY = 50;

// Kill map: ATT&CK tactics left→right, hosts top→bottom, so the path reads like a sentence and every
// hop between machines is visible. Edges are the evidence links (noisy-OR confidence) between steps.
export default function KillMap({ inc, minConf, allLinks, replay, selected, onStep, onEdge }) {
  const L = useMemo(() => {
    const tactics = TACTICS.filter((t) => inc.steps.some((s) => s.stage === t));
    const extra = [...new Set(inc.steps.map((s) => s.stage).filter((t) => !TACTICS.includes(t)))];
    const lanes = [...tactics, ...extra];
    const hosts = [...new Set([...inc.path, ...inc.steps.map((s) => s.host)].filter((h) => inc.steps.some((s) => s.host === h)))];
    const roles = Object.fromEntries((inc.graph?.nodes || []).filter((x) => x.type === "host").map((x) => [x.label, x.role]));
    const cell = {};
    inc.steps.forEach((s) => { const k = `${s.host}|${s.stage}`; cell[k] = (cell[k] || 0) + 1; });
    const rowH = hosts.map((h) => 24 + Math.max(1, ...lanes.map((t) => cell[`${h}|${t}`] || 0)) * (NH + GAP));
    const rowY = [];
    rowH.reduce((y, hgt, i) => ((rowY[i] = y), y + hgt), TY);
    const H = rowY.at(-1) + rowH.at(-1) + 12;
    const W = LX + lanes.length * CW + 16;
    const slot = {}, pos = {};
    for (const s of inc.steps) {
      const k = `${s.host}|${s.stage}`;
      const i = (slot[k] = (slot[k] || 0) + 1) - 1;
      pos[s.order] = { x: LX + lanes.indexOf(s.stage) * CW + (CW - NW) / 2, y: rowY[hosts.indexOf(s.host)] + 12 + i * (NH + GAP) };
    }
    const count = Object.fromEntries(hosts.map((h) => [h, inc.steps.filter((s) => s.host === h).length]));
    return { lanes, hosts, roles, rowY, rowH, H, W, pos, count };
  }, [inc]);

  const linked = (inc.graph?.edges || []).filter((e) => e.kind === "evidence" && e.confidence >= minConf && e.src.startsWith("step") && e.dst.startsWith("step"));
  // Default: only the strongest link into each step (the story spine); "all links" shows every supported edge.
  const edges = allLinks ? linked : Object.values(linked.reduce((best, e) => {
    const b = best[e.dst];
    if (!b || e.confidence > b.confidence || (e.confidence === b.confidence && +e.src.slice(4) > +b.src.slice(4))) best[e.dst] = e;
    return best;
  }, {}));

  const path = (a, b) => {
    if (b.x > a.x + 1) {
      const x1 = a.x + NW, y1 = a.y + NH / 2, x2 = b.x - 4, y2 = b.y + NH / 2, m = (x2 - x1) / 2;
      return `M${x1},${y1} C${x1 + m},${y1} ${x2 - m},${y2} ${x2},${y2}`;
    }
    if (b.x < a.x - 1) {
      const x1 = a.x, y1 = a.y + NH / 2, x2 = b.x + NW + 4, y2 = b.y + NH / 2, m = Math.max(40, (x1 - x2) / 3);
      return `M${x1},${y1} C${x1 - m},${y1 - 40} ${x2 + m},${y2 - 40} ${x2},${y2}`;
    }
    const down = b.y > a.y, x = a.x + NW, y1 = a.y + NH / 2, y2 = b.y + NH / 2;
    return `M${x},${y1} C${x + 28},${y1} ${x + 28},${y2} ${x + 4},${y2 + (down ? 0 : 0)}`;
  };

  return (
    <div className="viz">
      <svg width={L.W} height={L.H} role="img" aria-label="Kill map: ATT&CK tactics by host">
        <defs>
          <marker id="km-a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z" fill="var(--edge)" /></marker>
          <marker id="km-d" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z" fill="var(--edge-dash)" /></marker>
        </defs>
        {L.lanes.map((t, i) => (
          <g key={t}>
            <rect x={LX + i * CW + 3} y={TY - 8} width={CW - 6} height={L.H - TY} rx="6" fill="var(--panel2)" />
            <rect x={LX + i * CW + 3} y={8} width={CW - 6} height={4} rx="2" fill={tacticColor(t)} />
            <text x={LX + i * CW + 10} y={30} fontSize="10.5" fontWeight="600" style={{ textTransform: "uppercase", letterSpacing: ".05em" }} fill="var(--muted)">{t}</text>
          </g>
        ))}
        {L.hosts.map((h, i) => (
          <g key={h}>
            {i > 0 && <line x1="8" x2={L.W - 8} y1={L.rowY[i] - 1} y2={L.rowY[i] - 1} stroke="var(--line)" strokeDasharray="3 4" />}
            <text x="14" y={L.rowY[i] + 30} fontWeight="650" fontSize="13">{h}</text>
            <text x="14" y={L.rowY[i] + 47} fontSize="11" fill="var(--muted)">{L.roles[h] || "host"} · {L.count[h]} steps</text>
          </g>
        ))}
        {edges.map((e, i) => {
          const a = L.pos[+e.src.slice(4)], b = L.pos[+e.dst.slice(4)];
          if (!a || !b) return null;
          const solid = e.style === "solid" && !e.inferred;
          const ghost = +e.src.slice(4) > replay || +e.dst.slice(4) > replay;
          return (
            <path key={i} d={path(a, b)} fill="none" stroke={solid ? "var(--edge)" : "var(--edge-dash)"} strokeWidth={1 + 2 * (e.confidence - 0.4) / 0.6}
              strokeDasharray={e.inferred ? "2 3" : solid ? undefined : "5 4"} markerEnd={`url(#${solid ? "km-a" : "km-d"})`} opacity={ghost ? 0.08 : 0.75}
              style={{ cursor: "pointer" }} onClick={() => onEdge(e)}>
              <title>{`confidence ${e.confidence}\n${(e.reasons || []).join(", ")}${e.inferred ? "\ninferred across a logging gap" : ""}`}</title>
            </path>
          );
        })}
        {inc.steps.map((s) => {
          const p = L.pos[s.order];
          const c = tacticColor(s.stage);
          const name = s.technique_name || s.stage;
          return (
            <g key={s.order} className={`svg-node${selected === s.order ? " sel" : ""}${s.order > replay ? " ghost" : ""}`} onClick={() => onStep(s.order)}
              tabIndex={0} role="button" aria-label={`Step ${s.order} ${s.technique} on ${s.host}`} onKeyDown={(e) => e.key === "Enter" && onStep(s.order)}>
              <rect className="nbox" x={p.x} y={p.y} width={NW} height={NH} rx="6" fill="var(--panel)" stroke={c} strokeWidth="1.5" />
              <rect x={p.x} y={p.y} width="5" height={NH} rx="2.5" fill={c} />
              <circle cx={p.x + 21} cy={p.y + 16} r="9" fill={c} />
              <text x={p.x + 21} y={p.y + 19.5} textAnchor="middle" fontSize="10" fontWeight="700" fill="#fff">{s.order}</text>
              <text x={p.x + 36} y={p.y + 20} fontSize="11.5" fontWeight="650" fontFamily="var(--mono)">{s.sub_technique || s.technique}</text>
              <text x={p.x + 12} y={p.y + 37} fontSize="10.5" fill="var(--muted)">{name.length > 24 ? name.slice(0, 23) + "…" : name}</text>
              <title>{`${fmtTime(s.time)} UTC · ${s.host}${s.user ? " · " + s.user : ""}\n${s.technique_name || ""} (${s.stage})\n${s.summary}\nlabel: ${s.label_source} · ${s.evidence.length} evidence line(s)`}</title>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
