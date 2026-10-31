import { useMemo } from "react";
import { TACTICS, tacticColor, fmtTime } from "../lib.js";

// ─── Layout constants ────────────────────────────────────────────────────────
const CW     = 200; // tactic column width (room for labels)
const NW     = 174; // node width
const NH     = 54;  // node height
const VGAP   = 24;  // vertical gap between stacked nodes in same cell
const ROWPAD = 36;  // top+bottom padding per host band (room for curves)
const ROWSEP = 30;  // extra separation between distinct host bands
const LX     = 170; // left gutter (host names and roles)
const TY     = 60;  // top gutter (tactic column headers)

// ─── High-contrast edge styling ──────────────────────────────────────────────
// Solid: confirmed high-confidence link (≥ 0.70)
// Dashed: possible / moderate confidence (0.40 – 0.69)
// Inferred: gap-crossing (telemetry missing)
const CLR_SOLID = "#4c9aff"; // Electric Blue
const CLR_DASH  = "#ff9f43"; // Vivid Orange
const CLR_INF   = "#ff5c5c"; // Warning Red

function getEdgeKind(e) {
  if (e.inferred) return "inf";
  if (e.style === "solid" && e.confidence >= 0.70) return "solid";
  return "dash";
}

// ─── Clean curved SVG routing ────────────────────────────────────────────────
function getPath(a, b, backIdx) {
  const ay = a.y + NH / 2;
  const by = b.y + NH / 2;

  // Case 1: Forward (A is in an earlier tactic column than B)
  if (b.x > a.x + 1) {
    const ax = a.x + NW;
    const bx = b.x - 4; // stop 4px before node border so arrowhead sits outside
    const m = (bx - ax) / 2;
    return `M${ax},${ay} C${ax + m},${ay} ${bx - m},${by} ${bx},${by}`;
  }

  // Case 2: Backward (A is in a later tactic column than B, e.g. post-lateral execution)
  // Leaves top of A, arcs overhead with fanned lift, enters top of B pointing down
  if (b.x < a.x - 1) {
    const ax = a.x + NW / 2;
    const bx = b.x + NW / 2;
    const lift = 48 + (backIdx % 4) * 22; // fan overhead loops so they don't overlap
    const topY = Math.min(a.y, b.y) - lift;
    return `M${ax},${a.y} C${ax},${topY} ${bx},${topY} ${bx},${b.y - 4}`;
  }

  // Case 3: Same column (different rows)
  // Loops out to the right of the column
  const fanX = a.x + NW + 32 + (backIdx % 3) * 16;
  return `M${a.x + NW},${ay} C${fanX},${ay} ${fanX},${by} ${b.x + NW + 4},${by}`;
}

export default function KillMap({ inc, minConf, allLinks, replay, selected, onStep, onEdge }) {
  const L = useMemo(() => {
    const tactics = TACTICS.filter((t) => inc.steps.some((s) => s.stage === t));
    const extra   = [...new Set(inc.steps.map((s) => s.stage).filter((t) => !TACTICS.includes(t)))];
    const lanes   = [...tactics, ...extra];
    const hosts   = [...new Set(
      [...inc.path, ...inc.steps.map((s) => s.host)].filter((h) => inc.steps.some((s) => s.host === h))
    )];
    const roles = Object.fromEntries(
      (inc.graph?.nodes || []).filter((x) => x.type === "host").map((x) => [x.label, x.role])
    );

    // Count steps per (host × tactic) cell
    const cell = {};
    inc.steps.forEach((s) => { const k = `${s.host}|${s.stage}`; cell[k] = (cell[k] || 0) + 1; });

    // Calculate height of each host row based on densest column
    const rowH = hosts.map(
      (h) => ROWPAD * 2 + Math.max(1, ...lanes.map((t) => cell[`${h}|${t}`] || 0)) * (NH + VGAP) - VGAP
    );
    const rowY = [];
    rowH.reduce((y, h, i) => ((rowY[i] = y), y + h + ROWSEP), TY);

    const H = rowY.at(-1) + rowH.at(-1) + 30;
    const W = LX + lanes.length * CW + 30;

    // Pixel position of each step node
    const slot = {}, pos = {};
    for (const s of inc.steps) {
      const k = `${s.host}|${s.stage}`;
      const i = (slot[k] = (slot[k] || 0) + 1) - 1;
      pos[s.order] = {
        x: LX + lanes.indexOf(s.stage) * CW + (CW - NW) / 2,
        y: rowY[hosts.indexOf(s.host)] + ROWPAD + i * (NH + VGAP),
      };
    }
    const count = Object.fromEntries(hosts.map((h) => [h, inc.steps.filter((s) => s.host === h).length]));
    return { lanes, hosts, roles, rowY, rowH, H, W, pos, count };
  }, [inc]);

  // Filter edges above minConf
  const linked = (inc.graph?.edges || []).filter(
    (e) => e.kind === "evidence" && e.confidence >= minConf
         && e.src.startsWith("step") && e.dst.startsWith("step")
  );

  // Default: strongest link per destination node. Toggle allLinks shows all.
  const edges = allLinks
    ? linked
    : Object.values(linked.reduce((best, e) => {
        const b = best[e.dst];
        if (!b || e.confidence > b.confidence
               || (e.confidence === b.confidence && +e.src.slice(4) > +b.src.slice(4)))
          best[e.dst] = e;
        return best;
      }, {}));

  // Index backward arcs to fan them
  const backCounts = {};
  const routedEdges = edges.map((e) => {
    const a = L.pos[+e.src.slice(4)];
    const b = L.pos[+e.dst.slice(4)];
    const isBack = a && b && b.x <= a.x + 1;
    const idx = isBack ? (backCounts[e.dst] = (backCounts[e.dst] || 0) + 1) - 1 : 0;
    return { e, a, b, idx };
  });

  return (
    <div className="viz">
      <svg width={L.W} height={L.H} role="img" aria-label="Kill map: ATT&CK tactics by host">
        <defs>
          {/* Solid Arrowhead (Blue, filled) */}
          <marker id="km-solid" viewBox="0 0 10 10" refX="8" refY="5"
                  markerWidth="8" markerHeight="8" orient="auto">
            <path d="M0,1 L9,5 L0,9 Z" fill={CLR_SOLID} />
          </marker>

          {/* Dashed Arrowhead (Orange, open chevron with thick stroke) */}
          <marker id="km-dash" viewBox="0 0 10 10" refX="8" refY="5"
                  markerWidth="8" markerHeight="8" orient="auto">
            <path d="M1,1 L8,5 L1,9" fill="none" stroke={CLR_DASH} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
          </marker>

          {/* Inferred Arrowhead (Red, open chevron) */}
          <marker id="km-inf" viewBox="0 0 10 10" refX="8" refY="5"
                  markerWidth="8" markerHeight="8" orient="auto">
            <path d="M1,1 L8,5 L1,9" fill="none" stroke={CLR_INF} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
          </marker>
        </defs>

        {/* ── Tactic Column Background Lanes ── */}
        {L.lanes.map((t, i) => (
          <g key={t}>
            <rect x={LX + i * CW + 4} y={TY - 14} width={CW - 8} height={L.H - TY + 10} rx="8" fill="var(--panel2)" />
            <rect x={LX + i * CW + 4} y={10} width={CW - 8} height={5} rx="2.5" fill={tacticColor(t)} />
            <text x={LX + i * CW + 14} y={35} fontSize="10.5" fontWeight="700" fill="var(--muted)"
                  style={{ textTransform: "uppercase", letterSpacing: ".06em" }}>
              {t}
            </text>
          </g>
        ))}

        {/* ── Host Rows & Dividers ── */}
        {L.hosts.map((h, i) => (
          <g key={h}>
            {i > 0 && (
              <line x1="8" x2={L.W - 8}
                    y1={L.rowY[i] - ROWSEP / 2} y2={L.rowY[i] - ROWSEP / 2}
                    stroke="var(--line)" strokeDasharray="5 5" strokeWidth="1" />
            )}
            <text x="14" y={L.rowY[i] + 24} fontWeight="700" fontSize="14">{h}</text>
            <text x="14" y={L.rowY[i] + 43} fontSize="11" fill="var(--muted)">
              {L.roles[h] || "host"} · {L.count[h]} steps
            </text>
          </g>
        ))}

        {/* ── Edges / Relationship Arrows (drawn behind nodes) ── */}
        {routedEdges.map(({ e, a, b, idx }, i) => {
          if (!a || !b) return null;
          const kind = getEdgeKind(e);
          const ghost = +e.src.slice(4) > replay || +e.dst.slice(4) > replay;

          const stroke = kind === "solid" ? CLR_SOLID : kind === "dash" ? CLR_DASH : CLR_INF;
          const strokeW = kind === "solid" ? 2.4 : 2.0;
          const dash = kind === "solid" ? undefined : kind === "dash" ? "8 5" : "3 4";
          const marker = `url(#km-${kind})`;
          const opacity = ghost ? 0.08 : 0.9;

          return (
            <path key={i}
              d={getPath(a, b, idx)}
              fill="none"
              stroke={stroke}
              strokeWidth={strokeW}
              strokeDasharray={dash}
              strokeLinecap="round"
              markerEnd={marker}
              opacity={opacity}
              style={{ cursor: "pointer" }}
              onClick={() => onEdge(e)}>
              <title>{`${kind === "solid" ? "✔ Solid (High Confidence)" : kind === "dash" ? "~ Dashed (Possible Link)" : "⚠ Inferred (Logging Gap)"} · confidence ${e.confidence}\n${(e.reasons || []).join(", ")}`}</title>
            </path>
          );
        })}

        {/* ── Step Nodes ── */}
        {inc.steps.map((s) => {
          const p = L.pos[s.order];
          if (!p) return null;
          const c = tacticColor(s.stage);
          const name = s.technique_name || s.stage;
          return (
            <g key={s.order}
               className={`svg-node${selected === s.order ? " sel" : ""}${s.order > replay ? " ghost" : ""}`}
               onClick={() => onStep(s.order)}
               tabIndex={0} role="button"
               aria-label={`Step ${s.order} ${s.technique} on ${s.host}`}
               onKeyDown={(ev) => ev.key === "Enter" && onStep(s.order)}>
              {/* Node background rect */}
              <rect className="nbox" x={p.x} y={p.y} width={NW} height={NH} rx="8"
                    fill="var(--panel)" stroke={c} strokeWidth="1.8" />
              {/* Left accent color strip */}
              <rect x={p.x} y={p.y} width="5" height={NH} rx="2.5" fill={c} />
              {/* Order number circle badge */}
              <circle cx={p.x + 22} cy={p.y + 18} r="10" fill={c} />
              <text x={p.x + 22} y={p.y + 22} textAnchor="middle" fontSize="10.5" fontWeight="800" fill="#fff">
                {s.order}
              </text>
              {/* Technique ID */}
              <text x={p.x + 39} y={p.y + 22} fontSize="12" fontWeight="700" fontFamily="var(--mono)">
                {s.sub_technique || s.technique}
              </text>
              {/* Technique name */}
              <text x={p.x + 12} y={p.y + 41} fontSize="10.5" fill="var(--muted)">
                {name.length > 26 ? name.slice(0, 25) + "…" : name}
              </text>
              <title>{`${fmtTime(s.time)} UTC · ${s.host}${s.user ? " · " + s.user : ""}\n${s.technique_name || ""} (${s.stage})\n${s.summary}\nlabel: ${s.label_source} · ${s.evidence.length} evidence line(s)`}</title>
            </g>
          );
        })}
      </svg>

      {/* ── Legend below the SVG ── */}
      <div className="km-legend">
        <span className="km-leg-item">
          <svg width="44" height="14" style={{ overflow: "visible" }}>
            <line x1="2" y1="7" x2="34" y2="7" stroke={CLR_SOLID} strokeWidth="2.4" markerEnd="url(#km-solid)" />
          </svg>
          <span style={{ color: "var(--text)", fontWeight: 500 }}>Solid Blue:</span> Confirmed Link (≥ 0.70)
        </span>
        <span className="km-leg-item">
          <svg width="44" height="14" style={{ overflow: "visible" }}>
            <line x1="2" y1="7" x2="34" y2="7" stroke={CLR_DASH} strokeWidth="2.0" strokeDasharray="8 5" markerEnd="url(#km-dash)" />
          </svg>
          <span style={{ color: "var(--text)", fontWeight: 500 }}>Dashed Orange:</span> Possible Link (0.40–0.69)
        </span>
        <span className="km-leg-item">
          <svg width="44" height="14" style={{ overflow: "visible" }}>
            <line x1="2" y1="7" x2="34" y2="7" stroke={CLR_INF} strokeWidth="2.0" strokeDasharray="3 4" markerEnd="url(#km-inf)" />
          </svg>
          <span style={{ color: "var(--text)", fontWeight: 500 }}>Dotted Red:</span> Inferred Across Telemetry Gap
        </span>
      </div>
    </div>
  );
}
