import { useMemo } from "react";
import { TACTICS, tacticColor, fmtTime } from "../lib.js";

// Layout constants — increase vertical spacing so arrows have room to breathe
const CW = 190;   // column width: wider tactic lanes
const NW = 166;   // node width
const NH = 52;    // node height: taller so text doesn't clip
const GAP = 18;   // gap between stacked nodes in the same cell
const ROW_PAD = 28; // extra padding above/below each host row
const LX = 160;   // left gutter for host labels
const TY = 56;    // top gutter for tactic headers

// Kill map: ATT&CK tactics left→right, hosts top→bottom, so the path reads like a sentence and every
// hop between machines is visible. Edges are the evidence links (noisy-OR confidence) between steps.
// Solid edge   = confidence ≥ 0.70 (Noisy-OR fused; multiple independent clues agree)
// Dashed edge  = confidence 0.40–0.69 (plausible but single / weaker evidence)
// Dotted edge  = inferred across a telemetry gap (engine flagged e.inferred = true)
export default function KillMap({ inc, minConf, allLinks, replay, selected, onStep, onEdge }) {
  const L = useMemo(() => {
    const tactics = TACTICS.filter((t) => inc.steps.some((s) => s.stage === t));
    const extra = [...new Set(inc.steps.map((s) => s.stage).filter((t) => !TACTICS.includes(t)))];
    const lanes = [...tactics, ...extra];
    const hosts = [...new Set([...inc.path, ...inc.steps.map((s) => s.host)].filter((h) => inc.steps.some((s) => s.host === h)))];
    const roles = Object.fromEntries((inc.graph?.nodes || []).filter((x) => x.type === "host").map((x) => [x.label, x.role]));

    // Count how many steps land in each (host × tactic) cell to size rows correctly
    const cell = {};
    inc.steps.forEach((s) => { const k = `${s.host}|${s.stage}`; cell[k] = (cell[k] || 0) + 1; });

    // Each row is tall enough for its busiest column, plus top/bottom padding
    const rowH = hosts.map((h) =>
      ROW_PAD * 2 + Math.max(1, ...lanes.map((t) => cell[`${h}|${t}`] || 0)) * (NH + GAP) - GAP
    );
    const rowY = [];
    rowH.reduce((y, hgt, i) => ((rowY[i] = y), y + hgt + 20), TY); // 20px gap between host bands

    const H = rowY.at(-1) + rowH.at(-1) + 24;
    const W = LX + lanes.length * CW + 24;

    // Assign each step a pixel position inside its (host, tactic) cell
    const slot = {}, pos = {};
    for (const s of inc.steps) {
      const k = `${s.host}|${s.stage}`;
      const i = (slot[k] = (slot[k] || 0) + 1) - 1;
      pos[s.order] = {
        x: LX + lanes.indexOf(s.stage) * CW + (CW - NW) / 2,
        y: rowY[hosts.indexOf(s.host)] + ROW_PAD + i * (NH + GAP),
      };
    }
    const count = Object.fromEntries(hosts.map((h) => [h, inc.steps.filter((s) => s.host === h).length]));
    return { lanes, hosts, roles, rowY, rowH, H, W, pos, count };
  }, [inc]);

  // Filter edges by confidence threshold then pick best-link-per-destination (story spine)
  // or show all links when the "all links" toggle is on
  const linked = (inc.graph?.edges || []).filter(
    (e) => e.kind === "evidence" && e.confidence >= minConf && e.src.startsWith("step") && e.dst.startsWith("step")
  );
  const edges = allLinks
    ? linked
    : Object.values(
        linked.reduce((best, e) => {
          const b = best[e.dst];
          if (!b || e.confidence > b.confidence || (e.confidence === b.confidence && +e.src.slice(4) > +b.src.slice(4)))
            best[e.dst] = e;
          return best;
        }, {})
      );

  // Build the SVG cubic-Bézier path between two node rectangles.
  // — Forward (b is to the right): S-curve from right edge → left edge
  // — Backward (b is to the left): arc looping above so it doesn't hide behind nodes
  // — Same column: C-curve that fans to the right side with vertical offset
  const edgePath = (a, b, idx) => {
    const ay = a.y + NH / 2, by = b.y + NH / 2;
    if (b.x > a.x + 1) {
      // Forward: right edge of src → left edge of dst
      const x1 = a.x + NW, x2 = b.x - 6, m = (x2 - x1) / 2;
      return `M${x1},${ay} C${x1 + m},${ay} ${x2 - m},${by} ${x2},${by}`;
    }
    if (b.x < a.x - 1) {
      // Backward: arc loops above the map — fan out so multiple arcs don't overlap
      const x1 = a.x + NW / 2, x2 = b.x + NW / 2;
      const lift = 38 + idx * 14; // stagger each backward arc vertically
      const topY = Math.min(ay, by) - lift;
      return `M${x1},${ay} C${x1},${topY} ${x2},${topY} ${x2},${by}`;
    }
    // Same column, different row — fan edge to the right to avoid sitting on top of each other
    const fanX = a.x + NW + 30 + (idx % 3) * 14;
    return `M${a.x + NW},${ay} C${fanX},${ay} ${fanX},${by} ${b.x + NW},${by}`;
  };

  return (
    <div className="viz">
      <svg width={L.W} height={L.H} role="img" aria-label="Kill map: ATT&CK tactics by host">
        <defs>
          {/* Solid arrowhead — used for confirmed edges (confidence ≥ 0.70) */}
          <marker id="km-a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0L10,5L0,10z" fill="var(--edge)" />
          </marker>
          {/* Open arrowhead — used for dashed / possible edges (0.40–0.69) */}
          <marker id="km-d" viewBox="0 0 12 12" refX="10" refY="6" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
            <path d="M0,2L10,6L0,10" fill="none" stroke="var(--edge-dash)" strokeWidth="1.8" />
          </marker>
          {/* Dotted arrowhead — used for inferred edges crossing a telemetry gap */}
          <marker id="km-inf" viewBox="0 0 12 12" refX="10" refY="6" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
            <path d="M0,2L10,6L0,10" fill="none" stroke="var(--high)" strokeWidth="1.8" />
          </marker>
        </defs>

        {/* Tactic lane backgrounds */}
        {L.lanes.map((t, i) => (
          <g key={t}>
            <rect x={LX + i * CW + 3} y={TY - 10} width={CW - 6} height={L.H - TY + 4} rx="7" fill="var(--panel2)" />
            {/* Colour bar under the header text */}
            <rect x={LX + i * CW + 3} y={10} width={CW - 6} height={5} rx="2.5" fill={tacticColor(t)} />
            <text x={LX + i * CW + 12} y={34} fontSize="10" fontWeight="700"
              style={{ textTransform: "uppercase", letterSpacing: ".06em" }} fill="var(--muted)">
              {t}
            </text>
          </g>
        ))}

        {/* Host row dividers and labels */}
        {L.hosts.map((h, i) => (
          <g key={h}>
            {i > 0 && (
              <line x1="8" x2={L.W - 8} y1={L.rowY[i] - 10} y2={L.rowY[i] - 10}
                stroke="var(--line)" strokeDasharray="4 5" strokeWidth="1" />
            )}
            <text x="14" y={L.rowY[i] + 22} fontWeight="700" fontSize="13.5">{h}</text>
            <text x="14" y={L.rowY[i] + 40} fontSize="11" fill="var(--muted)">
              {L.roles[h] || "host"} · {L.count[h]} steps
            </text>
          </g>
        ))}

        {/* ── Edges (drawn before nodes so they sit underneath) ── */}
        {edges.map((e, i) => {
          const a = L.pos[+e.src.slice(4)], b = L.pos[+e.dst.slice(4)];
          if (!a || !b) return null;

          // Classify edge by Noisy-OR confidence
          const isInferred = !!e.inferred;                      // crosses a telemetry gap
          const isSolid    = e.style === "solid" && !isInferred && e.confidence >= 0.70;
          const isDashed   = !isSolid && !isInferred;

          const ghost = +e.src.slice(4) > replay || +e.dst.slice(4) > replay;

          // Visual encoding
          const stroke      = isInferred ? "var(--high)" : isSolid ? "var(--edge)" : "var(--edge-dash)";
          const strokeW     = isSolid ? 1.8 + (e.confidence - 0.70) / 0.30 * 1.2   // 1.8–3.0px for solid
                            : isDashed ? 1.4 + (e.confidence - 0.40) / 0.30 * 0.8   // 1.4–2.2px for dashed
                            : 1.4;
          const dashArray   = isInferred ? "3 4" : isDashed ? "8 5" : undefined;
          const marker      = isInferred ? "url(#km-inf)" : isSolid ? "url(#km-a)" : "url(#km-d)";
          const opacity     = ghost ? 0.07 : isInferred ? 0.80 : isSolid ? 0.85 : 0.65;

          const label = `${isSolid ? "✔ Solid" : isInferred ? "⚠ Inferred (gap)" : "~ Possible"} · confidence ${e.confidence}\n${(e.reasons || []).join(", ")}`;

          return (
            <path key={i} d={edgePath(a, b, i)} fill="none"
              stroke={stroke} strokeWidth={strokeW}
              strokeDasharray={dashArray}
              markerEnd={marker}
              opacity={opacity}
              style={{ cursor: "pointer" }}
              onClick={() => onEdge(e)}>
              <title>{label}</title>
            </path>
          );
        })}

        {/* ── Step nodes (drawn on top of edges) ── */}
        {inc.steps.map((s) => {
          const p = L.pos[s.order];
          const c = tacticColor(s.stage);
          const name = s.technique_name || s.stage;
          return (
            <g key={s.order}
              className={`svg-node${selected === s.order ? " sel" : ""}${s.order > replay ? " ghost" : ""}`}
              onClick={() => onStep(s.order)}
              tabIndex={0} role="button"
              aria-label={`Step ${s.order} ${s.technique} on ${s.host}`}
              onKeyDown={(ev) => ev.key === "Enter" && onStep(s.order)}>
              <rect className="nbox" x={p.x} y={p.y} width={NW} height={NH} rx="7"
                fill="var(--panel)" stroke={c} strokeWidth="1.8" />
              {/* Left colour bar */}
              <rect x={p.x} y={p.y} width="5" height={NH} rx="2.5" fill={c} />
              {/* Step order badge */}
              <circle cx={p.x + 22} cy={p.y + 17} r="10" fill={c} />
              <text x={p.x + 22} y={p.y + 21} textAnchor="middle" fontSize="10.5" fontWeight="800" fill="#fff">
                {s.order}
              </text>
              {/* Technique ID */}
              <text x={p.x + 38} y={p.y + 21} fontSize="12" fontWeight="700" fontFamily="var(--mono)">
                {s.sub_technique || s.technique}
              </text>
              {/* Technique name */}
              <text x={p.x + 12} y={p.y + 40} fontSize="10.5" fill="var(--muted)">
                {name.length > 27 ? name.slice(0, 26) + "…" : name}
              </text>
              <title>{`${fmtTime(s.time)} UTC · ${s.host}${s.user ? " · " + s.user : ""}\n${s.technique_name || ""} (${s.stage})\n${s.summary}\nlabel: ${s.label_source} · ${s.evidence.length} evidence line(s)`}</title>
            </g>
          );
        })}
      </svg>

      {/* Edge legend */}
      <div className="km-legend">
        <svg width="220" height="20">
          <line x1="8" y1="10" x2="44" y2="10" stroke="var(--edge)" strokeWidth="2" markerEnd="url(#km-a)" />
          <text x="50" y="14" fontSize="11" fill="var(--muted)">Solid (confidence ≥ 0.70)</text>
        </svg>
        <svg width="240" height="20">
          <line x1="8" y1="10" x2="44" y2="10" stroke="var(--edge-dash)" strokeWidth="1.6" strokeDasharray="8 5" markerEnd="url(#km-d)" />
          <text x="50" y="14" fontSize="11" fill="var(--muted)">Dashed (0.40–0.69 possible)</text>
        </svg>
        <svg width="240" height="20">
          <line x1="8" y1="10" x2="44" y2="10" stroke="var(--high)" strokeWidth="1.6" strokeDasharray="3 4" markerEnd="url(#km-inf)" />
          <text x="50" y="14" fontSize="11" fill="var(--muted)">Dotted (inferred across gap)</text>
        </svg>
      </div>
    </div>
  );
}
