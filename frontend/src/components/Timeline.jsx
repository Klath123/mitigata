import { Fragment, useMemo } from "react";
import { tacticColor, fmtTime, hhmm, hhmmss, dur } from "../lib.js";

const W = 1000, LX = 110, PAD = 24, LANE = 44, TOP = 30;

// Time is the truth: steps on a real time axis per host, logon hops as arrows between lanes, log gaps shaded.
export default function Timeline({ inc, replay, selected, onStep, onEvidence }) {
  const M = useMemo(() => {
    const ts = inc.steps.map((s) => Date.parse(s.time));
    const t0 = Math.min(...ts), t1 = Math.max(...ts, t0 + 60_000);
    const hosts = [...new Set([...inc.path, ...inc.steps.map((s) => s.host)])].filter((h) => inc.steps.some((s) => s.host === h));
    const x = (t) => LX + PAD + ((t - t0) / (t1 - t0)) * (W - LX - PAD * 2);
    const y = (h) => TOP + hosts.indexOf(h) * LANE + LANE / 2;
    const ticks = Array.from({ length: 7 }, (_, i) => t0 + ((t1 - t0) * i) / 6);
    return { ts, t0, t1, hosts, x, y, ticks, H: TOP + hosts.length * LANE + 26 };
  }, [inc]);

  const gaps = inc.gaps || [];
  const dwell = M.t1 - M.t0;
  const deltas = M.ts.slice(1).map((t, i) => t - M.ts[i]);
  const longest = deltas.length ? Math.max(...deltas) : 0;

  return (
    <>
      <div className="counters">
        <div className="counter"><b>{dur(dwell)}</b><span>dwell time, first → last step</span></div>
        <div className="counter"><b>{dur(deltas.length ? dwell / deltas.length : 0)}</b><span>mean time between steps</span></div>
        <div className="counter"><b>{dur(longest)}</b><span>longest pause</span></div>
        <div className="counter"><b>{M.hosts.length}</b><span>hosts on the timeline</span></div>
        <div className={`counter${gaps.length ? " alert" : ""}`}><b>{gaps.length}</b><span>logging gaps</span></div>
      </div>

      <div className="viz" style={{ marginBottom: 14 }}>
        <svg viewBox={`0 0 ${W} ${M.H}`} width="100%" style={{ minWidth: 720 }} role="img" aria-label="Incident timeline by host">
          <defs><marker id="tl-a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0L10,5L0,10z" fill="var(--accent)" /></marker></defs>
          {M.hosts.map((h, i) => (
            <g key={h}>
              <rect x={LX} y={TOP + i * LANE + 4} width={W - LX - 8} height={LANE - 8} rx="5" fill="var(--panel2)" />
              <text x="10" y={M.y(h) + 4} fontSize="12" fontWeight="600">{h}</text>
            </g>
          ))}
          {gaps.filter((g) => M.hosts.includes(g.host)).map((g, i) => {
            const a = Math.max(LX, M.x(Date.parse(g.start))), b = Math.min(W - 8, M.x(Date.parse(g.end)));
            return (
              <rect key={i} x={a} y={M.y(g.host) - LANE / 2 + 4} width={Math.max(3, b - a)} height={LANE - 8} fill="var(--crit-soft)" stroke="var(--crit)" strokeDasharray="3 3">
                <title>{`${g.host} silent ${fmtTime(g.start)} → ${fmtTime(g.end)} (expected ~${g.expected_events} events)`}</title>
              </rect>
            );
          })}
          {M.ticks.map((t, i) => (
            <g key={i}>
              <line x1={M.x(t)} x2={M.x(t)} y1={TOP - 2} y2={M.H - 22} stroke="var(--line)" />
              <text x={M.x(t)} y={M.H - 8} fontSize="10.5" textAnchor="middle" fill="var(--muted)">{hhmm(new Date(t).toISOString())}</text>
            </g>
          ))}
          {(inc.hops || []).map((h, i) => {
            const t = M.x(Date.parse(h.time));
            const y2 = M.y(h.to);
            const y1 = M.hosts.includes(h.from) ? M.y(h.from) : TOP - 14;
            if (!M.hosts.includes(h.to)) return null;
            return (
              <g key={i} style={{ cursor: "pointer" }} onClick={() => onEvidence([h.evidence], `Logon hop ${h.from} → ${h.to}`)}>
                <line x1={t} x2={t} y1={y1} y2={y2 + (y2 > y1 ? -11 : 11)} stroke="var(--accent)" strokeWidth="2" markerEnd="url(#tl-a)" />
                <title>{`${h.from} → ${h.to} as ${h.user || "?"} at ${fmtTime(h.time)}`}</title>
              </g>
            );
          })}
          {inc.steps.map((s, i) => (
            <g key={s.order} className={`svg-node${selected === s.order ? " sel" : ""}${s.order > replay ? " ghost" : ""}`} onClick={() => onStep(s.order)}>
              <circle className="nbox" cx={M.x(M.ts[i])} cy={M.y(s.host)} r="9" fill={tacticColor(s.stage)} stroke="var(--panel)" strokeWidth="2" />
              <text x={M.x(M.ts[i])} y={M.y(s.host) + 3.5} fontSize="9.5" fontWeight="700" textAnchor="middle" fill="#fff" style={{ pointerEvents: "none" }}>{s.order}</text>
              <title>{`${s.order}. ${fmtTime(s.time)} · ${s.host}\n${s.sub_technique || s.technique} ${s.technique_name || ""} (${s.stage})\n${s.summary}`}</title>
            </g>
          ))}
        </svg>
      </div>

      <div className="card">
        <div className="card-h"><h3>Step by step</h3><span className="sub">times in UTC · click a step for its log lines</span></div>
        <div className="tl-list">
          {inc.steps.map((s, i) => (
            <Fragment key={s.order}>
              {i > 0 && <div className="tl-item" style={{ cursor: "default" }}><div /><div className="tl-rail" /><div className="tl-gap">+{dur(deltas[i - 1])}{deltas[i - 1] === longest && longest > 0 ? " · longest pause" : ""}</div></div>}
              <div className={`tl-item${selected === s.order ? " sel" : ""}${s.order > replay ? " ghost" : ""}`} onClick={() => onStep(s.order)}>
                <div className="tl-time">{hhmmss(s.time)}</div>
                <div className="tl-rail"><span className="dot" style={{ background: tacticColor(s.stage) }} /></div>
                <div className="tl-body">
                  <div className="row" style={{ gap: 6 }}>
                    <b>{s.order}.</b>
                    <span className="chip" style={{ background: tacticColor(s.stage) + "26", color: tacticColor(s.stage) }}>{s.stage}</span>
                    <code>{s.sub_technique || s.technique}</code><span>{s.technique_name}</span>
                    <span className="spacer" />
                    <span className="muted small">{s.host}{s.user ? ` · ${s.user}` : ""}</span>
                  </div>
                  <div className="muted small" style={{ marginTop: 3 }}>{s.summary}</div>
                </div>
              </div>
            </Fragment>
          ))}
        </div>
      </div>
    </>
  );
}
