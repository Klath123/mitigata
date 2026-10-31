import { useState } from "react";
import { ReachGraph } from "./Graphs.jsx";
import { TACTICS, tacticColor, fmtTime, hhmmss, shortEv, critLevel } from "../lib.js";

const Chips = ({ items, cls = "", max = 60, empty = "none" }) =>
  items?.length ? <div>{items.slice(0, max).map((x) => <span key={x} className={`chip ${cls}`}>{x}</span>)}{items.length > max && <span className="chip outline">+{items.length - max} more</span>}</div>
    : <span className="muted small">{empty}</span>;

/* ---------------------------------------------------------------- look-ahead (FR-6) */
export function LookAhead({ inc, theme }) {
  const la = inc.look_ahead || [];
  const pot = inc.blast_radius?.potential || {};
  if (!la.length) return <div className="card empty">No further reach was observed in the logs for this incident.</div>;
  return (
    <>
      <div className="banner warn">
        <div><b>{pot.potential_hosts?.length || 0} more hosts are within reach</b>
          through {pot.at_risk_accounts?.length || 0} at-risk accounts. Built from the logs alone: "observed admin access" means logs show
          what accounts did, not everything they are allowed to do.</div>
      </div>
      <ReachGraph inc={inc} theme={theme} />
      <div className="grid2" style={{ marginTop: 14 }}>
        {la.map((a, i) => (
          <div className="card" key={i}>
            <div className="card-h">
              <h3>{a.account === "(network)" ? "Network reach" : a.account}</h3>
              <span className={`chip ${critLevel(a.max_criticality || 0)}`}>criticality {Number(a.max_criticality ?? 0).toFixed(2)}</span>
              <span className="chip outline">{a.shortest_hops} hop{a.shortest_hops === 1 ? "" : "s"}</span>
            </div>
            <div className="small muted" style={{ marginBottom: 8 }}>{a.kind}{a.exposed_on?.length ? ` · credentials exposed on ${a.exposed_on.join(", ")}` : ""}</div>
            <Chips items={a.can_reach} cls="high" />
            <p className="small" style={{ margin: "10px 0 0" }}>{a.why}</p>
          </div>
        ))}
      </div>
    </>
  );
}

/* ---------------------------------------------------------------- blast radius + indicators */
export function BlastRadius({ inc, onEvidence }) {
  const br = inc.blast_radius || {};
  const c = br.confirmed || {}, p = br.potential || {};
  const ke = inc.key_entities || {};
  const maxC = Math.max(1e-9, ...[...(ke.hosts || []), ...(ke.accounts || [])].map((x) => x.centrality));
  return (
    <>
      <div className="grid2">
        <div className="card"><div className="card-h"><h3>Confirmed hosts</h3><span className="sub">{c.hosts?.length || 0} touched by story edges</span></div><Chips items={c.hosts} cls="crit" /></div>
        <div className="card"><div className="card-h"><h3>Confirmed accounts</h3><span className="sub">reset & revoke sessions</span></div><Chips items={c.users} cls="crit" /></div>
        <div className="card"><div className="card-h"><h3>External IPs</h3><span className="sub">block at the perimeter</span></div><Chips items={c.external_ips} cls="crit" /></div>
        <div className="card"><div className="card-h"><h3>Files and shares</h3></div><Chips items={c.files_and_shares} max={30} /></div>
        <div className="card"><div className="card-h"><h3>Potential hosts</h3><span className="sub">reachable next</span></div><Chips items={p.potential_hosts} cls="high" /></div>
        <div className="card"><div className="card-h"><h3>At-risk accounts</h3></div><Chips items={p.at_risk_accounts} cls="med" /></div>
      </div>
      <div className="grid2" style={{ marginTop: 14 }}>
        <div className="card">
          <div className="card-h"><h3>Indicators to block and hunt</h3><span className="sub">shared across steps</span></div>
          {inc.indicators?.length ? (
            <table className="tbl"><thead><tr><th>Type</th><th>Value</th><th>Hits</th><th>Hosts</th></tr></thead>
              <tbody>{inc.indicators.map((x, i) => (
                <tr key={i}><td><span className="chip outline">{x.type}</span></td><td><code style={{ wordBreak: "break-all" }}>{x.value}</code></td><td>{x.hits}</td>
                  <td title={(x.host_list || []).join(", ")}>{x.hosts}</td></tr>))}</tbody></table>
          ) : <span className="muted small">No shared indicators.</span>}
        </div>
        <div className="card">
          <div className="card-h"><h3>Key entities</h3><span className="sub">betweenness centrality in the incident graph</span></div>
          <table className="tbl"><thead><tr><th>Entity</th><th>Hits</th><th style={{ width: "45%" }}>Centrality</th></tr></thead>
            <tbody>{[...(ke.hosts || []).map((x) => ({ ...x, t: "host" })), ...(ke.accounts || []).map((x) => ({ ...x, t: "account" }))]
              .sort((a, b) => b.centrality - a.centrality).map((x) => (
                <tr key={x.t + x.name}><td><span className="muted small">{x.t}</span> <b>{x.name}</b></td><td>{x.hits}</td>
                  <td><div className="row" style={{ flexWrap: "nowrap" }}><div className="mini-bar" style={{ flex: 1 }}><b style={{ width: `${(x.centrality / maxC) * 100}%` }} /></div><span className="mono small">{x.centrality}</span></div></td></tr>))}</tbody></table>
        </div>
      </div>
    </>
  );
}

/* ---------------------------------------------------------------- excluded + gaps */
export function Excluded({ inc, onEvidence }) {
  const ex = inc.excluded || [], gaps = inc.gaps || [];
  return (
    <>
      <div className="card">
        <div className="card-h"><h3>Considered and excluded</h3><span className="chip">{ex.length}</span>
          <span className="sub">lookalike activity that failed linkage, kept with the reason so precision is checkable</span></div>
        {ex.length ? (
          <div className="tbl-wrap"><table className="tbl">
            <thead><tr><th>Technique</th><th>Host</th><th>Account</th><th>Rule</th><th>Why it was left out</th><th>Evidence</th></tr></thead>
            <tbody>{ex.map((x, i) => (
              <tr key={i} className="click" onClick={() => onEvidence(x.evidence.slice(0, 5), `Excluded: ${x.technique} on ${x.host}`)}>
                <td><code>{x.technique}</code></td><td>{x.host}</td><td>{x.user || "—"}</td><td className="small muted">{x.rule}</td>
                <td>{x.reason}{x.other_cluster != null && <span className="chip outline">cluster {x.other_cluster}</span>}</td>
                <td>{x.evidence.slice(0, 2).map((e) => <span key={e} className="cite">{shortEv(e)}</span>)}</td>
              </tr>))}</tbody>
          </table></div>
        ) : <div className="muted small">No lookalike activity near this incident.</div>}
      </div>
      <div className="card">
        <div className="card-h"><h3>Logging gaps</h3><span className="sub">windows with no events from a story host; links that cross them are marked inferred</span></div>
        {gaps.length ? gaps.map((g, i) => (
          <div key={i} className="warn-item high">
            <b>{g.host}</b> silent {fmtTime(g.start)} → {fmtTime(g.end)} UTC
            {g.expected_events != null && <span className="muted"> · expected ~{g.expected_events} events</span>}
            <div className="small muted">edges crossing: {(g.crosses_edges || []).join(", ") || "none"}</div>
          </div>)) : <div className="muted small">No gaps detected on the incident hosts.</div>}
        {inc.data_quality?.warnings?.map((w, i) => <div key={"w" + i} className={`warn-item ${w.level || ""}`}>{w.text}</div>)}
      </div>
    </>
  );
}

/* ---------------------------------------------------------------- ATT&CK matrix heatmap */
export function Heatmap({ inc, onStep }) {
  const byTactic = {};
  for (const s of inc.steps) {
    const id = s.sub_technique || s.technique;
    const col = (byTactic[s.stage] ||= {});
    (col[id] ||= { id, name: s.technique_name, steps: [] }).steps.push(s);
  }
  const max = Math.max(1, ...Object.values(byTactic).flatMap((c) => Object.values(c).map((t) => t.steps.length)));
  const used = Object.values(byTactic).reduce((a, c) => a + Object.keys(c).length, 0);
  return (
    <div className="card">
      <div className="card-h"><h3>ATT&CK matrix</h3>
        <span className="sub">{used} techniques across {Object.keys(byTactic).length} of 14 tactics · darker = more steps</span>
        <span className="spacer" />
        <a className="btn sm" href={`/incidents/${inc.incident_id}/navigator`} download>Navigator layer ↓</a>
      </div>
      <div className="matrix">
        {TACTICS.map((t) => {
          const techs = Object.values(byTactic[t] || {});
          const c = tacticColor(t);
          return (
            <div className="mcol" key={t}>
              <div className="mhead" style={{ borderTopColor: c, opacity: techs.length ? 1 : 0.5 }}>{t}<small>{techs.length} technique{techs.length === 1 ? "" : "s"}</small></div>
              {techs.length ? techs.map((x) => {
                const a = 0.18 + 0.62 * (x.steps.length / max);
                return (
                  <div key={x.id} className="mcell" onClick={() => onStep(x.steps[0].order)} title={x.steps.map((s) => `${s.order}. ${s.host} ${hhmmss(s.time)}`).join("\n")}
                    style={{ background: c + Math.round(a * 255).toString(16).padStart(2, "0"), borderColor: c }}>
                    <code>{x.id}</code>{x.name}<div className="small" style={{ opacity: 0.8 }}>{x.steps.length} step{x.steps.length > 1 ? "s" : ""}</div>
                  </div>);
              }) : <div className="mempty" />}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- steps table */
const SRC = { sigma: "med", vendor: "high", rule: "accent", suggested: "outline" };
export function StepsTable({ inc, selected, onStep }) {
  return (
    <div className="card" style={{ padding: 0 }}>
      <div className="tbl-wrap" style={{ maxHeight: "none" }}><table className="tbl">
        <thead><tr><th>#</th><th>Time (UTC)</th><th>Host</th><th>Account</th><th>Technique</th><th>Stage</th><th>Label source</th><th>Evidence</th></tr></thead>
        <tbody>{inc.steps.map((s) => (
          <tr key={s.order} className={`click${selected === s.order ? " sel" : ""}`} onClick={() => onStep(s.order)}>
            <td><b>{s.order}</b></td><td className="mono nowrap" title={fmtTime(s.time) + " UTC"}>{hhmmss(s.time)}</td><td className="nowrap">{s.host}</td><td className="nowrap">{s.user || "—"}</td>
            <td><code>{s.sub_technique || s.technique}</code> {s.technique_name}<div className="small muted clamp2" title={s.summary}>{s.summary}</div></td>
            <td><span className="row" style={{ gap: 6, flexWrap: "nowrap" }}><span className="dot" style={{ background: tacticColor(s.stage) }} />{s.stage}</span></td>
            <td><span className={`chip ${SRC[s.label_source] || "outline"}`} title={s.rule}>{s.label_source}</span></td>
            <td>{s.evidence.length}</td>
          </tr>))}</tbody>
      </table></div>
    </div>
  );
}

/* ---------------------------------------------------------------- response checklist */
export function Response({ inc, actions }) {
  const [done, setDone] = useState({});
  const list = actions || [];
  const k = Object.values(done).filter(Boolean).length;
  return (
    <div className="card">
      <div className="card-h"><h3>Response checklist</h3><span className="sub">{k} / {list.length} done · derived from the blast radius, look-ahead and techniques</span>
        <span className="spacer" />
        <a className="btn sm" href={`/incidents/${inc.incident_id}/report?format=md`} target="_blank" rel="noreferrer">Full report (Markdown) ↗</a></div>
      {list.length ? list.map((a, i) => (
        <label key={i} className={`check${done[i] ? " done" : ""}`}>
          <input type="checkbox" checked={!!done[i]} onChange={(e) => setDone({ ...done, [i]: e.target.checked })} /><span>{a}</span>
        </label>)) : <div className="muted small">No recommended actions available.</div>}
    </div>
  );
}
