import { useEffect, useState } from "react";
import { get, n, riskLevel, fmtTime } from "../lib.js";

const KINDS = [["", "All"], ["account", "Accounts"], ["host", "Hosts / endpoints"], ["external_ip", "Internet addresses"]];
const KIND_LABEL = { account: "account", host: "host", external_ip: "internet" };
const ts = (ms) => (ms ? new Date(ms).toISOString().slice(0, 16).replace("T", " ") : "—");

// The knowledge base's memory (engine/kb.py): incidents as they grew across batches, and every entity it has seen.
export default function KnowledgeBase({ kb, list, onSelect }) {
  const [q, setQ] = useState("");
  const [kind, setKind] = useState("");
  const [only, setOnly] = useState("");
  const [data, setData] = useState(null);
  useEffect(() => {
    const t = setTimeout(() => {
      const p = new URLSearchParams({ q, kind, only, limit: "300" });
      get(`/kb/entities?${p}`).then(setData).catch(() => setData(false));
    }, 200);
    return () => clearTimeout(t);
  }, [q, kind, only]);
  const batches = kb.batches.map((b) => b.run);
  const incs = list?.incidents || [];

  return (
    <>
      <div className="section-row"><h2>Incidents across batches</h2><span className="muted small">each row is one incident; a filled box = that batch added to it</span></div>
      <div className="tbl-wrap" style={{ marginBottom: 18 }}><table className="tbl kb-grid">
        <thead><tr><th>#</th><th>Risk</th><th>What</th>{batches.map((b) => <th key={b} className="kb-b">{b}</th>)}<th>First seen</th><th>Last seen</th></tr></thead>
        <tbody>{incs.map((i) => (
          <tr key={i.incident_id} className="click" onClick={() => onSelect(i.incident_id)}>
            <td>{i.incident_id}</td>
            <td><b className={`risk ${riskLevel(i.risk)}`} style={{ fontSize: 13 }}>{i.risk.toFixed(2)}</b>{i.verdict !== "attack" && <span className="chip med" style={{ marginLeft: 6 }}>review</span>}</td>
            <td>{i.entry} → {i.outcome}</td>
            {batches.map((b) => {
              const on = i.kb?.batches?.includes(b);
              const made = i.kb?.created_run === b;
              return <td key={b} className="kb-b"><span className={`kb-cell${on ? " on" : ""}${made ? " made" : ""}`} title={on ? (made ? `created in ${b}` : `grew in ${b}`) : `not in ${b}`} /></td>;
            })}
            <td className="small">{fmtTime(i.first_seen)}</td><td className="small">{fmtTime(i.last_seen)}</td>
          </tr>))}
          {!incs.length && <tr><td colSpan={5 + batches.length} className="muted">No open incidents.</td></tr>}
        </tbody>
      </table></div>

      <div className="section-row">
        <h2>What the knowledge base remembers</h2>
        {data && <span className="muted small">{n(data.counts.account)} accounts · {n(data.counts.host)} hosts · {n(data.counts.external_ip)} internet addresses · <b>{n(data.new_in_latest_batch)}</b> new in the latest batch</span>}
      </div>
      <div className="kb-filters">
        <input className="search" placeholder="Search a name, account or IP" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search entities" />
        <div className="seg" role="group" aria-label="Entity type">
          {KINDS.map(([k, label]) => <button key={k} className={`btn sm${kind === k ? " on" : " ghost"}`} onClick={() => setKind(k)}>{label}</button>)}
        </div>
        <label className="small row" style={{ gap: 5 }}><input type="checkbox" checked={only === "incidents"} onChange={(e) => setOnly(e.target.checked ? "incidents" : "")} /> in an incident</label>
        <label className="small row" style={{ gap: 5 }}><input type="checkbox" checked={only === "new"} onChange={(e) => setOnly(e.target.checked ? "new" : "")} /> new in latest batch</label>
      </div>
      {data === false && <div className="warn-item med">Entity memory is not available for this run.</div>}
      {data && (
        <div className="tbl-wrap" style={{ maxHeight: 460 }}><table className="tbl">
          <thead><tr><th>Name</th><th>Type</th><th>First seen (UTC)</th><th>Last seen (UTC)</th><th>Batches</th><th>Detections</th><th>Incidents</th></tr></thead>
          <tbody>{data.entities.map((e) => (
            <tr key={e.kind + e.name}>
              <td><code>{e.name}</code>{e.new_in_latest_batch && <span className="chip accent" style={{ marginLeft: 6 }}>new</span>}</td>
              <td className="small muted">{KIND_LABEL[e.kind]}</td>
              <td className="small">{ts(e.first_seen)}</td><td className="small">{ts(e.last_seen)}</td>
              <td>{e.batches}</td><td>{n(e.hits)}</td>
              <td>{e.incidents.length ? e.incidents.map((id) => <button key={id} className="chip outline" onClick={() => onSelect(id)}>#{id}</button>) : <span className="faint">—</span>}</td>
            </tr>))}
            {!data.entities.length && <tr><td colSpan={7} className="muted">Nothing matches.</td></tr>}
          </tbody>
        </table>
        {data.matched > data.entities.length && <div className="small muted" style={{ padding: 8 }}>Showing {data.entities.length} of {n(data.matched)}: narrow the search.</div>}
        </div>
      )}
    </>
  );
}
