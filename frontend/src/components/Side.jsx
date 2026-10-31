import { Fragment, useEffect, useState } from "react";
import { get, riskLevel, fmtTime, hhmm, tacticColor } from "../lib.js";

/* ---------------------------------------------------------------- incident rail (left) */
export function IncidentList({ list, selected, onSelect, onHome }) {
  const [q, setQ] = useState("");
  const items = (list?.incidents || []).filter((i) => !q || [i.incident_id, i.entry, i.outcome, ...i.path, ...i.stages].join(" ").toLowerCase().includes(q.toLowerCase()));
  return (
    <aside className="col-left">
      <div className="list-head">
        <button className="btn ghost back" onClick={onHome}>← Briefing</button>
        <input className="search" placeholder="Filter attacks" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter incidents" />
      </div>
      <div className="list">
        {items.map((i) => (
          <button key={i.incident_id} className={`inc${selected === i.incident_id ? " sel" : ""}`} onClick={() => onSelect(i.incident_id)}>
            <div className="inc-top">
              <span className={`risk-badge ${riskLevel(i.risk)}`}>{i.risk.toFixed(2)}</span>
              <span className="muted small">#{i.incident_id}</span>
              {i.verdict !== "attack" && <span className="chip med">review</span>}
              <span className="spacer" />
              {i.injection_flags > 0 && <span className="chip crit" title="Instruction-like text found in log fields">⚠</span>}
            </div>
            <div className="inc-title">{i.entry} → {i.outcome}</div>
            <div className="inc-path">{i.path.join(" → ")}</div>
            <div className="stage-strip thin">{i.stages.map((s) => <span key={s} title={s} style={{ background: tacticColor(s) }} />)}</div>
          </button>
        ))}
        {list && !items.length && <div className="empty small">No incident matches.</div>}
      </div>
    </aside>
  );
}

/* ---------------------------------------------------------------- narrative + evidence drawer (right) */
const SECTIONS = { summary: "Summary", timeline: "What happened", movement: "Movement", look_ahead: "Could reach next", gaps: "Logging gaps", impact: "Impact" };
const TIME = /^(\d{4}-\d{2}-\d{2} )?(\d{2}:\d{2}) UTC: /;

export function RightPanel({ report, focus, onEvidence, onClose, open: panelOpen, setOpen: setPanelOpen }) {
  const [observedOnly, setObservedOnly] = useState(false);
  const [open, setOpen] = useState({});
  useEffect(() => setOpen({}), [report]);
  const sents = (report?.sentences || []).filter((s) => s.section !== "summary" && (!observedOnly || s.kind === "observed"));
  let last = null;
  if (!panelOpen) return (
    <aside className="col-right narr-rail">
      <button className="btn sm" onClick={() => setPanelOpen(true)} title="Show the narrative">◂ Narrative</button>
    </aside>
  );
  return (
    <aside className="col-right">
      <div className="right-head">
        <div className="row">
          <h3>Narrative</h3>
          <span className="spacer" />
          <button className="btn sm ghost" onClick={() => setPanelOpen(false)} title="Hide the narrative to widen the view" aria-label="Hide narrative">▸</button>
          {report && <span className={`chip ${report.grounding_rate >= 0.95 ? "low" : "med"}`} title="Share of sentences that passed the citation checker: every name, time and technique matches a cited log line">
            ✓ {Math.round((report.grounding_rate ?? 0) * 100)}% grounded</span>}
        </div>
        <div className="row small muted" style={{ justifyContent: "space-between" }}>
          <span>Written from the graph · {report?.source || "template"}</span>
          <label className="row" style={{ gap: 5 }}><input type="checkbox" checked={observedOnly} onChange={(e) => setObservedOnly(e.target.checked)} /> observed only</label>
        </div>
      </div>
      <div className="narr">
        {!report && <div className="empty">Select an incident.</div>}
        {sents.map((s, i) => {
          const head = s.section !== last ? <h4>{SECTIONS[s.section] || s.section}</h4> : null;
          last = s.section;
          const m = s.text.match(TIME);
          const text = m ? s.text.slice(m[0].length) : s.text;
          return (
            <Fragment key={i}>
              {head}
              <div className={`sent ${s.kind}${open[i] ? " open" : ""}`} onClick={() => setOpen({ ...open, [i]: !open[i] })}>
                {m && <span className="sent-time">{m[2]}</span>}
                <span className="sent-text">{text}{s.kind === "inferred" && <em> (inferred)</em>}</span>
                <button className="cite" onClick={(e) => { e.stopPropagation(); onEvidence(s.citations, "Cited evidence"); }}>{s.citations.length} log{s.citations.length > 1 ? "s" : ""}</button>
              </div>
            </Fragment>
          );
        })}
      </div>
      {focus && <Drawer focus={focus} onClose={onClose} />}
    </aside>
  );
}

const FIELDS = ["host", "user", "event_type", "process", "parent", "cmdline", "target", "src_ip", "dst_ip", "message", "format"];
const PAGE = 6;

function highlight(raw, ev) {
  const vals = [...new Set(["host", "user", "src_ip", "dst_ip", "process", "target"].map((k) => ev[k]).filter((v) => v && String(v).length >= 3).map(String))];
  if (!raw || !vals.length) return raw;
  const re = new RegExp(`(${vals.map((v) => v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\\\\/g, "\\\\{1,2}")).join("|")})`, "gi");
  return String(raw).split(re).map((part, i) => (i % 2 ? <mark key={i}>{part}</mark> : part));
}

function Drawer({ focus, onClose }) {
  const [shown, setShown] = useState(PAGE);
  const [events, setEvents] = useState({});
  const ids = focus.ids || [];
  useEffect(() => { setShown(PAGE); setEvents({}); }, [focus]);
  useEffect(() => {
    let live = true;
    ids.slice(0, shown).filter((id) => !(id in events)).forEach((id) =>
      get(`/events/${encodeURI(id)}`).catch(() => ({ evidence_id: id, missing: true })).then((e) => live && setEvents((m) => ({ ...m, [id]: e }))));
    return () => { live = false; };
  }, [focus, shown]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    const k = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);

  const s = focus.step, e = focus.edge;
  return (
    <div className="drawer" role="dialog" aria-label="Evidence">
      <div className="drawer-head">
        <button className="btn sm ghost" onClick={onClose} aria-label="Back to narrative">←</button>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div className="drawer-kicker">Evidence · {ids.length} log line{ids.length === 1 ? "" : "s"}</div>
          <h3 title={focus.title}>{focus.title}</h3>
        </div>
      </div>
      <div className="drawer-body">
        {s && (
          <div className="fact-box" style={{ borderLeftColor: tacticColor(s.stage) }}>
            <div className="small muted">{s.stage} · {fmtTime(s.time)} UTC</div>
            <div className="fact-title"><code>{s.sub_technique || s.technique}</code> {s.technique_name}</div>
            <div>{s.summary}</div>
            <div className="small muted" style={{ marginTop: 6 }}>{s.host}{s.user ? ` · ${s.user}` : ""} · detected by <code>{s.rule}</code> ({s.label_source})</div>
          </div>
        )}
        {e && (
          <div className="fact-box">
            <div className="small muted">Why these steps are linked</div>
            <div className="fact-title">Confidence {e.confidence} · {e.inferred ? "inferred across a logging gap" : e.confidence >= 0.7 ? "linked" : "possible"}</div>
            <div>{(e.reasons || []).map((r) => <span key={r} className="chip outline">{r.replace(/_/g, " ")}</span>)}</div>
          </div>
        )}
        {focus.note && <p className="small muted" style={{ marginTop: 0 }}>{focus.note}</p>}
        {ids.slice(0, shown).map((id) => {
          const ev = events[id];
          return (
            <div className="ev" key={id}>
              <div className="ev-id"><span>{id}</span>{ev?.ts && <span className="faint">{hhmm(new Date(ev.ts).toISOString())}:{new Date(ev.ts).toISOString().slice(17, 19)} UTC</span>}</div>
              {!ev ? <div className="muted small">Loading…</div> : ev.missing ? <div className="muted small">Not in the evidence index for this run.</div> : (
                <>
                  <div className="kv">{FIELDS.filter((k) => ev[k] != null && ev[k] !== "").map((k) => <Fragment key={k}><div>{k}</div><div className={k === "cmdline" ? "mono" : ""}>{String(ev[k])}</div></Fragment>)}</div>
                  {ev.raw && <details className="raw-wrap" open><summary>Raw log line</summary><pre className="raw">{highlight(ev.raw, ev)}</pre></details>}
                </>
              )}
            </div>
          );
        })}
        {ids.length > shown && <button className="btn sm" onClick={() => setShown(shown + PAGE)}>Show {Math.min(PAGE, ids.length - shown)} more of {ids.length - shown}</button>}
      </div>
    </div>
  );
}
