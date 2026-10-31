import { useCallback, useEffect, useMemo, useState } from "react";
import { api, get, n, riskLevel, fmtTime, dur, hhmm } from "./lib.js";
import { IncidentList, RightPanel } from "./components/Side.jsx";
import KillMap from "./components/KillMap.jsx";
import Timeline from "./components/Timeline.jsx";
import Story from "./components/Story.jsx";
import { AttackGraph, HostHops } from "./components/Graphs.jsx";
import { LookAhead, BlastRadius, Excluded, Heatmap, StepsTable, Response } from "./components/Panels.jsx";
import Briefing, { RiskRing } from "./components/Overview.jsx";

function initTheme() {
  let t = null;
  try { t = localStorage.getItem("as-theme"); } catch { /* storage blocked */ }
  t ||= window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
  document.documentElement.dataset.theme = t;
  return t;
}
// Deep link: #i=<incident>&t=<tab>; empty hash = briefing
const hash = () => Object.fromEntries(new URLSearchParams(location.hash.slice(1)));

const TABS = [
  ["story", "Story", "The attack in plain terms and what to do now"],
  ["kill", "Kill map", "ATT&CK tactics × hosts"],
  ["time", "Timeline", "Steps on a real clock"],
  ["graph", "Graph", "Steps, hosts and the links between them"],
  ["look", "Reach next", "What the attacker could reach next"],
  ["attack", "ATT&CK", "Technique matrix and Navigator export"],
  ["evidence", "Evidence", "Steps, indicators, excluded lookalikes, gaps"],
  ["respond", "Respond", "Containment checklist and report"],
];

export default function App() {
  const [theme, setTheme] = useState(initTheme);
  const [stats, setStats] = useState(null);
  const [runs, setRuns] = useState(null);
  const [list, setList] = useState(null);
  const [review, setReview] = useState(false);
  const [error, setError] = useState(null);
  const [id, setId] = useState(() => (hash().i ? +hash().i : null));
  const [inc, setInc] = useState(null);
  const [report, setReport] = useState(null);
  const [timing, setTiming] = useState(null);
  const [tab, setTab] = useState(() => (TABS.some(([k]) => k === hash().t) ? hash().t : "story"));
  const [minConf, setMinConf] = useState(0.4);
  const [allLinks, setAllLinks] = useState(false);
  const [graphMode, setGraphMode] = useState("steps");
  const [replay, setReplay] = useState(999);
  const [playing, setPlaying] = useState(false);
  const [focus, setFocus] = useState(null);
  const [sel, setSel] = useState(null);
  const [narrOpen, setNarrOpen] = useState(true);
  useEffect(() => { if (focus) setNarrOpen(true); }, [focus]);

  const toggleTheme = () => {
    const t = theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = t;
    try { localStorage.setItem("as-theme", t); } catch { /* storage blocked */ }
    setTheme(t);
  };

  useEffect(() => { history.replaceState(null, "", id != null ? `#i=${id}&t=${tab}` : location.pathname); }, [id, tab]);
  useEffect(() => { get("/stats").then(setStats).catch(() => setStats(null)); }, []);
  useEffect(() => { get("/runs").then(setRuns).catch(() => setRuns(null)); }, []);
  // switching run reloads the page: every view then reads the new run from the API
  const switchRun = (run) => fetch(`/reload?run=${encodeURIComponent(run)}`, { method: "POST" })
    .then((r) => { if (!r.ok) throw new Error(`cannot open run ${run}`); location.hash = ""; location.reload(); })
    .catch((e) => setError(e.message));
  useEffect(() => {
    get(`/incidents${review ? "?include_review=true" : ""}`).then((d) => { setList(d); setError(null); }).catch((e) => setError(e.message));
  }, [review]);
  useEffect(() => {
    if (id == null) { setInc(null); setReport(null); return; }
    let live = true;
    Promise.all([api(`/incidents/${id}`), get(`/incidents/${id}/report`)])
      .then(([r, rep]) => {
        if (!live) return;
        setInc(r.data); setReport(rep); setTiming(r);
        setReplay(r.data.steps.length); setPlaying(false); setFocus(null); setSel(null);
      })
      .catch((e) => setError(e.message));
    return () => { live = false; };
  }, [id]);
  useEffect(() => {
    if (!playing || !inc) return;
    if (replay >= inc.steps.length) { setPlaying(false); return; }
    const t = setTimeout(() => setReplay((r) => r + 1), 700);
    return () => clearTimeout(t);
  }, [playing, replay, inc]);

  const evStep = useMemo(() => {
    const m = new Map();
    inc?.steps.forEach((s) => s.evidence.forEach((e) => m.has(e) || m.set(e, s.order)));
    return m;
  }, [inc]);
  const stepOf = (o) => inc.steps.find((s) => s.order === o);

  const onStep = (order) => {
    const s = stepOf(order);
    if (!s) return;
    setSel(order);
    setFocus({ title: `Step ${order} · ${s.technique_name || s.technique}`, ids: s.evidence, step: s });
  };
  const onEvidence = (ids, title = "Evidence", note) => { setSel(evStep.get(ids[0]) ?? null); setFocus({ title, ids, note }); };
  const onEdge = (e) => {
    const a = stepOf(+e.src.slice(4)), b = stepOf(+e.dst.slice(4));
    setSel(null);
    setFocus({ title: `Step ${a?.order} → step ${b?.order}`, edge: e, ids: [...(a?.evidence.slice(0, 2) || []), ...(b?.evidence.slice(0, 2) || [])],
      note: `${a?.technique_name || ""} → ${b?.technique_name || ""}` });
  };
  const onGraphTap = (d) => {
    if (!d) return;
    if (d.kind === "step") onStep(d.order);
    else if (d.kind === "context") onEvidence([d.evidence], `Context event · ${d.label}`, `Pulled in by the tracer: ${d.why}`);
    else if (d.kind === "logon") onEvidence([d.evidence], `Logon hop · ${d.user || "?"} at ${hhmm(d.time)}`);
    else if (d.kind === "evidence") onEdge({ src: d.source, dst: d.target, confidence: d.confidence, reasons: d.reasons, inferred: d.inferred });
    else if (d.kind === "host" || d.kind === "external") {
      const name = d.id.slice(5);
      const ev = (inc.hops || []).filter((h) => h.to === name || h.from === name).map((h) => h.evidence);
      if (ev.length) onEvidence(ev, `Logons involving ${name}`);
    }
  };
  const closeFocus = useCallback(() => { setFocus(null); setSel(null); }, []);
  const select = (i) => { setId(i); setTab("story"); window.scrollTo(0, 0); };
  const home = () => { setId(null); setFocus(null); };
  const play = () => { if (playing) return setPlaying(false); if (replay >= inc.steps.length) setReplay(1); setPlaying(true); };

  const p = stats?.processed || {}, c = stats?.counts || {};
  const briefing = id == null;
  const br = inc?.blast_radius || {};
  const counts = inc ? { look: br.potential?.potential_hosts?.length, evidence: inc.steps.length } : {};

  return (
    <div className={`app${briefing ? " is-briefing" : ""}`}>
      <header className="topbar">
        <button className="brand" onClick={home} aria-label="AttackStory home">
          <span className="brand-mark"><svg width="14" height="14" viewBox="0 0 16 16"><path d="M2 12l4-4 3 3 5-6" stroke="#fff" strokeWidth="2.2" fill="none" strokeLinecap="round" strokeLinejoin="round" /></svg></span>
          AttackStory
        </button>
        {runs?.runs?.length > 1 && (
          <select className="run-pick" value={runs.active} onChange={(e) => switchRun(e.target.value)} aria-label="Results run" title="Results run (finished engine runs under results/)">
            {runs.runs.map((r) => <option key={r.run} value={r.run}>{r.run} · {r.attack_incidents} attack · {r.review_incidents} review</option>)}
          </select>)}
        {stats && <span className="top-meta">{!(runs?.runs?.length > 1) && <span className="chip outline">{stats.dataset}</span>}{n(p.events)} events · {p.seconds}s · <b className="crit-txt">{c.attack_incidents} attacks</b></span>}
        <span className="spacer" />
        {timing && !briefing && <span className="chip low" title="Time to open this incident (target under 500 ms)">⚡ {Math.round(timing.ms)} ms</span>}
        <button className="btn ghost" onClick={toggleTheme} aria-label="Toggle theme">{theme === "dark" ? "☀" : "☾"}</button>
      </header>

      {error && <div className="banner" style={{ margin: 16 }}><div><b>Cannot reach the AttackStory API</b>{error}. Start it with <code>python -m engine.api</code> (newest run under results/) or <code>python -m engine.api results/&lt;run&gt;</code>.</div></div>}

      {briefing ? (
        <main className="page"><Briefing stats={stats} list={list} onSelect={select} review={review} setReview={setReview} /></main>
      ) : (
        <div className={`main${narrOpen ? "" : " narr-closed"}`}>
          <IncidentList list={list} selected={id} onSelect={select} onHome={home} />
          <main className="col col-center">
            {!inc ? <div className="empty">Loading incident…</div> : (
              <>
                <div className="inc-header">
                  <RiskRing risk={inc.risk} size={68} />
                  <div className="inc-title-block">
                    <div className="row" style={{ gap: 8 }}>
                      <span className="muted small">Incident #{inc.incident_id}</span>
                      <span className={`chip ${inc.verdict === "attack" ? "crit" : "med"}`}>{inc.verdict === "attack" ? "likely attack" : "needs review"}</span>
                      {inc.injection_flags?.length > 0 && <span className="chip crit">⚠ AI-injection attempt in logs</span>}
                    </div>
                    <h1>{inc.steps[0]?.technique_name} <span className="faint">→</span> {inc.steps.at(-1)?.technique_name}</h1>
                    <div className="facts">
                      <span><b>{dur(Date.parse(inc.last_seen) - Date.parse(inc.first_seen))}</b> from first to last step</span>
                      <span><b>{br.confirmed?.hosts?.length || 0}</b> hosts</span>
                      <span><b>{br.confirmed?.users?.length || 0}</b> accounts</span>
                      <span><b>{inc.stages.length}</b> kill-chain stages</span>
                      <span className="faint">{fmtTime(inc.first_seen)} UTC</span>
                    </div>
                  </div>
                  <div className="row header-actions">
                    <a className="btn" href={`/incidents/${inc.incident_id}/report?format=md`} target="_blank" rel="noreferrer">Report ↗</a>
                    <a className="btn" href={`/incidents/${inc.incident_id}/navigator`} download title="ATT&CK Navigator layer">Navigator ↓</a>
                  </div>
                </div>

                {inc.injection_flags?.length > 0 && (
                  <div className="banner">
                    <div>
                      <b>Someone wrote instructions to an AI inside the logs</b>
                      {inc.injection_flags.length} log field{inc.injection_flags.length > 1 ? "s" : ""} contain text like <q>{inc.injection_flags[0].match}</q>. It is treated as attacker data and
                      cannot change the verdict.{" "}
                      <button className="cite" onClick={() => onEvidence(inc.injection_flags.map((f) => f.evidence), "Injection attempt")}>show the logs</button>
                    </div>
                  </div>
                )}

                <nav className="tabs" role="tablist">
                  {TABS.map(([k, label, hint]) => (
                    <button key={k} role="tab" title={hint} aria-selected={tab === k} className={`tab${tab === k ? " on" : ""}`} onClick={() => setTab(k)}>
                      {label}{counts[k] != null && <span className="count">{counts[k]}</span>}
                    </button>))}
                </nav>

                {["kill", "graph", "time"].includes(tab) && (
                  <div className="toolbar">
                    {tab === "kill" && (
                      <div className="seg">
                        <button className={!allLinks ? "on" : ""} onClick={() => setAllLinks(false)}>Main path</button>
                        <button className={allLinks ? "on" : ""} onClick={() => setAllLinks(true)}>All links</button>
                      </div>)}
                    {tab === "graph" && (
                      <div className="seg">
                        <button className={graphMode === "steps" ? "on" : ""} onClick={() => setGraphMode("steps")}>Steps & hosts</button>
                        <button className={graphMode === "hops" ? "on" : ""} onClick={() => setGraphMode("hops")}>Machines only</button>
                      </div>)}
                    {(tab === "graph" && graphMode === "steps") || (tab === "kill" && allLinks) ? (
                      <label>Min. link confidence
                        <input type="range" min="0.4" max="1" step="0.05" value={minConf} onChange={(e) => setMinConf(+e.target.value)} />
                        <span className="val">{minConf.toFixed(2)}</span>
                      </label>) : null}
                    {!(tab === "graph" && graphMode === "hops") && (
                      <label>
                        <button className="btn sm" onClick={play}>{playing ? "❚❚ Pause" : "▶ Replay attack"}</button>
                        <input type="range" min="1" max={inc.steps.length} value={Math.min(replay, inc.steps.length)} onChange={(e) => { setPlaying(false); setReplay(+e.target.value); }} aria-label="Replay position" />
                        <span className="val">{Math.min(replay, inc.steps.length)}/{inc.steps.length}</span>
                      </label>)}
                    {tab === "kill" && <span className="legend"><span><span className="swatch-line" /> linked</span><span><span className="swatch-line dash" /> possible</span><span>colour = tactic</span></span>}
                  </div>
                )}

                {tab === "story" && <Story inc={inc} report={report} onStep={onStep} onEvidence={onEvidence} goto={setTab} />}
                {tab === "kill" && <KillMap inc={inc} minConf={minConf} allLinks={allLinks} replay={replay} selected={sel} onStep={onStep} onEdge={onEdge} />}
                {tab === "time" && <Timeline inc={inc} replay={replay} selected={sel} onStep={onStep} onEvidence={onEvidence} />}
                {tab === "graph" && (graphMode === "steps"
                  ? <AttackGraph inc={inc} theme={theme} minConf={minConf} replay={replay} selected={sel ? `step${sel}` : null} onTap={onGraphTap} />
                  : <HostHops inc={inc} theme={theme} onEvidence={onEvidence} />)}
                {tab === "look" && <LookAhead inc={inc} theme={theme} />}
                {tab === "attack" && <Heatmap inc={inc} onStep={onStep} />}
                {tab === "evidence" && (
                  <>
                    <div className="section-row"><h2>Labelled steps</h2><span className="muted small">every step with its technique, stage and label source</span></div>
                    <StepsTable inc={inc} selected={sel} onStep={onStep} />
                    <div className="section-row"><h2>Blast radius & indicators</h2></div>
                    <BlastRadius inc={inc} />
                    <div className="section-row"><h2>What was left out, and why</h2></div>
                    <Excluded inc={inc} onEvidence={onEvidence} />
                  </>
                )}
                {tab === "respond" && <Response key={inc.incident_id} inc={inc} actions={report?.actions} />}
              </>
            )}
          </main>
          <RightPanel report={report} focus={focus} onEvidence={onEvidence} onClose={closeFocus} open={narrOpen} setOpen={setNarrOpen} />
        </div>
      )}
    </div>
  );
}
