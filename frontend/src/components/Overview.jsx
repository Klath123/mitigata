import { useEffect, useState } from "react";
import { get, n, bytes, riskLevel, fmtTime, dur, tacticColor } from "../lib.js";
import KnowledgeBase from "./KnowledgeBase.jsx";
import KnowledgeGraph from "./KnowledgeGraph.jsx";

const STAGE_COLORS = ["#3e8ef7", "#8b6cf6", "#1fb5a4", "#f0a52c", "#ec4f4f", "#d955c8", "#22a9d6"];

export function RiskRing({ risk, size = 64 }) {
  const r = size / 2 - 5, c = 2 * Math.PI * r;
  return (
    <svg width={size} height={size} className={`ring ${riskLevel(risk)}`} role="img" aria-label={`risk ${risk.toFixed(2)}`}>
      <circle cx={size / 2} cy={size / 2} r={r} className="ring-bg" />
      <circle cx={size / 2} cy={size / 2} r={r} className="ring-fg" strokeDasharray={`${c * risk} ${c}`} transform={`rotate(-90 ${size / 2} ${size / 2})`} />
      <text x="50%" y="53%" textAnchor="middle" dominantBaseline="middle" fontSize={size * 0.27} fontWeight="700">{risk.toFixed(2)}</text>
    </svg>
  );
}

// Landing page. Answers "what happened?" first, then "where do I look?", then the pipeline numbers.
export default function Briefing({ stats, list, onSelect, review, setReview }) {
  const [quality, setQuality] = useState(null);
  useEffect(() => { get("/quality").then(setQuality).catch(() => setQuality(false)); }, []);
  const p = stats?.processed || {}, c = stats?.counts || {};
  const attacks = (list?.incidents || []).filter((i) => i.verdict === "attack");
  const shown = list?.incidents || [];
  const top = attacks[0];
  const stages = Object.entries(stats?.stages_seconds || {});
  const total = stages.reduce((a, [, v]) => a + v, 0) || 1;
  const funnel = [["Events parsed", p.events], ["Rule matches (rows)", c.raw_hit_rows], ["Hunt hits (grouped)", c.hits], ["Clusters (linked hits)", c.clusters],
    ["To review (risk 0.4–0.7)", c.review_incidents], ["Attack incidents (risk ≥ 0.7)", c.attack_incidents]].filter(([, v]) => v != null);
  const fmax = Math.log10(Math.max(10, ...funnel.map(([, v]) => v || 0)));
  // stats.rules also holds summaries (_packs, _sigma): not rules. Silent rules are counted, not listed.
  const allRules = Object.entries(stats?.rules || {}).filter(([k, v]) => !k.startsWith("_") && v && typeof v === "object");
  const rules = allRules.filter(([, v]) => v.hits || v.error || v.disabled).sort((a, b) => (b[1].hits || 0) - (a[1].hits || 0));
  const kbInfo = list?.knowledge_base || stats?.knowledge_base;
  const dq = quality || stats?.data_quality;

  return (
    <div className="briefing">
      <section className="hero">
        <div className="hero-kicker">Hunt briefing · {stats?.dataset || "—"}</div>
        {list && (attacks.length ? (
          <h1><span className="hero-num">{attacks.length}</span> attack{attacks.length > 1 ? "s" : ""} found in {n(p.events)} log events</h1>
        ) : <h1>No confident attack found in {n(p.events)} events</h1>)}
        <p className="hero-sub">
          {kbInfo ? <>Knowledge base: everything still open across <b>{kbInfo.batches.length}</b> batches of logs. An attack that spans batches is one incident here.</>
            : c.hits != null ? <>No alerts were given. The engine ran {n(stats?.rules_loaded || allRules.length)} detection rules over the raw logs: {n(c.raw_hit_rows)} log lines matched,
              grouped into {n(c.hits)} hits and linked into {n(c.clusters)} clusters. A cluster becomes an attack only when it covers two or more attack stages
              with linked evidence (risk ≥ 0.7); weaker ones are listed for review.</> : null}
          {" "}Everything below is backed by a log line you can open.
        </p>
        {top && (
          <button className="btn primary lg" onClick={() => onSelect(top.incident_id)}>Start with the highest risk: incident #{top.incident_id} →</button>
        )}
      </section>

      <ol className="guide">
        <li><b>Pick an attack</b><span>Ranked by risk. Highest first.</span></li>
        <li><b>Follow the path</b><span>Entry point → machines → what was taken.</span></li>
        <li><b>Check the proof</b><span>Click any step to see its raw log line.</span></li>
        <li><b>Act</b><span>Contain, reset, block: the response list is ready.</span></li>
      </ol>

      <div className="section-row">
        <h2>Detected attacks</h2>
        <label className="small muted row" style={{ gap: 6 }}>
          <input type="checkbox" checked={review} onChange={(e) => setReview(e.target.checked)} /> also show clusters to review (risk 0.4–0.7)
        </label>
      </div>
      <div className="inc-grid">
        {shown.map((i) => (
          <button key={i.incident_id} className={`inc-card ${riskLevel(i.risk)}`} onClick={() => onSelect(i.incident_id)}>
            <div className="inc-card-top">
              <RiskRing risk={i.risk} />
              <div style={{ minWidth: 0 }}>
                <div className="row" style={{ gap: 6 }}>
                  <span className="muted small">Incident #{i.incident_id}</span>
                  {i.verdict !== "attack" && <span className="chip med">review</span>}
                  {i.injection_flags > 0 && <span className="chip crit">⚠ AI-injection attempt</span>}
                </div>
                <div className="inc-card-title">{i.entry} <span className="faint">→</span> {i.outcome}</div>
              </div>
            </div>
            <div className="mini-path">
              {i.external_source && <><span className="host-pill ext">{i.external_source}</span><span className="arrow">→</span></>}
              {i.path.map((h, k) => <span key={h + k} className="row" style={{ gap: 6 }}>{k > 0 && <span className="arrow">→</span>}<span className="host-pill">{h}</span></span>)}
            </div>
            <div className="stage-strip" title={i.stages.join(" → ")}>{i.stages.map((s) => <span key={s} style={{ background: tacticColor(s) }} />)}</div>
            <div className="inc-card-facts">
              <span><b>{i.stages_covered}</b> stages</span>
              <span><b>{i.hosts}</b> hosts</span>
              <span><b>{dur(Date.parse(i.last_seen) - Date.parse(i.first_seen))}</b> duration</span>
              <span className={i.could_reach ? "warn-txt" : ""}><b>{i.could_reach ?? 0}</b> could reach next</span>
            </div>
            <div className="inc-card-foot"><span className="faint small">{fmtTime(i.first_seen)} UTC · {i.alerts_merged} alerts merged</span><span className="open">Investigate →</span></div>
          </button>
        ))}
      </div>

      {kbInfo && (
        <>
          <div className="section-row"><h2>Batches in the knowledge base</h2><span className="muted small">{kbInfo.open_incidents} open incidents · {kbInfo.closed_incidents} closed (no new activity for 7 days)</span></div>
          <div className="tbl-wrap" style={{ marginBottom: 18 }}><table className="tbl">
            <thead><tr><th>Batch</th><th>Logs</th><th>Events</th><th>Attack</th><th>Review</th><th>Processed</th></tr></thead>
            <tbody>{[...kbInfo.batches].reverse().map((b) => (
              <tr key={b.run}><td><code>{b.run}</code></td><td>{b.dataset}</td><td>{n(b.events)}</td><td>{b.attack}</td><td>{b.review}</td>
                <td>{b.finished ? new Date(b.finished * 1000).toISOString().slice(0, 16).replace("T", " ") + " UTC" : "—"}</td></tr>))}</tbody>
          </table></div>
          <KnowledgeBase kb={kbInfo} list={list} onSelect={onSelect} />
        </>
      )}

      {stats && <KnowledgeGraph key={stats.dataset} onSelect={onSelect} />}

      <div className="section-row"><h2>How the hunt ran</h2><span className="muted small">processed in one streaming pass; every answer is precomputed</span></div>
      {!kbInfo && <div className="stat-grid">
        <div className="stat-tile"><b>{bytes(p.bytes)}</b><span>log data</span></div>
        <div className="stat-tile"><b>{n(p.events)}</b><span>events</span></div>
        <div className="stat-tile"><b>{p.seconds ?? "—"} s</b><span>processing time</span></div>
        <div className="stat-tile"><b>{p.peak_memory_gb ?? "—"} GB</b><span>peak memory</span></div>
        <div className="stat-tile"><b>{quality ? quality.quality_score : dq?.score ?? "—"}<small>/100</small></b><span>data quality</span></div>
      </div>}

      <details className="card details">
        <summary><b>Pipeline details</b><span className="muted small"> · stage timings, event funnel, data-quality warnings, cluster scores and rules</span></summary>
        <div className="details-body">
          {stages.length > 0 && <>
            <div className="section-title">Time per stage</div>
            <div className="stack" style={{ marginBottom: 18 }}>
              {stages.map(([k, v], i) => <div key={k} style={{ width: `${(v / total) * 100}%`, background: STAGE_COLORS[i % STAGE_COLORS.length] }} title={`${k}: ${v}s`}>{v / total > 0.1 ? `${k.replace(/_/g, " ")} ${v}s` : ""}</div>)}
            </div>
          </>}
          <div className="grid2">
            <div>
              <div className="section-title">From events to incidents (log scale)</div>
              <div className="funnel">
                {funnel.map(([k, v]) => (
                  <div className="funnel-row" key={k}><span className="muted">{k}</span>
                    <i style={{ width: `${(Math.log10(Math.max(1, v || 0)) / fmax) * 100}%`, background: k.includes("Attack") ? "var(--crit)" : "var(--accent)" }} /><b>{n(v)}</b></div>))}
              </div>
            </div>
            <div>
              <div className="section-title">Data quality</div>
              {dq?.warnings?.length ? dq.warnings.map((w, i) => <div key={i} className={`warn-item ${w.level}`}><b>{w.level}</b> · {w.text}</div>)
                : <div className="warn-item low">No data-quality problems found.</div>}
            </div>
          </div>
          <div className="section-title" style={{ marginTop: 18 }}>Cluster scores · S = 0.35·tactics + 0.20·order + 0.15·hosts + 0.20·severity + 0.10·rarity (each scaled 0–1)</div>
          <div className="small muted" style={{ marginBottom: 6 }}>Table shows raw values: tactics = distinct attack stages (full marks at 4), hosts = machines (full at 3), order = how well stages follow the kill chain.
            One stage or one labelled hit caps the risk below 0.4 (below 0.7 when driven from the internet). A multi-stage chain with a severe step on a critical asset is raised to 0.7.</div>
          <div className="tbl-wrap"><table className="tbl">
            <thead><tr><th>#</th><th>Risk</th><th>Tactics</th><th>Order</th><th>Hosts</th><th>Severity</th><th>Rarity</th><th>Raised</th><th>Alerts</th></tr></thead>
            <tbody>{shown.map((i) => { const b = i.score_breakdown || {}; return (
              <tr key={i.incident_id} className="click" onClick={() => onSelect(i.incident_id)}><td>{i.incident_id}</td><td><b className={`risk ${riskLevel(i.risk)}`} style={{ fontSize: 13 }}>{i.risk.toFixed(3)}</b></td>
                <td>{b.tactics}</td><td>{b.order}</td><td>{b.hosts}</td><td>{b.severity}</td><td>{b.rarity}</td>
                <td>{b.escalated_critical_asset ? <span className="chip high" title="multi-stage chain with a severe step on a critical asset">critical asset</span> : "—"}</td><td>{i.alerts_merged}</td></tr>); })}</tbody>
          </table></div>
          {rules.length > 0 && <>
            <div className="section-title" style={{ marginTop: 18 }}>Detection rules that fired: {rules.length} of {n(stats?.rules_loaded || allRules.length)} loaded (the rest found nothing)</div>
            <div className="tbl-wrap" style={{ maxHeight: 300 }}><table className="tbl">
              <thead><tr><th>Rule</th><th>Hits</th><th>Seconds</th><th>Status</th></tr></thead>
              <tbody>{rules.map(([k, v]) => (
                <tr key={k}><td><code>{k}</code></td><td>{n(v.hits)}</td><td>{v.seconds ?? "—"}</td>
                  <td>{v.error ? <span className="chip crit" title={v.error}>error</span>
                    : v.disabled ? <span className="chip outline" title={String(v.disabled)}>no data for it</span>
                    : v.noisy ? <span className="chip med" title={v.noisy}>noisy: weak links only</span>
                    : v.prevalent ? <span className="chip med" title={v.prevalent}>common here</span>
                    : <span className="chip low">fired</span>}</td></tr>))}</tbody>
            </table></div>
          </>}
        </div>
      </details>
    </div>
  );
}
