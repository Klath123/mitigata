import { Fragment } from "react";
import { tacticColor, hhmm, fmtTime, critLevel, shortEv } from "../lib.js";

const MAX_ROWS = 6;

// Default incident view: the attack as a chain of machines, what happened on each, and what to do now.
export default function Story({ inc, report, onStep, onEvidence, goto }) {
  const hops = [...(inc.hops || [])].sort((a, b) => a.time.localeCompare(b.time));
  const ext = hops.find((h) => h.external);
  const roles = Object.fromEntries((inc.graph?.nodes || []).filter((x) => x.type === "host").map((x) => [x.label, x.role]));
  const hosts = [...new Set([...inc.path, ...inc.steps.map((s) => s.host)])].filter((h) => inc.steps.some((s) => s.host === h));
  const into = (h) => hops.find((x) => x.to === h && !x.external);
  const summary = (report?.sentences || []).find((s) => s.section === "summary");
  const br = inc.blast_radius || {}, c = br.confirmed || {};
  const chains = br.potential?.chains || [];
  const targets = [...new Map(chains.map((x) => [x.target, x])).values()].sort((a, b) => b.criticality - a.criticality);
  const last = inc.steps.at(-1);

  return (
    <>
      {summary && (
        <p className="lede">
          {summary.text}{" "}
          <button className="cite" onClick={() => onEvidence(summary.citations, "Evidence for the summary")}>{summary.citations.length} logs</button>
        </p>
      )}

      <div className="card">
        <div className="card-h"><h3>Attack path</h3><span className="sub">how the attacker moved, in order. Click a step for its log line.</span></div>
        <div className="chain">
          {ext && (
            <>
              <div className="chain-host ext">
                <div className="chain-host-h"><span className="role-ico">⌁</span><div><b>{ext.from}</b><div className="small muted">internet</div></div></div>
                <div className="small muted" style={{ padding: "4px 2px" }}>External source. Guessed or used credentials from outside.</div>
              </div>
              <Hop h={ext} onEvidence={onEvidence} />
            </>
          )}
          {hosts.map((h, i) => {
            const steps = inc.steps.filter((s) => s.host === h);
            const hop = into(h);
            return (
              <Fragment key={h}>
                {i > 0 && (hop ? <Hop h={hop} onEvidence={onEvidence} /> : <div className="chain-arrow"><span>→</span></div>)}
                <div className="chain-host">
                  <div className="chain-host-h">
                    <span className="role-ico">{roles[h] === "dc" ? "⬡" : roles[h] === "fileserver" ? "▤" : roles[h] === "workstation" ? "▭" : "◻"}</span>
                    <div><b>{h}</b><div className="small muted">{roles[h] || "host"} · {steps.length} step{steps.length > 1 ? "s" : ""}</div></div>
                  </div>
                  {steps.slice(0, MAX_ROWS).map((s) => (
                    <button key={s.order} className="chain-step" onClick={() => onStep(s.order)} title={`${fmtTime(s.time)} UTC\n${s.summary}`}>
                      <span className="num" style={{ background: tacticColor(s.stage) }}>{s.order}</span>
                      <span className="chain-step-t"><b>{s.technique_name || s.technique}</b><span>{s.stage} · {hhmm(s.time)}</span></span>
                    </button>
                  ))}
                  {steps.length > MAX_ROWS && <button className="btn sm ghost" onClick={() => goto("kill")}>+{steps.length - MAX_ROWS} more on the kill map</button>}
                </div>
              </Fragment>
            );
          })}
        </div>
        {last && <div className="chain-end">Last observed: <b>{last.technique_name}</b> on {last.host} at {fmtTime(last.time)} UTC</div>}
      </div>

      <div className="section-row"><h2>What to do now</h2><button className="btn sm" onClick={() => goto("respond")}>Full response checklist →</button></div>
      <div className="act-grid">
        <ActCard tone="crit" title="Isolate these machines" items={c.hosts} empty="No hosts confirmed." />
        <ActCard tone="high" title="Reset these accounts" items={c.users} empty="No accounts confirmed." />
        <ActCard tone="med" title="Block these addresses" items={c.external_ips} empty="No external IPs seen." />
      </div>

      {targets.length > 0 && (
        <div className="card reach-card">
          <div className="card-h">
            <h3>Could reach next: {targets.length} more host{targets.length > 1 ? "s" : ""}</h3>
            <span className="sub">through accounts the attacker controls or whose credentials were exposed</span>
            <span className="spacer" /><button className="btn sm" onClick={() => goto("look")}>See the reach graph →</button>
          </div>
          <div className="reach-list">
            {targets.slice(0, 6).map((t) => (
              <div key={t.target} className="reach-item">
                <span className={`crit-dot ${critLevel(t.criticality)}`} />
                <div><b>{t.target}</b> <span className="muted small">{t.role}</span><div className="small muted">via {t.chain.join(" → ")}</div></div>
              </div>
            ))}
          </div>
        </div>
      )}

      {inc.excluded?.length > 0 && (
        <div className="note-line">
          <b>{inc.excluded.length}</b> lookalike events were considered and left out (e.g. an admin's legitimate PsExec).{" "}
          <button className="linkish" onClick={() => goto("evidence")}>See why →</button>
        </div>
      )}
    </>
  );
}

function Hop({ h, onEvidence }) {
  return (
    <button className="chain-arrow hop" onClick={() => onEvidence([h.evidence], `Logon ${h.from} → ${h.to}`)} title={`Log: ${shortEv(h.evidence)}`}>
      <span className="hop-user">{h.user || "?"}</span>
      <span>→</span>
      <span className="hop-time">{hhmm(h.time)}</span>
    </button>
  );
}

function ActCard({ tone, title, items, empty }) {
  return (
    <div className={`act-card ${tone}`}>
      <div className="act-title">{title}</div>
      {items?.length ? <div>{items.map((x) => <span key={x} className="chip outline">{x}</span>)}</div> : <span className="muted small">{empty}</span>}
    </div>
  );
}
