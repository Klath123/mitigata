import { useEffect, useRef, useState } from "react";
import { bytes } from "../lib.js";

// Send log files to the backend and analyse them (engine/api/uploads.py): upload each file with progress, start the
// engine, follow its stage, then open the new run. Files are streamed as raw bodies, so large logs work.
function put(url, file, onProgress) {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open("PUT", url);
    x.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded);
    x.onload = () => (x.status < 300 ? resolve(JSON.parse(x.responseText)) : reject(new Error(errText(x.responseText, x.status))));
    x.onerror = () => reject(new Error("network error while uploading"));
    x.send(file);
  });
}
const errText = (t, code) => { try { return JSON.parse(t).detail || `HTTP ${code}`; } catch { return `HTTP ${code}`; } };
async function post(url) {
  const r = await fetch(url, { method: "POST" });
  if (!r.ok) throw new Error(errText(await r.text(), r.status));
  return r.json();
}

export default function UploadLogs({ onClose, onDone }) {
  const [files, setFiles] = useState([]);
  const [llm, setLlm] = useState(true);
  const [sent, setSent] = useState(0);
  const [job, setJob] = useState(null);
  const [st, setSt] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const input = useRef(null);
  const total = files.reduce((a, f) => a + f.size, 0);

  useEffect(() => {
    if (!job || !st || !["running", "uploaded"].includes(st.state)) return;
    const t = setTimeout(() => fetch(`/jobs/${job}`).then((r) => r.json()).then(setSt).catch(() => {}), 2000);
    return () => clearTimeout(t);
  }, [job, st]);
  useEffect(() => { if (st?.state === "done") onDone(st.run); }, [st]);   // eslint-disable-line react-hooks/exhaustive-deps

  const start = async () => {
    setErr(null); setBusy(true); setSent(0);
    try {
      const { job: j } = await post("/jobs");
      setJob(j);
      let done = 0;
      for (const f of files) {
        await put(`/jobs/${j}/files?name=${encodeURIComponent(f.name)}`, f, (n) => setSent(done + n));
        done += f.size; setSent(done);
      }
      setSt(await post(`/jobs/${j}/run?llm=${llm}`));
    } catch (e) { setErr(e.message); setBusy(false); }
  };

  const stage = st?.stage?.replace(/^\[(\d)\/6\]\s*/, (m, k) => `Step ${k} of 6: `) || "starting…";
  const pct = total ? Math.round((sent / total) * 100) : 0;
  return (
    <div className="modal-back" role="dialog" aria-modal="true" aria-label="Upload logs" onClick={(e) => e.target === e.currentTarget && !busy && onClose()}>
      <div className="modal card">
        <div className="card-h"><h3>Analyse log files</h3><span className="spacer" />{!busy && <button className="btn sm ghost" onClick={onClose} aria-label="Close">✕</button>}</div>
        {!job && (
          <>
            <p className="small muted" style={{ marginTop: 0 }}>Any format: firewall, Windows (EVTX), Linux, web, JSON, CSV, syslog; .gz / .zip are fine. The files are sent to this server, analysed by the engine, and the result opens as a new run.</p>
            <div className="drop" onClick={() => input.current.click()} onDragOver={(e) => e.preventDefault()}
                 onDrop={(e) => { e.preventDefault(); setFiles([...e.dataTransfer.files]); }}>
              <input ref={input} type="file" multiple hidden onChange={(e) => setFiles([...e.target.files])} />
              {files.length ? <><b>{files.length} file{files.length > 1 ? "s" : ""}</b> · {bytes(total)}<div className="small muted">{files.map((f) => f.name).join(", ").slice(0, 160)}</div></>
                : <><b>Choose files</b> or drop them here</>}
            </div>
            <label className="small row" style={{ gap: 6, margin: "10px 0" }}><input type="checkbox" checked={llm} onChange={(e) => setLlm(e.target.checked)} /> write AI reports and reviews (needs an LLM key on the server)</label>
            <button className="btn primary" disabled={!files.length || busy} onClick={start}>Upload and analyse</button>
          </>
        )}
        {job && (
          <div className="upload-status">
            <div className="small muted">Job <code>{job}</code></div>
            {(!st || st.state === "uploading") && <><div className="bar"><i style={{ width: `${pct}%` }} /></div><div className="small">Uploading… {bytes(sent)} of {bytes(total)} ({pct}%)</div></>}
            {st?.state === "running" && <><div className="bar run"><i /></div><div className="small"><b>Analysing.</b> {stage}</div></>}
            {st?.state === "done" && <div className="small"><b>Done.</b> Opening the results…</div>}
            {st?.state === "failed" && <div className="warn-item high"><b>The analysis failed.</b> Last lines of its log:<pre className="small">{st.log_tail.join("\n")}</pre></div>}
          </div>
        )}
        {err && <div className="warn-item high" style={{ marginTop: 10 }}>{err}</div>}
      </div>
    </div>
  );
}
