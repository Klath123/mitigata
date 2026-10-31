// API client + shared formatting. Every call reads precomputed results; nothing re-scans logs.

export async function api(path) {
  const t = performance.now();
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${path} → HTTP ${r.status}`);
  const data = await r.json();
  const server = parseFloat(r.headers.get("X-Response-Time-ms"));
  return { data, ms: performance.now() - t, serverMs: Number.isFinite(server) ? server : null };
}
export const get = async (path) => (await api(path)).data;

// ATT&CK enterprise tactic order = kill-chain lanes, left to right.
export const TACTICS = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
  "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
  "Collection", "Command and Control", "Exfiltration", "Impact",
];
export const TACTIC_SLUG = Object.fromEntries(TACTICS.map((t) => [t.toLowerCase().replace(/ /g, "-"), t]));
export const TACTIC_COLOR = {
  Reconnaissance: "#7c8799", "Resource Development": "#8f8579", "Initial Access": "#3e8ef7",
  Execution: "#8b6cf6", Persistence: "#b35cf0", "Privilege Escalation": "#d955c8", "Defense Evasion": "#e8579a",
  "Credential Access": "#f0a52c", Discovery: "#1fb5a4", "Lateral Movement": "#f2762e", Collection: "#d4b62a",
  "Command and Control": "#22a9d6", Exfiltration: "#ec4f4f", Impact: "#c9302c",
};
export const tacticColor = (t) => TACTIC_COLOR[t] || "#7c8799";
export const tacticIndex = (t) => { const i = TACTICS.indexOf(t); return i < 0 ? 99 : i; };

export const riskLevel = (r) => (r >= 0.85 ? "crit" : r >= 0.7 ? "high" : r >= 0.4 ? "med" : "low");
export const critLevel = (c) => (c >= 0.8 ? "crit" : c >= 0.6 ? "high" : c >= 0.4 ? "med" : "low");

export const fmtTime = (iso) => (iso ? String(iso).slice(0, 19).replace("T", " ") : "—");
export const hhmm = (iso) => (iso ? String(iso).slice(11, 16) : "");
export const hhmmss = (iso) => (iso ? String(iso).slice(11, 19) : "");
export const shortEv = (id) => String(id).split("/").pop();
export const n = (x) => (x ?? 0).toLocaleString();

export function dur(ms) {
  if (!Number.isFinite(ms)) return "—";
  const s = Math.round(Math.abs(ms) / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  return h < 48 ? `${h}h ${m % 60}m` : `${Math.floor(h / 24)}d ${h % 24}h`;
}
export function bytes(b) {
  if (!b) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(b) / Math.log(1024)));
  return `${(b / 1024 ** i).toFixed(i ? 2 : 0)} ${u[i]}`;
}

// Cytoscape can't read CSS variables, so resolve them once per theme.
export const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
