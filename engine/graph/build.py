"""Hit nodes and evidence links between them.

A node is one hunt hit (rule match, possibly many evidence rows). Links are found through
inverted indexes (GUIDs, sessions, accounts, external IPs, hosts) so the cost grows with the
number of hits, never with the number of raw events.
"""
from __future__ import annotations

import bisect
from collections import defaultdict
from dataclasses import dataclass, field

import duckdb
import networkx as nx

from ..entities.resolve import IpResolver, is_external, is_internal, is_local, is_system_account
from .confidence import POSSIBLE, WEIGHTS, noisy_or

HOUR = 3_600_000
MIN = 60_000
SYSTEM_LOGON_IDS = {"0x3e7", "0x3e4", "0x3e5", "0x0"}
LOGON_TYPES = {"win:4624", "auth:success", "win:5140", "win:5145"}
MAX_FANOUT = 60
HOP_LOOKBACK = 24 * 3_600_000
SIGMA_STEP_MIN = 0.6                      # Sigma 'high' and above can be incident steps
REMOTE_REQUEST = {"win:4769", "win:4768", "win:4776"}   # logged on the DC, naming the requesting host
# links that only say "near in time / same account / same host"; strong ones (GUID, session, logon hop) always count
WEAK_LINKS = {"same_account", "same_account_weak", "time_proximity", "compromised_host", "same_external_ip",
              "shared_ioc"}
# techniques whose command line / registry data is a payload worth matching across hosts
IOC_TECHNIQUES = {"T1059", "T1547", "T1204", "T1105", "T1486", "T1053", "T1071", "T1041", "T1505"}
COMMON_BINARIES = {"powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "svchost.exe",
                   "explorer.exe", "vssadmin.exe", "wmic.exe", "mshta.exe", "wscript.exe", "cscript.exe",
                   "services.exe", "lsass.exe", "bash", "sh", "dash", "python", "python3", "perl", "php",
                   "psexesvc.exe", "conhost.exe", "taskeng.exe", "schtasks.exe", "net.exe", "net1.exe"}                         # ignore index keys shared by more hits than this (too generic)


def norm_domain(d: str | None) -> str | None:
    """CORP, corp.local, CORP.LOCAL -> CORP (NetBIOS and DNS forms of one domain compare equal)."""
    if not d:
        return None
    d = str(d).strip().upper()
    if not d or d in ("-", "NT AUTHORITY", "NT SERVICE", "WORKGROUP", "BUILTIN"):
        return None
    return d.split(".", 1)[0]


def account_key(user: str | None, domain: str | None, domains_of: dict[str, set[str]]) -> str | None:
    """Identity used for linking.
    domain known                          -> user@DOMAIN
    domain missing, name has one domain   -> that identity (e.g. a Linux log of a domain account)
    domain missing, name never had one    -> user
    domain missing, name has several      -> None: ambiguous, never linked by account
    """
    if not user or is_system_account(user):
        return None
    d = norm_domain(domain)
    if d:
        return f"{user}@{d}"
    known = domains_of.get(user) or set()
    if len(known) == 1:
        return f"{user}@{next(iter(known))}"
    return user if not known else None


@dataclass
class Node:
    key: str
    rule_id: str
    title: str
    kind: str
    technique: str | None
    sub_technique: str | None
    tactic: str | None
    severity: float
    rarity: float
    rows: list[dict] = field(default_factory=list)
    noisy: bool = False                   # rule fires far too often in this dataset: strong links only

    @property
    def ts(self) -> int:
        return min(r["ts"] for r in self.rows if r["ts"] is not None) if self.rows else 0

    @property
    def ts_end(self) -> int:
        return max(r["ts"] for r in self.rows if r["ts"] is not None) if self.rows else 0

    def vals(self, col: str) -> set:
        return {r[col] for r in self.rows if r.get(col) not in (None, "")}

    @property
    def hosts(self) -> set:
        return self.vals("host")

    @property
    def users(self) -> set:
        return {u for u in self.vals("user") if not is_system_account(u)}

    @property
    def evidence(self) -> list[str]:
        return sorted({f"{r['src_file']}:{r['line']}" for r in self.rows})


def load_nodes(con: duckdb.DuckDBPyConnection, resolver: IpResolver) -> dict[str, Node]:
    # low/medium Sigma hits stay in `hits` (labels, blind scoring, the evidence index) but do not become
    # incident steps: on real data they fire on routine activity and flood the review queue
    cur = con.execute(f"SELECT * FROM hits WHERE NOT (kind = 'sigma' AND severity < {SIGMA_STEP_MIN}) ORDER BY ts")
    cols = [d[0] for d in cur.description]
    nodes: dict[str, Node] = {}
    for row in cur.fetchall():
        r = dict(zip(cols, row))
        n = nodes.get(r["hit_key"])
        if n is None:
            n = nodes[r["hit_key"]] = Node(r["hit_key"], r["rule_id"], r["rule_title"], r["kind"], r["technique"],
                                           r["sub_technique"], r["tactic"], r["severity"] or 0.0, r["rarity"] or 0.0,
                                           noisy=bool(r.get("noisy")))
        n.severity = max(n.severity, r["severity"] or 0.0)
        # resolve the source host of logons/flows once
        src_h = r.get("src_host")
        if is_external(r.get("src_ip")):
            src_h = None                      # spoofable workstation name from an internet source
        elif is_local(r.get("src_ip")):
            src_h = r.get("host")             # loopback: the host itself, never a hop
        if not src_h and r.get("src_ip") and is_internal(r["src_ip"]):
            src_h = resolver.host(r["src_ip"], r["ts"])
        r["src_h"] = src_h
        dst_h = r.get("dst_host") if r.get("dst_host") and "." not in r["dst_host"] else None
        if not dst_h and r.get("dst_ip") and is_internal(r["dst_ip"]):
            dst_h = resolver.host(r["dst_ip"], r["ts"])
        r["dst_h"] = dst_h
        n.rows.append(r)
    return nodes


class Linker:
    def __init__(self, nodes: dict[str, Node], con: duckdb.DuckDBPyConnection):
        self.nodes = nodes
        self.con = con
        self.reasons: dict[tuple[str, str], dict[str, float]] = defaultdict(dict)
        self.attribution: dict[str, str] = {}     # node -> reason it belongs to a non-flagged session
        self.domains_of: dict[str, set[str]] = defaultdict(set)   # account name -> domains it appears with
        for u, d in con.execute("""SELECT DISTINCT "user", domain FROM events
                                   WHERE "user" IS NOT NULL AND domain IS NOT NULL""").fetchall():
            nd = norm_domain(d)
            if nd:
                self.domains_of[u].add(nd)

    def add(self, a: str, b: str, kind: str, w: float | None = None) -> None:
        if a == b:
            return
        if kind in WEAK_LINKS and (self.nodes[a].noisy or self.nodes[b].noisy):
            return                        # a noisy rule must not glue unrelated activity together
        k = (a, b) if a < b else (b, a)
        w = WEIGHTS[kind] if w is None else w
        self.reasons[k][kind] = max(self.reasons[k].get(kind, 0.0), w)

    # ------------------------------------------------------------ index helpers
    def _link_by_index(self, index: dict, kind: str, window: int | None = None) -> None:
        for key, members in index.items():
            if len(members) < 2 or len(members) > MAX_FANOUT:
                continue
            members = sorted(set(members), key=lambda k: self.nodes[k].ts)
            for i, a in enumerate(members):
                for b in members[i + 1:]:
                    if window is not None and self.nodes[b].ts - self.nodes[a].ts_end > window:
                        break
                    self.add(a, b, kind)

    def link_all(self) -> dict[tuple[str, str], float]:
        N = self.nodes
        guid_idx, session_idx, ext_idx = defaultdict(list), defaultdict(list), defaultdict(list)
        user_idx, host_idx, created_idx = defaultdict(list), defaultdict(list), defaultdict(list)
        for k, n in N.items():
            for r in n.rows:
                for g in (r.get("process_guid"), r.get("target_guid")):
                    if g:
                        guid_idx[("p", g)].append(k)
                if r.get("parent_guid"):
                    guid_idx[("c", r["parent_guid"])].append(k)
                lid = r.get("logon_id")
                if lid and lid not in SYSTEM_LOGON_IDS and r.get("host"):
                    session_idx[(r["host"], lid)].append(k)
                for ip in (r.get("src_ip"), r.get("dst_ip")):
                    if is_external(ip):
                        ext_idx[ip].append(k)
                if r.get("event_type") in ("win:4720", "win:4728", "win:4732", "win:4756", "account:create") \
                        and r.get("target_user"):
                    ck = account_key(r["target_user"], r.get("domain"), self.domains_of)
                    if ck:
                        created_idx[ck].append(k)
            for ak in {account_key(r.get("user"), r.get("domain"), self.domains_of) for r in n.rows} - {None}:
                user_idx[ak].append(k)
            for h in n.hosts:
                host_idx[h].append(k)

        self._shared_iocs()

        # process lineage: same GUID, or parent GUID of one = process GUID of another
        for (kind, g), members in list(guid_idx.items()):
            if kind == "p":
                self._link_by_index({g: members}, "same_process")
                for child in guid_idx.get(("c", g), []):
                    for parent in members:
                        self.add(parent, child, "spawned")
        self._link_by_index(session_idx, "session")
        self.session_idx, self.guid_idx = session_idx, guid_idx
        self._link_by_index(ext_idx, "same_external_ip", window=24 * HOUR)

        # created / modified account later acting
        for acct, creators in created_idx.items():
            for actor in user_idx.get(acct, []):
                for c in creators:
                    if N[actor].ts >= N[c].ts - MIN:
                        self.add(c, actor, "created_account_used")
            self._link_by_index({acct: creators}, "created_account_used", window=6 * HOUR)

        # same account within 60 min
        for u, members in user_idx.items():
            if len(members) > MAX_FANOUT * 5:
                continue
            members = sorted(set(members), key=lambda k: N[k].ts)
            for i, a in enumerate(members):
                for b in members[i + 1:]:
                    if N[b].ts - N[a].ts_end > HOUR:
                        break
                    strong = min(N[a].severity, N[b].severity) >= 0.4 and bool(N[a].hosts & N[b].hosts)
                    self.add(a, b, "same_account" if strong else "same_account_weak")

        # host-level: time proximity, logon hops, service-after-logon, compromised host
        host_sorted = {h: sorted(set(m), key=lambda k: N[k].ts) for h, m in host_idx.items()}
        host_ts = {h: [N[k].ts for k in m] for h, m in host_sorted.items()}
        for h, members in host_sorted.items():
            ts = host_ts[h]
            for i, a in enumerate(members):
                j = bisect.bisect_right(ts, N[a].ts_end + 5 * MIN)
                for b in members[i + 1:j]:
                    self.add(a, b, "time_proximity")
        self._system_activity(host_sorted)          # first: explains service/SYSTEM hits by their own session
        self._logon_hops(host_sorted, host_ts)

        return {k: noisy_or(v.values()) for k, v in self.reasons.items()}

    def _shared_iocs(self) -> None:
        """Campaign links: flagged hits that share a specific indicator, whatever host/user/time.
        Star-linked to one hub per indicator, so fan-out costs O(n) links, not O(n^2)."""
        N = self.nodes
        idx: dict[tuple, list[str]] = defaultdict(list)
        for k, n in N.items():
            if n.severity < 0.5 or not n.technique:
                continue
            for r in n.rows:
                for ip in (r.get("src_ip"), r.get("dst_ip")):
                    if is_external(ip):
                        idx[("ip", ip)].append(k)
                dh = r.get("dst_host") or ""
                if "." in dh and not dh[0].isdigit():
                    idx[("domain", dh.lower())].append(k)
                if n.technique in IOC_TECHNIQUES:
                    cmd = (r.get("cmdline") or "").strip().lower()
                    if len(cmd) >= 20:
                        idx[("payload", cmd)].append(k)
                proc = (r.get("process") or "").lower()
                base = proc.replace("/", "\\").rsplit("\\", 1)[-1]
                if n.severity >= 0.9 and base and "\windows\\" not in proc and base not in COMMON_BINARIES:
                    idx[("binary", base)].append(k)
                if n.technique == "T1486" and r.get("target"):
                    ext = r["target"].rsplit(".", 1)[-1].lower() if "." in r["target"] else ""
                    if 2 <= len(ext) <= 12:
                        idx[("extension", ext)].append(k)
        self.iocs = {}
        for key, members in idx.items():
            members = sorted(set(members), key=lambda m: N[m].ts)
            if len(members) < 2:
                continue
            self.iocs[key] = members
            hub = members[0]
            for m in members[1:]:
                self.add(hub, m, "shared_ioc")

    def _sent_bytes(self, k: str, host: str) -> bool:
        """A flow to an internet IP belongs to whoever ran the process that talked to that IP:
        find process events on the host naming that IP (Sysmon 3 / command line), then the hits that share
        their logon session or process lineage."""
        n = self.nodes[k]
        ext = sorted({r["dst_ip"] for r in n.rows if is_external(r.get("dst_ip"))})
        if not ext:
            return False
        lo, hi = n.ts - 15 * MIN, n.ts_end + 5 * MIN
        linked = False
        for ip in ext[:5]:
            rows = self.con.execute("""
                SELECT logon_id, process_guid, parent_guid FROM events
                WHERE host = ? AND ts BETWEEN ? AND ?
                  AND (dst_ip = ? OR (event_type IN ('sysmon:1','win:4688','audit:execve') AND cmdline LIKE ?))""",
                                    [host, lo, hi, ip, f"%{ip}%"]).fetchall()
            guids = {g for _, pg, ppg in rows for g in (pg, ppg) if g}
            lids = {lid for lid, _, _ in rows if lid and lid not in SYSTEM_LOGON_IDS}
            owners = set()
            for lid in lids:
                owners |= set(self.session_idx.get((host, lid), []))
            # walk one level up the lineage: the process that started the uploader
            if guids:
                more = self.con.execute(f"""
                    SELECT DISTINCT logon_id, parent_guid FROM events WHERE host = ? AND event_type = 'sysmon:1'
                      AND process_guid IN ({",".join("?" * len(guids))})""", [host, *guids]).fetchall()
                for lid, pg in more:
                    if lid and lid not in SYSTEM_LOGON_IDS:
                        owners |= set(self.session_idx.get((host, lid), []))
                    if pg:
                        guids.add(pg)
                for g in guids:
                    owners |= set(self.guid_idx.get(("p", g), [])) | set(self.guid_idx.get(("c", g), []))
            for o in owners - {k}:
                self.add(k, o, "sent_bytes")
                linked = True
        return linked

    def _hop_rows(self, n: Node) -> list[dict]:
        return [r for r in n.rows if r.get("event_type") in LOGON_TYPES and r.get("src_h") and r["src_h"] != r.get("host")]

    def _logon_hops(self, host_sorted, host_ts) -> None:
        """A logon on Y from X links to meaningful hits on X before it (the attacker came from X). Attackers often
        wait hours before moving on, so the look-back is a day, with a lower weight past 2 h.
        Servers and DCs start logons to other machines all day, so from them the look-back stays 2 h.
        A Kerberos/NTLM request logged on a DC links the same way to hits on the requesting host (+-1 h)."""
        N = self.nodes
        try:
            roles = dict(self.con.execute("SELECT host, role FROM hosts").fetchall())
        except duckdb.Error:
            roles = {}
        for k, n in N.items():
            for r in self._hop_rows(n):
                x, t = r["src_h"], r["ts"]
                if x not in host_sorted:
                    continue
                ts = host_ts[x]
                back = HOP_LOOKBACK if roles.get(x, "workstation") in ("workstation", "unknown") else 2 * HOUR
                lo = bisect.bisect_left(ts, t - back)
                hi = bisect.bisect_right(ts, t + 5 * MIN)
                for other in host_sorted[x][lo:hi]:
                    if other in self.attribution:       # already explained by another (unflagged) session
                        continue
                    o = N[other]
                    if o.severity >= 0.45 or o.technique in ("T1003", "T1552"):
                        w = WEIGHTS["logon_hop"] if t - o.ts_end <= 2 * HOUR else WEIGHTS["logon_hop_late"]
                        if o.technique in ("T1003", "T1552"):        # credentials stolen here, used to hop
                            self.add(k, other, "reused_credential")
                        self.add(k, other, "logon_hop", w)
            for r in n.rows:
                if r.get("event_type") not in REMOTE_REQUEST or not r.get("src_h") or r["src_h"] == r.get("host"):
                    continue
                x, t = r["src_h"], r["ts"]
                if x not in host_sorted:
                    continue
                ts = host_ts[x]
                for other in host_sorted[x][bisect.bisect_left(ts, t - HOUR):bisect.bisect_right(ts, t + HOUR)]:
                    if N[other].severity >= 0.3 and N[other].technique:
                        self.add(k, other, "remote_request")

    def _system_activity(self, host_sorted) -> None:
        """Hits with no real user on host Y (services, flows, SYSTEM processes): attribute to the remote admin
        logon just before them; if that logon was not flagged, remember why (used for the excluded list)."""
        N = self.nodes
        entries: dict[str, list[tuple[int, str]]] = defaultdict(list)   # host -> (ts, node) of hop-in logons
        for k, n in N.items():
            for r in self._hop_rows(n):
                entries[r["host"]].append((r["ts"], k))
        for h in entries:
            entries[h].sort()
        sysnodes = [k for k, n in N.items() if not n.users and n.technique and k not in self.attribution]
        if not sysnodes:
            return
        by_host: dict[str, list[str]] = defaultdict(list)
        for k in sysnodes:
            for h in N[k].hosts:
                by_host[h].append(k)
        for h, ks in by_host.items():
            lo = min(N[k].ts for k in ks) - 3 * MIN
            hi = max(N[k].ts for k in ks)
            logons = self.con.execute("""
                SELECT l.ts, l."user", l.logon_id, l.src_file, l.line FROM events l
                WHERE l.host = ? AND l.event_type = 'win:4624' AND l.logon_type IN (3, 10)
                  AND l.ts BETWEEN ? AND ?
                  AND EXISTS (SELECT 1 FROM events p WHERE p.host = l.host AND p.event_type = 'win:4672'
                              AND p.logon_id = l.logon_id AND p.ts BETWEEN l.ts - 5000 AND l.ts + 5000)
                ORDER BY l.ts""", [h, lo, hi]).fetchall()
            node_by_ev = {}
            for t_, k in entries.get(h, []):
                for e in N[k].evidence:
                    node_by_ev[e] = k
            for k in ks:
                t = N[k].ts
                if self._sent_bytes(k, h):
                    continue
                recent = [(ts, u, f"{f}:{ln}") for ts, u, _, f, ln in logons
                          if t - 2 * MIN <= ts <= t and not is_system_account(u)]
                if recent:
                    ts_, u, ev = recent[-1]
                    owner = node_by_ev.get(ev)
                    if owner:
                        self.add(k, owner, "service_after_logon")
                    else:
                        self.attribution[k] = f"follows a remote admin logon by {u} that is not part of any incident"
                    continue
                # no session to blame: tie to the most recent hop into this host (compromised host)
                cands = [(ts_, kk) for ts_, kk in entries.get(h, []) if 0 <= t - ts_ <= 6 * HOUR]
                if cands:
                    self.add(k, cands[-1][1], "compromised_host")


def to_networkx(nodes: dict[str, Node], edges: dict[tuple[str, str], float],
                reasons: dict[tuple[str, str], dict[str, float]] | None = None,
                threshold: float = POSSIBLE) -> nx.Graph:
    """The correlation graph: one node per hit, weighted evidence edges (noisy-OR confidence)."""
    g = nx.Graph()
    for k, n in nodes.items():
        g.add_node(k, rule=n.rule_id, technique=n.technique or "", tactic=n.tactic or "", severity=n.severity,
                   rarity=n.rarity, ts=n.ts, hosts=",".join(sorted(n.hosts)), users=",".join(sorted(n.users)))
    for (a, b), c in edges.items():
        if c >= threshold:
            why = sorted((reasons or {}).get((a, b), {}).keys())
            g.add_edge(a, b, confidence=round(c, 3), reasons=",".join(why))
    return g


def components(g: nx.Graph) -> list[set[str]]:
    return [set(c) for c in nx.connected_components(g)]
