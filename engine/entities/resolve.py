"""Entity resolution: IP -> host over time, host roles/criticality, account classes.

IP evidence, strongest first (an IP is resolved only from its strongest available source,
so a spoofable hint never overrides a DHCP lease):
  1 dhcp     rows carrying both host and host_ip (DHCP leases, 'Server listening on', agent IPs)
  2 self     a host reporting its own address (Sysmon 3 SourceIp of the logging host)
  3 logon    Windows logons naming the source workstation (WorkstationName + IpAddress)
"""
from __future__ import annotations

import re

import duckdb

INTERNAL_SQL = ("({c} LIKE '10.%' OR {c} LIKE '192.168.%' OR regexp_matches({c}, '^172\\.(1[6-9]|2[0-9]|3[01])\\.')"
                " OR {c} LIKE 'fe80:%' OR {c} LIKE 'fd%:%')")
SYSTEM_ACCOUNTS = {"system", "local service", "network service", "anonymous logon", "anonymous", "-", "",
                   "localsystem", "nobody", "root_cron", "font driver host", "window manager", "dwm-1", "dwm-2",
                   "umfd-0", "umfd-1", "trustedinstaller"}


def is_internal_sql(col: str) -> str:
    return INTERNAL_SQL.format(c=col)


LOCAL_IPS = ("::1", "0.0.0.0", "::")


def is_local(ip: str | None) -> bool:
    """Loopback / unspecified: the host itself, neither its network nor the internet."""
    return bool(ip) and (ip.startswith("127.") or ip in LOCAL_IPS)


NETWORK_DEVICE = re.compile(r"^(FGT?\d|FW[-_]|PA-\d|ASA\d|SRX\d)", re.I)


def is_network_device(name: str | None) -> bool:
    """A firewall / VPN gateway by its name (FortiGate serials FGT60F..., FW-*, PA-*, ASA*, SRX*): the organisation's
    own protection, never something to isolate or switch off."""
    return bool(name) and bool(NETWORK_DEVICE.match(str(name)))


def is_external(ip: str | None) -> bool:
    return bool(ip) and not is_internal(ip) and not is_local(ip)


def is_internal(ip: str | None) -> bool:
    if not ip:
        return False
    if ip.startswith(("10.", "192.168.", "fe80:")):
        return True
    m = re.match(r"172\.(\d+)\.", ip)
    return bool(m and 16 <= int(m.group(1)) <= 31)


def is_system_account(u: str | None) -> bool:
    if not u:
        return True
    u = u.lower()
    return u in SYSTEM_ACCOUNTS or u.endswith("$") or u.startswith(("dwm-", "umfd-"))


def build_ip_map(con: duckdb.DuckDBPyConnection) -> int:
    con.execute(f"""
    CREATE OR REPLACE TABLE ip_obs AS
    SELECT host_ip AS ip, host, ts, 1 AS prio FROM events
      WHERE host_ip IS NOT NULL AND host IS NOT NULL AND ts IS NOT NULL AND NOT regexp_matches(host, '^[0-9.:]+$')
        AND NOT (host_ip LIKE '127.%' OR host_ip IN ('::1', '0.0.0.0', '::'))
    UNION ALL
    SELECT src_ip, host, ts, 2 FROM events
      WHERE event_type = 'sysmon:3' AND src_ip IS NOT NULL AND host IS NOT NULL AND {is_internal_sql('src_ip')}
    UNION ALL
    SELECT src_ip, src_host, ts, 3 FROM events
      WHERE event_type IN ('win:4624','win:4625','win:4648','win:4776') AND src_ip IS NOT NULL
        AND src_host IS NOT NULL AND {is_internal_sql('src_ip')} AND NOT regexp_matches(src_host, '^[0-9.:]+$')
    """)
    # keep only each IP's best source, collapse consecutive duplicates into segments
    con.execute("""
    CREATE OR REPLACE TABLE ip_segments AS
    WITH best AS (
      SELECT o.* FROM ip_obs o JOIN (SELECT ip, min(prio) p FROM ip_obs GROUP BY ip) b
        ON o.ip = b.ip AND o.prio = b.p),
    chg AS (
      SELECT ip, host, ts, prio,
             CASE WHEN host = lag(host) OVER (PARTITION BY ip ORDER BY ts) THEN 0 ELSE 1 END AS new_seg
      FROM best)
    SELECT ip, host, ts AS valid_from, prio,
           coalesce(lead(ts) OVER (PARTITION BY ip ORDER BY ts), 9223372036854775807) AS valid_to,
           row_number() OVER (PARTITION BY ip ORDER BY ts) AS seg_no
    FROM chg WHERE new_seg = 1
    ORDER BY ip, valid_from
    """)
    return con.execute("SELECT count(DISTINCT ip) FROM ip_segments").fetchone()[0]


def resolve_sql(ip_col: str, ts_col: str) -> str:
    """Scalar subquery: host holding ip_col at ts_col (earliest lease is back-filled)."""
    return (f"(SELECT s.host FROM ip_segments s WHERE s.ip = {ip_col} "
            f"AND ({ts_col} >= s.valid_from AND {ts_col} < s.valid_to OR s.seg_no = 1 AND {ts_col} < s.valid_from) "
            f"LIMIT 1)")


class IpResolver:
    """In-memory resolver for Python-side graph work (segments are small: one row per lease change)."""

    def __init__(self, con: duckdb.DuckDBPyConnection):
        self.segs: dict[str, list[tuple[int, int, str]]] = {}
        for ip, host, vf, vt in con.execute(
                "SELECT ip, host, valid_from, valid_to FROM ip_segments ORDER BY ip, valid_from").fetchall():
            self.segs.setdefault(ip, []).append((vf, vt, host))

    def host(self, ip: str | None, ts: int | None) -> str | None:
        if not ip:
            return None
        segs = self.segs.get(ip)
        if not segs:
            return None
        if ts is None or ts < segs[0][0]:
            return segs[0][2]
        for vf, vt, h in segs:
            if vf <= ts < vt:
                return h
        return segs[-1][2]


# ---------------------------------------------------------------- host roles
ROLE_PATTERNS = [
    ("firewall", r"^(FGT|FG|FORTIGATE|FW|PA|PAN|ASA|SRX|CHKP|PFSENSE|OPNSENSE|SOPHOS|UTM)[-_]?\d|FIREWALL|^FW[-_]"),
    ("dc", r"(^|[-_])(DC|ADDC|PDC)\d*($|[-_])|DOMAINCONTROLLER"),
    ("fileserver", r"(^|[-_])(FS|FILE|FILESRV|NAS|SHARE)\d*"),
    ("database", r"(^|[-_])(SQL|DB|ORA|PG|MYSQL)\d*"),
    ("backup", r"(^|[-_])(BK|BKP|BACKUP|VEEAM)\d*"),
    ("web", r"(^|[-_])(WEB|WWW|IIS|APACHE|NGINX)\d*"),
    ("gateway", r"(^|[-_])(SSO|ADFS|VPN|GW|RDS|RDG|JUMP|BASTION)\d*"),
    ("mail", r"(^|[-_])(EXCH|MAIL|SMTP)\d*"),
    ("server", r"(^|[-_])(SRV|SVR|APP)\d*"),
]
CRITICALITY = {"dc": 1.0, "firewall": 0.9, "fileserver": 0.85, "database": 0.85, "backup": 0.8, "gateway": 0.75, "mail": 0.7,
               "web": 0.6, "server": 0.55, "workstation": 0.3, "external": 0.1, "unknown": 0.4}


def build_hosts(con: duckdb.DuckDBPyConnection) -> dict[str, dict]:
    """Host inventory with a role guess from name + behaviour (DCs issue Kerberos tickets, file servers
    see share access from many users)."""
    rows = con.execute("""
    SELECT host, count(*) AS n, min(ts), max(ts),
           count(*) FILTER (WHERE event_type IN ('win:4768','win:4769','win:4776')) AS kerb,
           count(DISTINCT user) FILTER (WHERE event_type IN ('win:5140','win:5145')) AS share_users,
           count(*) FILTER (WHERE format IN ('auditd') OR event_type LIKE 'auth:%' OR event_type LIKE 'syslog:%') AS linux,
           count(*) FILTER (WHERE event_type LIKE 'fw:%' OR event_type IN ('net:flow', 'zeek:conn')) AS netdev,
           count(DISTINCT src_ip) FILTER (WHERE event_type LIKE 'fw:%' OR event_type IN ('net:flow', 'zeek:conn')) AS netsrc
    FROM events WHERE host IS NOT NULL GROUP BY host
    """).fetchall()
    hosts = {}
    for host, n, lo, hi, kerb, share_users, linux, netdev, netsrc in rows:
        role = "unknown"
        for r, pat in ROLE_PATTERNS:
            if re.search(pat, host, re.I):
                role = r
                break
        if kerb > max(50, n * 0.2):
            role = "dc"
        elif role == "unknown" and share_users >= 10:
            role = "fileserver"
        elif role == "unknown" and netdev > n * 0.5 and netsrc >= 20:
            role = "firewall"                    # logs other machines' traffic: a network security device
        if role == "unknown":
            role = "workstation" if not linux else "server"
        hosts[host] = {"host": host, "events": n, "first": lo, "last": hi, "role": role,
                       "criticality": CRITICALITY[role], "os": "linux" if linux > n * 0.5 else "windows"}
    con.execute("CREATE OR REPLACE TABLE hosts (host VARCHAR, role VARCHAR, criticality DOUBLE, events BIGINT, os VARCHAR)")
    if hosts:
        con.executemany("INSERT INTO hosts VALUES (?,?,?,?,?)",
                        [(h["host"], h["role"], h["criticality"], h["events"], h["os"]) for h in hosts.values()])
    return hosts
