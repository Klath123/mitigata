import json

import duckdb
import pyarrow as pa

from engine.hunt.rules import load_macros, load_rules, run_rules
from engine.ingest.mapper import Mapper, TimeParser
from engine.ingest.parsers import parse_kvlines
from engine.schema import EVENT_SCHEMA, FIELD_NAMES

H = 'devname="FGT60" devid="FGT60" vd="root" '
LINES = {
    "admin_ok": 'date=2026-10-28 time=03:17:00 eventtime=1793157420568040000 tz="+0530" ' + H +
                'type="event" subtype="system" logdesc="Admin login successful" user="Deepika.Khan" '
                'srcip=171.104.84.193 dstip=10.10.99.1 action="login" srccountry="Russian Federation" '
                'srcintfrole="wan" status="success"',
    "web": 'date=2026-10-23 time=08:48:26 eventtime=1792745306000000000 tz="+0530" ' + H +
           'type="utm" subtype="webfilter" srcip=10.10.10.218 dstip=106.178.51.139 dstport=443 action="blocked" '
           'hostname="mailchimp.com" url="/" catdesc="Phishing Attempts"',
    "ips": 'date=2026-10-23 time=08:48:26 eventtime=1792745306000000000 tz="+0530" ' + H +
           'type="utm" subtype="ips" srcip=10.10.20.38 dstip=2.94.174.249 dstport=443 action="dropped" '
           'attack="Backdoor.Cobalt.Strike.Beacon" severity="critical"',
    "flow_no_epoch": 'date=2026-10-23 time=08:48:26 tz="+0530" ' + H +
                     'type="traffic" subtype="forward" srcip=10.10.40.225 dstip=71.38.6.121 dstport=443 sentbyte=100',
    "config": 'date=2026-10-23 time=16:31:43 eventtime=1792773103224622000 tz="+0530" ' + H +
              'type="event" subtype="system" logdesc="Attribute configured" user="Tejas.Roy" srcip=78.120.139.0 '
              'dstip=10.10.99.1 action="Edit" srccountry="India" srcintfrole="wan" '
              'msg="Attribute \'status\' of setting \'log disk setting\' changed from \'enable\' to \'disable\'"',
}


def _rows(lines):
    m, tp, out = Mapper(), TimeParser(), []
    for _, _, rec, _ in parse_kvlines([(i, 0, l) for i, l in enumerate(lines, 1)], {}):
        row, unmapped = m.map(dict(rec), tp, fmt="kv")
        row["extra"] = json.dumps({k: rec[k] for k in unmapped if k in rec})   # as ingest does (to_parquet)
        out.append(row)
    return out


def test_fortigate_types_times_and_hostname_trap():
    r = dict(zip(LINES, _rows(LINES.values())))
    assert r["admin_ok"]["event_type"] == "auth:success" and r["admin_ok"]["user"] == "deepika.khan"
    assert r["admin_ok"]["ts"] == 1793157420568 and not r["admin_ok"]["ts_assumed"]       # exact eventtime
    assert r["web"]["event_type"] == "fw:web" and r["web"]["host"] == "FGT60"                # site != reporter
    assert r["web"]["dst_host"] == "mailchimp.com" and r["web"]["rule"] == "Phishing Attempts"
    assert r["ips"]["event_type"] == "fw:ips" and r["ips"]["rule"] == "Backdoor.Cobalt.Strike.Beacon"
    assert r["flow_no_epoch"]["event_type"] == "net:flow"
    assert r["flow_no_epoch"]["ts"] == 1792725506000 and not r["flow_no_epoch"]["ts_assumed"]  # date+time+tz
    assert r["config"]["event_type"] == "fw:config"


def test_firewall_rules_fire():
    rows = _rows([LINES["config"], LINES["admin_ok"],
                  LINES["admin_ok"].replace("171.104.84.193", "8.42.69.77").replace("Russian Federation", "Türkiye")
                  .replace("1793157420568040000", "1793158000000000000")])
    for i, r in enumerate(rows, 1):
        r.update(src_file="fw.log", line=i)
    con = duckdb.connect()
    con.register("t", pa.Table.from_pylist([{f: r.get(f) for f in FIELD_NAMES} for r in rows], schema=EVENT_SCHEMA))
    con.execute("CREATE TABLE events AS SELECT * FROM t")
    con.execute("CREATE TABLE ip_segments (ip VARCHAR, host VARCHAR, valid_from BIGINT, valid_to BIGINT, seg_no INT)")
    con.execute("CREATE TABLE hosts (host VARCHAR, role VARCHAR)")
    for k, v in (("ds_start", 0), ("ds_end", 1), ("warmup_end", 2)):           # short dataset: no warm-up
        con.execute(f"SET VARIABLE {k} = {v}")
    load_macros(con)
    rules = [r for r in load_rules() if r["id"].startswith("fw_") or r["id"] == "config_change"]
    st = run_rules(con, rules, log=lambda *_: None)
    assert st["config_change"]["hits"] == 1
    assert con.execute("SELECT technique, sub_technique, tactic, severity FROM hits WHERE rule_id = 'config_change'"
                       ).fetchone() == ("T1685", None, "Defense Evasion", 0.75)    # logging disabled (Disable or Modify Tools)
    assert st["fw_admin_from_internet"]["hits"] == 3                            # one access per account + address
    assert st["fw_account_geo_jump"]["hits"] == 2                               # Russia then Türkiye in 10 min


def test_config_changes_get_the_label_of_what_they_did():
    """Labels come from rules/mappings/attack_labels.yaml (current ATT&CK): what the change DID, not who reported it."""
    msgs = {"log_off": "Attribute 'status' of setting 'log disk setting' changed from 'enable' to 'disable'",
            "log_on": "Attribute 'status' of setting 'log disk setting' changed from 'disable' to 'enable'",
            "purge": "Objects of 'firewall policy' were purged",
            "add": "Add system.admin svc_backup30", "delete": "Delete system.admin svc_backup30"}
    lines = [LINES["config"].replace(LINES["config"].split("msg=")[1], '"' + m.replace('"', "") + '"')
             for m in msgs.values()]
    rows = _rows(lines)
    for i, r in enumerate(rows, 1):
        r.update(src_file="fw.log", line=i)
    con = duckdb.connect()
    con.register("t", pa.Table.from_pylist([{f: r.get(f) for f in FIELD_NAMES} for r in rows], schema=EVENT_SCHEMA))
    con.execute("CREATE TABLE events AS SELECT * FROM t")
    con.execute("CREATE TABLE ip_segments (ip VARCHAR, host VARCHAR, valid_from BIGINT, valid_to BIGINT, seg_no INT)")
    con.execute("CREATE TABLE hosts (host VARCHAR, role VARCHAR)")
    for k, v in (("ds_start", 0), ("ds_end", 1), ("warmup_end", 2)):
        con.execute(f"SET VARIABLE {k} = {v}")
    load_macros(con)
    run_rules(con, [r for r in load_rules() if r["id"] == "config_change"], log=lambda *_: None)
    got = {line: (t, sub, tac) for line, t, sub, tac in con.execute(
        "SELECT line, technique, sub_technique, tactic FROM hits ORDER BY line").fetchall()}
    assert got == {1: ("T1685", None, "Defense Evasion"),            # logging off: disable or modify tools
                   2: ("T1070", None, "Defense Evasion"),            # logging back on: covering tracks
                   3: ("T1686", "T1686.002", "Defense Evasion"),     # firewall policies purged: network device firewall
                   4: ("T1136", "T1136.001", "Persistence"),         # admin account created
                   5: ("T1070", None, "Defense Evasion")}            # admin account deleted after use


def test_service_image_matches_the_process_start():
    from engine.graph.tracer import service_image
    assert service_image(r"%SystemRoot%\PSEXESVC.exe") == r"c:\windows\psexesvc.exe"
    assert service_image(r'"C:\Program Files\x\a.exe" -k netsvcs') == r"c:\program files\x\a.exe"
    assert service_image(r"C:\Windows\wsync.exe /install") == r"c:\windows\wsync.exe"
