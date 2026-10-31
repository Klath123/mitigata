"""Every sniffable format parses into normalized rows with the right key fields."""
import json
import os

import duckdb
import pytest

from engine.ingest.sniff import sniff
from engine.ingest.to_parquet import ingest

SAMPLES = {
    "fw/fortigate.log": (
        'date=2026-10-06 time=10:01:02 devname="FGT-01" type="traffic" srcip=10.0.10.5 srcport=51000 '
        'dstip=8.8.8.8 dstport=443 action="accept" sentbyte=1200 rcvdbyte=5400 proto=6\n'
        'date=2026-10-06 time=10:01:03 devname="FGT-01" type="traffic" srcip=10.0.10.6 srcport=51001 '
        'dstip=1.1.1.1 dstport=53 action="deny" sentbyte=80 rcvdbyte=0 proto=17\n'),
    "ids/cef.log": (
        'Oct  6 10:02:00 sensor1 CEF:0|Acme|IDS|1.0|1001|Port scan|7|src=203.0.113.9 dst=10.0.1.22 spt=4444 '
        'dpt=445 suser=bob act=blocked msg=Scan detected rt=1791280920000\n'),
    "qradar/leef.log": (
        "LEEF:1.0|IBM|QRadar|1.0|4625|src=203.0.113.7\tdst=10.0.1.10\tusrName=alice\tdevTime=2026-10-06 10:03:00\n"),
    "iis/u_ex261006.log": (
        "#Software: Microsoft Internet Information Services 10.0\n#Version: 1.0\n"
        "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status\n"
        "2026-10-06 10:04:00 10.0.2.50 GET /default.aspx - 443 - 198.51.100.4 Mozilla/5.0+(Windows) 200\n"),
    "zeek/conn.log": (
        "#separator \\x09\n#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\t"
        "orig_bytes\tresp_bytes\n"
        "1791280920.123\tCx1\t10.0.1.22\t50000\t185.1.2.3\t443\ttcp\t2000000000\t5000\n"),
    "syslog/rfc5424.log": (
        "<34>1 2026-10-06T10:05:00.000Z web02 sshd 4242 - - Failed password for root from 203.0.113.5 port 2222 ssh2\n"
        "<34>1 2026-10-06T10:05:09.000Z web02 sshd 4242 - - Accepted password for root from 203.0.113.5 port 2223 ssh2\n"),
    "win/events.xml": (
        '<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        '<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID>'
        '<TimeCreated SystemTime="2026-10-06T10:06:00.1234567Z"/><Channel>Security</Channel>'
        '<Computer>FS-09.corp.local</Computer></System><EventData><Data Name="TargetUserName">carol</Data>'
        '<Data Name="TargetDomainName">CORP</Data><Data Name="LogonType">3</Data>'
        '<Data Name="IpAddress">10.0.12.7</Data><Data Name="WorkstationName">HR-11</Data></EventData></Event>\n'
        "</Events>\n"),
    "export/array.json": (
        '[\n  {\n    "TimeGenerated": "2026-10-06T10:07:00Z",\n    "Computer": "SQL-09",\n'
        '    "EventID": 4625,\n    "Channel": "Security",\n    "TargetUserName": "dave",\n'
        '    "IpAddress": "198.51.100.77"\n  },\n  {\n    "TimeGenerated": "2026-10-06T10:07:05Z",\n'
        '    "Computer": "SQL-09",\n    "EventID": 4624,\n    "Channel": "Security",\n'
        '    "TargetUserName": "dave",\n    "LogonType": 3,\n    "IpAddress": "198.51.100.77"\n  }\n]\n'),
    "wazuh/archives.json": json.dumps({
        "timestamp": "2026-10-06T10:08:00.000+0000", "agent": {"name": "LAPTOP-9"},
        "data": {"win": {"system": {"eventID": "4688", "computer": "LAPTOP-9.corp.local", "channel": "Security"},
                         "eventdata": {"subjectUserName": "eve", "newProcessName": "C:\\Windows\\System32\\whoami.exe",
                                       "commandLine": "whoami /all"}}}}) + "\n",
    "dhcp/DhcpSrvLog-Tue.log": (
        "\t\tMicrosoft DHCP Service Activity Log\n\nEvent ID  Meaning\n00\tThe log was started.\n"
        "ID,Date,Time,Description,IP Address,Host Name,MAC Address\n"
        "10,10/06/26,10:09:00,Assign,10.0.12.99,LAPTOP-7.corp.local,00155D010203\n"),
    "misc/unknown.txt": "2026-10-06 10:10:00 something odd happened user=frank src=10.9.9.9 status=weird\n",
}


@pytest.fixture(scope="module")
def con(tmp_path_factory):
    root = tmp_path_factory.mktemp("formats")
    for rel, text in SAMPLES.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    out = root / "_out"
    rep = ingest(str(root), str(out), workers=2, log=lambda *_: None)
    c = duckdb.connect()
    c.sql(f"create view e as select * from read_parquet('{(out / 'events').as_posix()}/*.parquet')")
    return c, rep


def one(c, where, cols):
    r = c.execute(f"select {cols} from e where {where}").fetchall()
    assert r, where
    return r[0]


def test_sniff_formats(con):
    _, rep = con
    fmts = {k: v["format"] for k, v in rep["files"].items()}
    assert fmts["fw/fortigate.log"] == "kv"
    assert fmts["ids/cef.log"] == "cef"
    assert fmts["qradar/leef.log"] == "leef"
    assert fmts["iis/u_ex261006.log"] == "w3c"
    assert fmts["zeek/conn.log"] == "zeek"
    assert fmts["syslog/rfc5424.log"] == "syslog"
    assert fmts["win/events.xml"] == "xml_events"
    assert fmts["export/array.json"] == "json_stream"
    assert fmts["wazuh/archives.json"] == "jsonl"
    assert fmts["dhcp/DhcpSrvLog-Tue.log"] == "csv"
    assert rep["unparsed"] == 0


def test_fields(con):
    c, _ = con
    assert one(c, "src_file='fw/fortigate.log' and dst_ip='8.8.8.8'", "src_ip, dst_port, bytes_out, action, ts") [:4] == \
        ("10.0.10.5", 443, 1200, "accept")
    assert one(c, "src_file='ids/cef.log'", "src_ip, dst_ip, dst_port, user, rule") == \
        ("203.0.113.9", "10.0.1.22", 445, "bob", "Port scan")
    assert one(c, "src_file='qradar/leef.log'", "src_ip, user") == ("203.0.113.7", "alice")
    assert one(c, "src_file='iis/u_ex261006.log'", "src_ip, target, status, event_type") == \
        ("198.51.100.4", "/default.aspx", "200", "web:req")
    assert one(c, "src_file='zeek/conn.log'", "src_ip, dst_ip, bytes_out, event_type") == \
        ("10.0.1.22", "185.1.2.3", 2000000000, "zeek:conn")
    assert one(c, "src_file='syslog/rfc5424.log' and event_type='auth:success'", "host, user, src_ip") == \
        ("WEB02", "root", "203.0.113.5")
    assert one(c, "src_file='win/events.xml'", "event_type, host, user, logon_type, src_ip, src_host") == \
        ("win:4624", "FS-09", "carol", 3, "10.0.12.7", "HR-11")
    assert one(c, "src_file='export/array.json' and event_type='win:4624'", "host, user, logon_type") == \
        ("SQL-09", "dave", 3)
    assert one(c, "src_file='wazuh/archives.json'", "event_type, host, user, cmdline") == \
        ("win:4688", "LAPTOP-9", "eve", "whoami /all")
    assert one(c, "src_file='dhcp/DhcpSrvLog-Tue.log'", "host, host_ip") == ("LAPTOP-7", "10.0.12.99")
    assert one(c, "src_file='misc/unknown.txt'", "user, src_ip") == ("frank", "10.9.9.9")
    # every row got a timestamp
    assert c.execute("select count(*) from e where ts is null").fetchone()[0] == 0
    # timestamps parsed to the right instant
    ts = one(c, "src_file='zeek/conn.log'", "ts")[0]
    assert ts == 1791280920123


def test_line_numbers(con):
    c, _ = con
    # the 4624 in the pretty-printed array starts on line 10
    assert one(c, "src_file='export/array.json' and event_type='win:4624'", "line")[0] == 10
    assert one(c, "src_file='dhcp/DhcpSrvLog-Tue.log'", "line")[0] == 6


def test_sniff_single(tmp_path):
    p = tmp_path / "a.log"
    p.write_text('1.2.3.4 - - [06/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "curl"\n')
    assert sniff(str(p))[0] == "apache"
