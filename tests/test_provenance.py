"""Evidence preservation: identities, loopback IPs, parse status, timestamp assumptions, run manifest."""
import json
from datetime import datetime, timezone

import duckdb
import pytest

from engine.entities.resolve import is_external, is_internal, is_local
from engine.ingest.to_parquet import ingest
from engine.results import manifest


def win(eid, ts, **data):
    return json.dumps({"Event": {"System": {"EventID": eid, "Channel": "Security", "Computer": "WS-01.corp.local",
                                            "TimeCreated": {"#attributes": {"SystemTime": ts}}}, "EventData": data}})


LINES = [
    win(4688, "2026-10-06T10:00:00Z", SubjectUserName="Administrator", SubjectDomainName="CORP",
        NewProcessName="C:\\a.exe"),
    json.dumps({"ts": "2026-10-06T10:00:01Z", "host": "WS-01", "user": "LAB\\Administrator", "action": "x"}),
    json.dumps({"ts": "2026-10-06T10:00:02Z", "host": "WS-01", "user": "administrator@company.local", "action": "x"}),
    win(4624, "2026-10-06T10:00:03Z", TargetUserName="bob", LogonType=3, IpAddress="127.0.0.1"),
    win(4624, "2026-10-06T10:00:04Z", TargetUserName="bob", LogonType=3, IpAddress="::1"),
    json.dumps({"ts": "2026-10-06 10:00:05", "host": "WS-01", "user": "bob", "action": "y"}),   # no timezone
    '{"ts": "2026-10-06T10:00:06Z", "user": "broken"',                                          # invalid JSON
]


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    root = tmp_path_factory.mktemp("prov")
    (root / "events.jsonl").write_text("\n".join(LINES) + "\n", encoding="utf-8")
    out = root / "_out"
    rep = ingest(str(root), str(out), workers=1, log=lambda *_: None)
    c = duckdb.connect()
    c.execute(f"CREATE VIEW e AS SELECT * FROM read_parquet('{(out / 'events').as_posix()}/*.parquet')")
    rows = {r[0]: r[1:] for r in c.execute(
        "SELECT line, \"user\", user_original, domain, src_ip, ts_assumed, parse_status, parse_error, ingest_ts "
        "FROM e").fetchall()}
    return root, out, rep, rows


def test_identity_keeps_domain_and_original(run):
    rows = run[3]
    assert rows[1][:3] == ("administrator", "Administrator", "CORP")
    assert rows[2][:3] == ("administrator", "LAB\\Administrator", "LAB")
    assert rows[3][:3] == ("administrator", "administrator@company.local", "COMPANY.LOCAL")
    # same short name, different domains: still told apart
    assert len({rows[i][2] for i in (1, 2, 3)}) == 3


def test_loopback_kept_but_never_internet(run):
    rows = run[3]
    assert rows[4][3] == "127.0.0.1" and rows[5][3] == "::1"
    for ip in ("127.0.0.1", "::1", "0.0.0.0"):
        assert is_local(ip) and not is_internal(ip) and not is_external(ip)
    assert is_external("203.0.113.7") and is_internal("10.0.0.5")


def test_parse_status(run):
    rows = run[3]
    assert rows[1][5] == "ok" and rows[1][6] is None
    assert rows[7][5] == "fallback" and rows[7][6].startswith("invalid JSON")
    assert all(r[7] and r[7] > 1_700_000_000_000 for r in rows.values())          # ingest_ts on every row


def test_timestamp_assumption(run, tmp_path):
    rows = run[3]
    assert rows[1][4] is False                       # explicit Z
    assert rows[6][4] is True                        # naive timestamp, no timezone declared
    # declaring the timezone in manifest.json turns the assumption into a stated fact
    (tmp_path / "events.jsonl").write_text(LINES[5] + "\n", encoding="utf-8")
    (tmp_path / "manifest.json").write_text('{"timezone": "+05:30"}', encoding="utf-8")
    ingest(str(tmp_path), str(tmp_path / "_o"), workers=1, log=lambda *_: None)
    c = duckdb.connect()
    ts, assumed = c.execute(f"SELECT ts, ts_assumed FROM read_parquet('{(tmp_path / '_o' / 'events').as_posix()}"
                            f"/*.parquet')").fetchone()
    expected = int(datetime(2026, 10, 6, 4, 30, 5, tzinfo=timezone.utc).timestamp() * 1000)   # 10:00:05 IST
    assert assumed is False and ts == expected


def test_run_manifest(run):
    root, out, rep, _ = run
    m = manifest.write(str(out), str(root), 0, 1, rep, {"processed": {"events": 7, "unparsed": 1}})
    assert m["inputs"]["events.jsonl"]["sha256"] and m["config"]["sha256"]
    assert m["records"]["failed_to_parse"] == 1
    first = m["inputs"]["events.jsonl"]["sha256"]
    with open(root / "events.jsonl", "a", encoding="utf-8") as f:
        f.write("changed\n")
    assert manifest.file_hash(str(root / "events.jsonl"))["sha256"] != first
    assert manifest.file_hash(str(root / "events.jsonl"), full=True)["hash_kind"] == "full"


def test_account_identity_for_linking():
    from engine.graph.build import account_key, norm_domain
    domains = {"administrator": {"CORP", "LAB"}, "adm_ravi": {"CORP"}}
    assert norm_domain("corp.local") == norm_domain("CORP") == "CORP"
    # same short name, different domains: different identities
    assert account_key("administrator", "CORP", domains) != account_key("administrator", "LAB", domains)
    # DNS and NetBIOS spellings of one domain: same identity
    assert account_key("adm_ravi", "corp.local", domains) == account_key("adm_ravi", "CORP", domains)
    # no domain in the log (Linux/Sysmon) but only one known domain: linked to it
    assert account_key("adm_ravi", None, domains) == "adm_ravi@CORP"
    # no domain and the name exists in several domains: ambiguous, never linked by account
    assert account_key("administrator", None, domains) is None
    # never seen with a domain (Linux-only account): bare name
    assert account_key("deploy", None, domains) == "deploy"
    # local accounts on different machines are different people
    assert account_key("administrator", "WS-01", domains) != account_key("administrator", "WS-02", domains)
    assert account_key("system", "NT AUTHORITY", domains) is None


def test_timezone_stated_in_the_record(tmp_path):
    # FortiGate writes local date/time plus tz="+0530": the record's own offset is a fact, not an assumption
    (tmp_path / "fw.log").write_text('date=2026-10-23 time=08:48:26 tz="+0530" devname="FGT" srcip=10.0.0.5 '
                                     'dstip=8.8.8.8 dstport=53\n', encoding="utf-8")
    ingest(str(tmp_path), str(tmp_path / "_o"), workers=1, log=lambda *_: None)
    ts, assumed = duckdb.connect().execute(
        f"SELECT ts, ts_assumed FROM read_parquet('{(tmp_path / '_o' / 'events').as_posix()}/*.parquet')").fetchone()
    assert assumed is False
    assert ts == int(datetime(2026, 10, 23, 3, 18, 26, tzinfo=timezone.utc).timestamp() * 1000)
