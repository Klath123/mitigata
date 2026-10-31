"""Data-quality metrics count exactly the problems planted in a small broken dataset."""
import json

import pytest

from engine import quality
from engine.ingest.to_parquet import ingest
from engine.store.db import connect


def ev(eid, ts=None, host="WS-01", **data):
    sysd = {"EventID": eid, "Channel": "Security"}
    if ts:
        sysd["TimeCreated"] = {"#attributes": {"SystemTime": ts}}
    if host:
        sysd["Computer"] = f"{host}.corp.local"
    return json.dumps({"Event": {"System": sysd, "EventData": data}})


LINES = [
    ev(4624, "2026-10-06T10:00:00Z", TargetUserName="u1", LogonType=3, IpAddress="10.0.0.5"),   # 1 ok
    ev(4688, "2026-10-06T10:01:00Z", SubjectUserName="u1", NewProcessName="C:\\a.exe"),          # 2 ok
    ev(4688, "2026-10-06T10:01:00Z", SubjectUserName="u1", NewProcessName="C:\\a.exe"),          # 3 duplicate of 2
    ev(4688, None, SubjectUserName="u1", NewProcessName="C:\\b.exe"),                            # 4 no timestamp
    ev(4688, "1970-01-01T00:00:05Z", SubjectUserName="u1", NewProcessName="C:\\c.exe"),          # 5 impossible ts
    ev(4688, "2099-01-01T00:00:00Z", SubjectUserName="u1", NewProcessName="C:\\d.exe"),          # 6 future ts
    ev(4688, "2026-10-06T10:02:00Z", host=None, SubjectUserName="u1", NewProcessName="C:\\e.exe"),  # 7 no host
    ev(4688, "2026-10-06T09:00:00Z", SubjectUserName="u1", NewProcessName="C:\\f.exe"),          # 8 late (62 min)
    json.dumps({"foo": "bar", "time": "2026-10-06T10:03:00Z", "Computer": "WS-01"}),             # 9 unknown type
    "this line is not json at all",                                                              # 10 malformed
    ev(4624, "2026-10-06T10:04:00Z", TargetUserName="u2", LogonType=3),                          # 11 logon, no source
]


@pytest.fixture(scope="module")
def q(tmp_path_factory):
    root = tmp_path_factory.mktemp("dq")
    (root / "win").mkdir()
    (root / "win" / "security.jsonl").write_text("\n".join(LINES) + "\n", encoding="utf-8")
    out = root / "_out"
    rep = ingest(str(root), str(out), workers=1, log=lambda *_: None)
    con = connect(str(out), persist=False)
    res = quality.compute(con, rep)
    res["_detectable"] = con.execute("SELECT count(*) FROM events").fetchone()[0]
    return res


def test_counts(q):
    s = q["summary"]
    assert s["total_lines_read"] == 11
    assert s["total_records"] == 11                       # nothing dropped, the malformed line is kept
    assert s["malformed_records"] == 1
    assert s["successfully_parsed"] == 10
    assert s["missing_critical_fields"]["timestamp"] == 2  # line 4 + the malformed line
    assert s["invalid_timestamps"] == 2                    # 1970 and 2099
    assert s["missing_critical_fields"]["host"] == 2       # line 7 + the malformed line
    assert s["unknown_event_types"] == 2                   # line 9 (jsonl) + malformed (generic)
    assert s["duplicate_records"] == 1
    assert s["late_arriving_events"] == 1
    assert s["missing_critical_fields"]["source_of_remote_logon"] == 1
    assert s["records_excluded_from_detection"] == 4
    assert q["_detectable"] == 7                           # detection sees only placeable records


def test_warnings_and_score(q):
    texts = " ".join(w["text"] for w in q["warnings"])
    assert "excluded from detection" in texts
    assert "matched no parser" in texts
    assert "remote logons carry no source" in texts
    assert 0 <= q["quality_score"] < 90


def test_incident_view(q):
    steps = [{"host": "WS-01"}, {"host": "GHOST-9"}]
    r = quality.for_incident(q, steps, [{"host": "WS-01", "start": "a", "end": "b", "expected_events": 9}])
    texts = " ".join(w["text"] for w in r["warnings"])
    assert "GHOST-9: no records" in texts and "unusable timestamps" in texts and "no logs from a to b" in texts
    assert r["complete"] is False
