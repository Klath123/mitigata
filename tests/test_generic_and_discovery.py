"""Unknown formats: content-based discovery, generic fallback, message patterns and event semantics."""
import gzip
import io
import zipfile

import duckdb
import pytest

from engine.ingest.discover import classify
from engine.ingest.to_parquet import ingest

SSH = ("Oct  6 10:00:01 server sshd[1200]: Failed password for root from 10.0.0.5\n"
       "Oct  6 10:00:03 server sshd[1200]: Failed password for root from 10.0.0.5\n"
       "Oct  6 10:00:05 server sshd[1200]: Failed password for root from 10.0.0.5\n"
       "Oct  6 10:00:08 server sshd[1200]: Accepted password for root from 10.0.0.5\n")
KV = ("2026-10-06 10:00:01 user=frank src=10.9.9.9 action=login status=failed\n"
      "2026-10-06 10:00:02 user=frank src=10.9.9.9 status=failed\n"
      "2026-10-06 10:00:03 user=frank src=10.9.9.9 action=login status=success\n"
      "2026-10-06 10:00:04 something happened user=frank status=weird\n")
PNG = bytes([0x89]) + b"PNG\r\n" + bytes([0x1A, 0x0A]) + bytes(200)


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    root = tmp_path_factory.mktemp("unk")
    (root / "ssh.txt").write_text(SSH, encoding="utf-8")
    (root / "app.weird").write_text(KV, encoding="utf-8")
    with gzip.open(root / "renamed_gzip.txt", "wb") as f:              # gzip with a .txt name
        f.write(SSH.encode())
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("inner/ssh.log", SSH)
    (root / "bundle.log").write_bytes(buf.getvalue())                  # zip with a .log name
    (root / "picture.log").write_bytes(PNG)                            # binary with a log name
    (root / "logs_named_like.png").write_text(SSH, encoding="utf-8")   # real log with an image name
    (root / "utf16_nobom.txt").write_bytes(SSH.encode("utf-16-le"))    # UTF-16LE without BOM
    out = root / "_out"
    rep = ingest(str(root), str(out), workers=2, log=lambda *_: None)
    c = duckdb.connect()
    c.execute(f"CREATE VIEW e AS SELECT * FROM read_parquet('{(out / 'events').as_posix()}/*.parquet')")
    return rep, c


def test_classify_by_content(tmp_path):
    p = tmp_path / "x.txt"
    p.write_bytes(b"ElfFile" + bytes([0]) + bytes(100))
    assert classify(str(p))[0] == "evtx"                               # EVTX renamed .txt


def test_discovery(run):
    rep, _ = run
    files = set(rep["files"])
    assert "renamed_gzip.txt.ungz" in files
    assert "bundle.log!/inner/ssh.log" in files
    assert "logs_named_like.png" in files
    assert "utf16_nobom.txt" in files
    skipped = {s["file"]: s["reason"] for s in rep["skipped"]}
    assert "picture.log" in skipped and "PNG" in skipped["picture.log"]
    assert rep["unparsed"] == 0


def test_ssh_without_port(run):
    _, c = run
    rows = c.execute("SELECT event_type, \"user\", src_ip, host, type_source FROM e WHERE src_file = 'ssh.txt' "
                     "ORDER BY line").fetchall()
    assert [r[0] for r in rows] == ["auth:fail"] * 3 + ["auth:success"]
    assert all(r[1] == "root" and r[2] == "10.0.0.5" and r[3] == "SERVER" and r[4] == "pattern" for r in rows)
    # every copy (gzip, zip, renamed, utf-16) parses the same way
    n = c.execute("SELECT count(*) FROM e WHERE event_type = 'auth:fail' AND \"user\" = 'root'").fetchone()[0]
    assert n == 3 * 5


def test_semantics_need_context(run):
    _, c = run
    rows = c.execute("SELECT line, event_type, type_source, \"user\", src_ip FROM e WHERE src_file = 'app.weird' "
                     "ORDER BY line").fetchall()
    assert rows[0][1:3] == ("auth:fail", "semantic:auth_failure")      # action=login + status=failed
    assert rows[1][1:3] == ("generic", "unknown")                      # status=failed alone: no context
    assert rows[2][1:3] == ("auth:success", "semantic:auth_success")
    assert rows[3][1:3] == ("generic", "unknown")                      # status=weird
    assert rows[0][3:] == ("frank", "10.9.9.9")


def test_behavioural_candidate(tmp_path):
    """3 untyped failures then a success from the same account+IP -> a low-severity candidate hit."""
    from engine.hunt.rules import load_macros, run_rules
    from engine.store.db import connect, set_dataset_vars
    lines = [f"2026-10-06 10:00:0{i} portal user=frank src=10.9.9.9 result=FAILED" for i in range(3)]
    lines.append("2026-10-06 10:00:08 portal user=frank src=10.9.9.9 result=OK")
    (tmp_path / "portal.out").write_text("\n".join(lines) + "\n", encoding="utf-8")
    out = tmp_path / "_out"
    ingest(str(tmp_path), str(out), workers=1, log=lambda *_: None)
    con = connect(str(out), persist=False)
    set_dataset_vars(con)
    con.execute("CREATE TABLE ip_segments (ip VARCHAR, host VARCHAR, valid_from BIGINT, valid_to BIGINT, seg_no BIGINT)")
    con.execute("CREATE TABLE hosts (host VARCHAR, role VARCHAR)")
    load_macros(con)
    run_rules(con, log=lambda *_: None)
    hits = con.execute("SELECT rule_id, technique, severity, count(*) FROM hits GROUP BY ALL").fetchall()
    assert ("behav_fail_then_success", "T1110", 0.3, 4) in hits
