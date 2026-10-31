"""Template discovery on an unknown free-text format: fields come out, event types are NOT invented."""
import random

import duckdb
import pytest

from engine.ingest.templates import compile_template
from engine.ingest.to_parquet import ingest

pytest.importorskip("drain3")


def make_log() -> str:
    rnd = random.Random(1)
    users = ["frank", "alice", "bob", "carol"]
    out = []
    for i in range(300):
        u, ip = rnd.choice(users), f"10.0.{rnd.randint(0, 9)}.{rnd.randint(1, 250)}"
        ts = f"2026-10-06 10:{i % 60:02d}:{i % 59:02d}"
        k = rnd.random()
        if k < 0.4:
            out.append(f"{ts} WARN Failed login for {u} from {ip} via portal")
        elif k < 0.7:
            out.append(f"{ts} INFO Login succeeded for {u} from {ip} via portal")
        elif k < 0.9:
            out.append(f"{ts} INFO Session {rnd.randint(1000, 9999)} closed for {u}")
        else:
            out.append(f"{ts} DEBUG cache rebuilt in {rnd.randint(1, 99)} ms")
    return "\n".join(out) + "\n"


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    root = tmp_path_factory.mktemp("tpl")
    (root / "app.custom").write_text(make_log(), encoding="utf-8")
    out = root / "_out"
    rep = ingest(str(root), str(out), workers=1, log=lambda *_: None)
    c = duckdb.connect()
    c.execute(f"CREATE VIEW e AS SELECT * FROM read_parquet('{(out / 'events').as_posix()}/*.parquet')")
    return rep, c


def test_compile_names_slots():
    rx, slots = compile_template("<TS> WARN Failed login for <*> from <IP> via portal")
    assert [s["name"] for s in slots] == ["ts", "user", "src_ip"]


def test_discovery_coverage(run):
    rep, _ = run
    t = rep["templates"]["app.custom"]
    assert t["coverage"] >= 0.95
    fields = {f for x in t["templates"] for f in x["fields"]}
    assert {"ts", "user", "src_ip"} <= fields


def test_fields_extracted_types_not_invented(run):
    _, c = run
    n, users, ips, ts = c.execute("SELECT count(*), count(\"user\"), count(src_ip), count(ts) FROM e").fetchone()
    assert n == 300 and ts == 300
    assert users >= 270                     # every line except the cache line names a user
    assert ips >= 200                       # login lines carry the source IP
    # the failed/success lines have no field-level context (no action=/status=) -> still unknown types;
    # a message pattern or approved semantic rule must type them, not the template miner
    types = dict(c.execute("SELECT type_source, count(*) FROM e GROUP BY 1").fetchall())
    assert set(types) <= {"unknown", "pattern"} or "semantic:auth_failure" in types
