import duckdb
import pyarrow as pa

from engine.hunt.rules import run_rules
from engine.schema import EVENT_SCHEMA, FIELD_NAMES


def _con(rows):
    con = duckdb.connect()
    tbl = pa.Table.from_pylist([{f: r.get(f) for f in FIELD_NAMES} for r in rows], schema=EVENT_SCHEMA)
    con.register("ev_arrow", tbl)
    con.execute("CREATE TABLE events AS SELECT * FROM ev_arrow")
    return con


def test_rule_without_its_telemetry_is_disabled_with_a_reason():
    con = _con([{"ts": 1, "src_file": "a", "line": 1, "event_type": "sysmon:1", "process": "x.exe", "host": "H"}])
    rules = [
        {"id": "needs_dll_loads", "sql": "SELECT e.* FROM events e WHERE e.event_type = 'sysmon:7'",
         "requires": {"event_types": ["sysmon:7"], "fields": ["image_loaded"]}},
        {"id": "needs_proc", "sql": "SELECT e.* FROM events e WHERE e.event_type = 'sysmon:1'",
         "requires": {"event_types": ["sysmon:1"], "fields": ["process"]}, "technique": "T1059"},
    ]
    st = run_rules(con, rules, log=lambda *_: None)
    assert "sysmon:7" in st["needs_dll_loads"]["disabled"] and "image_loaded" in st["needs_dll_loads"]["disabled"]
    assert "disabled" not in st["needs_proc"] and st["needs_proc"]["hits"] == 1


def test_variation_keeps_ground_truth_consistent(tmp_path):
    import json
    from generator.gen import generate
    out = tmp_path / "v"
    gt = generate(str(out), 2 << 20, seed=1, days=2, scenarios=["prd"], vary=5)
    lines = {}
    for a in gt["attacks"]:
        for s in a["steps"]:
            assert "adm_meera" not in (s["user"] or "") and "FS-02" not in (s["host"] or "")
            for e in s["evidence"]:
                f, _, n = e.rpartition(":")
                lines.setdefault(f, open(out / f, encoding="utf-8").read().split("\n"))
                assert int(n) <= len(lines[f])               # every evidence id points at a real line
    text = "".join(open(out / f, encoding="utf-8").read() for f in lines)
    assert "PSEXESVC" not in text and "adm_meera" not in text
    assert json.load(open(out / "ground_truth.json"))["variation"]["seed"] == 5
