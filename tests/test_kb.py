"""Knowledge base across batches: hits carry over, incidents grow in place, ids stay stable, agents are checked."""
import json
import os

import duckdb
import yaml

from engine import kb, verify_agent
from engine.ingest import suggest
from engine.ingest.mapper import DEFAULT_FIELDS, Mapper
from engine.results import store

H = 3_600_000


def step(order, ts, ev, stage="Initial Access", tech="T1078"):
    return {"order": order, "ts": ts, "time": f"2026-10-30T{ts // H:02d}:00:00Z", "host": "10.0.0.5", "user": "bob",
            "technique": tech, "technique_name": tech, "stage": stage, "summary": "x", "evidence": ev}


def inc(iid, steps, verdict="attack"):
    return {"incident_id": iid, "risk": 0.8, "verdict": verdict, "steps": steps, "path": ["10.0.0.5"], "hops": [],
            "first_seen": steps[0]["time"], "last_seen": steps[-1]["time"], "stages": [s["stage"] for s in steps],
            "report": [{"text": "bob logged on", "citations": steps[0]["evidence"][:1], "section": "summary"}],
            "graph": {"nodes": [{"id": "ctx:" + steps[0]["evidence"][0]}], "edges": []}}


def batch(tmp, name, incidents, evidence):
    out = tmp / name
    store.write(str(out), {"dataset": name, "processed": {"events": 10}},
                [i for i in incidents if i["verdict"] == "attack"], [i for i in incidents if i["verdict"] != "attack"],
                {"processed": {"events": 10}, "time_bounds": {"ds_start": 0, "ds_end": 1}})
    (out / "evidence.json").write_text(json.dumps({e: {"src_file": e.rpartition(":")[0],
                                                       "line": int(e.rpartition(":")[2]), "host": "10.0.0.5",
                                                       "user": "bob"} for e in evidence}))
    return str(out)


def test_incident_grows_in_place_across_batches(tmp_path):
    k = str(tmp_path / "kb")
    a = batch(tmp_path, "h01", [inc(1, [step(1, 1 * H, ["fw.log:7"])], "review")], ["fw.log:7"])
    assert kb.merge(a, k, log=lambda *_: None) == {1: 1}
    # next hour: the carried hit (now a kb: id) plus a new step, in a batch-local incident numbered 3
    b = batch(tmp_path, "h02", [inc(3, [step(1, 1 * H, ["kb:h01/fw.log:7"]),
                                        step(2, 2 * H, ["fw.log:9"], "Defense Evasion", "T1562")])],
              ["kb:h01/fw.log:7", "fw.log:9"])
    assert kb.merge(b, k, log=lambda *_: None) == {3: 1}            # same KB incident, not a new one
    summary, full, _ = store.load(k)
    assert list(full) == [1] and full[1]["verdict"] == "attack"
    i = full[1]
    assert [s["evidence"] for s in i["steps"]] == [["kb:h01/fw.log:7"], ["kb:h02/fw.log:9"]]
    assert i["kb"]["batches"] == ["h01", "h02"] and i["kb"]["created_run"] == "h01"
    assert i["report"][0]["citations"] == ["kb:h01/fw.log:7"] and i["graph"]["nodes"][0]["id"] == "ctx:kb:h01/fw.log:7"
    ev = json.load(open(os.path.join(k, "evidence.json")))
    assert {"kb:h01/fw.log:7", "kb:h02/fw.log:9"} <= set(ev)          # every cited line resolves in the view
    assert i["validation"]["fail"] == 0, i["validation"]
    assert len(summary["knowledge_base"]["batches"]) == 2


def test_bridging_incident_absorbs_the_newer_one(tmp_path):
    k = str(tmp_path / "kb")
    kb.merge(batch(tmp_path, "h01", [inc(1, [step(1, H, ["a.log:1"])]), inc(2, [step(1, H, ["a.log:2"])])],
                   ["a.log:1", "a.log:2"]), k, log=lambda *_: None)
    m = kb.merge(batch(tmp_path, "h02", [inc(1, [step(1, H, ["kb:h01/a.log:1"]), step(2, H, ["kb:h01/a.log:2"]),
                                                 step(3, 2 * H, ["b.log:5"])])],
                       ["kb:h01/a.log:1", "kb:h01/a.log:2", "b.log:5"]), k, log=lambda *_: None)
    assert m == {1: 1}
    _, full, _ = store.load(k)
    assert list(full) == [1] and full[1]["kb"]["merged"] == [2]


def _hits(con, rows):
    con.execute("CREATE OR REPLACE TABLE hits (rule_id VARCHAR, kind VARCHAR, severity DOUBLE, hit_key VARCHAR, "
                "src_file VARCHAR, line BIGINT, ts BIGINT, host VARCHAR, \"user\" VARCHAR, src_ip VARCHAR, "
                "dst_ip VARCHAR, event_type VARCHAR, noisy BOOLEAN)")
    con.executemany("INSERT INTO hits VALUES (?, 'rule', 0.8, ?, 'fw.log', ?, ?, '10.0.0.5', 'bob', '8.8.8.8', "
                    "'10.0.0.5', 'auth:fail', false)", rows)
    con.execute("CREATE OR REPLACE TABLE events AS SELECT src_file, line, ts, 'raw ' || line AS raw, 'kv' AS format, "
                "event_type, \"user\", src_ip FROM hits")
    con.execute("CREATE OR REPLACE MACRO is_internal(ip) AS ip LIKE '10.%'")


def test_hits_carry_into_later_batches_and_old_ones_are_pruned(tmp_path):
    k = str(tmp_path / "kb")
    c1 = duckdb.connect()
    _hits(c1, [("r1", "k1", 1, 1 * H), ("r1", "k1", 2, 1 * H + 5)])
    kb.attach(c1, k)
    kb.absorb(c1, "h01", log=lambda *_: None)
    c1.close()

    c2 = duckdb.connect()
    _hits(c2, [("r2", "k2", 1, 5 * H)])                                # same file name, a different batch
    kb.attach(c2, k)
    assert kb.carry_in(c2, "h05", log=lambda *_: None) == 2
    got = c2.execute("SELECT src_file, line FROM hits ORDER BY src_file, line").fetchall()
    assert got == [("fw.log", 1), ("kb:h01/fw.log", 1), ("kb:h01/fw.log", 2)]
    kb.absorb(c2, "h05", log=lambda *_: None)
    assert c2.execute("SELECT raw FROM kb.hits WHERE run = 'h05'").fetchone()[0] == "raw 1"
    ents = dict(c2.execute("SELECT kind || ':' || name, batches FROM kb.entities").fetchall())
    assert ents["account:bob"] == 2 and ents["external_ip:8.8.8.8"] == 2 and "external_ip:10.0.0.5" not in ents
    c2.close()

    c3 = duckdb.connect()                                               # 2 days later: h01 is out of the window
    _hits(c3, [("r3", "k3", 1, 53 * H)])
    kb.attach(c3, k)
    kb.absorb(c3, "h53", log=lambda *_: None)
    assert c3.execute("SELECT DISTINCT run FROM kb.hits ORDER BY 1").fetchall() == [("h53",)]
    c3.close()


def test_first_time_hit_is_not_repeated_in_a_later_batch(tmp_path):
    """fw_admin_from_internet is 'first access of this account from this address': batch 2's first row of the same
    hit must not join batch 1's, or the access step would swallow a later step's log line."""
    k = str(tmp_path / "kb")
    key = "fw_admin_from_internet#tejas.roy|admin|78.120.139.0"
    c1 = duckdb.connect()
    _hits(c1, [("fw_admin_from_internet", key, 1, 1 * H)])
    kb.attach(c1, k)
    kb.absorb(c1, "h01", log=lambda *_: None)
    c1.close()
    c2 = duckdb.connect()
    _hits(c2, [("fw_admin_from_internet", key, 7, 3 * H), ("brute_force", "bf#x", 8, 3 * H)])
    kb.attach(c2, k)
    kb.carry_in(c2, "h02", log=lambda *_: None)
    got = c2.execute("SELECT rule_id, src_file, line FROM hits ORDER BY src_file, line").fetchall()
    assert got == [("brute_force", "fw.log", 8), ("fw_admin_from_internet", "kb:h01/fw.log", 1)]
    c2.close()


def test_report_cache_matches_unchanged_incident():
    steps = [step(1, H, ["kb:h01/fw.log:7"])]
    assert kb.fingerprint(steps, "attack") == kb.fingerprint([dict(s) for s in steps], "attack")
    assert kb.fingerprint(steps, "attack") != kb.fingerprint(steps, "review")


def test_verification_agent_answers_are_checked_by_code():
    steps = [{**step(1, H, ["fw.log:7"]), "_rows": [{"src_file": "fw.log", "line": 7}]}]
    out = {"verdict": "disagree", "false_positive_likelihood": "high", "summary": "s", "issues": [
        {"step": 1, "kind": "technique_label", "severity": "high", "text": "ok", "citations": ["fw.log:7"]},
        {"step": 9, "kind": "stage", "severity": "low", "text": "no such step", "citations": []},
        {"step": 1, "kind": "other", "severity": "low", "text": "made up line", "citations": ["fw.log:999"]}]}
    r = verify_agent.check(out, {"incident_id": 1}, steps)
    assert [i["text"] for i in r["issues"]] == ["ok"] and len(r["dropped"]) == 2


def test_config_agent_applies_only_verified_confident_mappings(tmp_path):
    res = {"field_aliases": [{"source_field": "clientip", "canonical": "src_ip", "confidence": 0.9, "reason": "r"},
                             {"source_field": "who", "canonical": "user", "confidence": 0.9, "reason": "r"},
                             {"source_field": "box", "canonical": "host", "confidence": 0.5, "reason": "r"}],
           "event_semantics": [], "rejected": []}
    res = suggest.apply_verdicts(res, {"alias:0": ("confirm", "IPs"), "alias:1": ("reject", "status codes"),
                                       "alias:2": ("confirm", "names")})
    assert [a["source_field"] for a in res["field_aliases"]] == ["clientip", "box"]
    assert res["rejected"][0]["rejected"].startswith("verification agent")
    fields = tmp_path / "fields.yaml"
    fields.write_text(open(DEFAULT_FIELDS, encoding="utf-8").read(), encoding="utf-8")
    assert suggest.auto_apply(res, str(tmp_path / "h01"), path=str(tmp_path / "auto.yaml"), log=lambda *_: None) == 1
    auto = yaml.safe_load((tmp_path / "auto.yaml").read_text())
    assert [a["source_field"] for a in auto["field_aliases"]] == ["clientip"]      # 'box' was not confident enough
    canon = [c for c, _ in Mapper(str(fields)).leaf.get("clientip", [])]
    assert canon == ["src_ip"]                                       # the mapper loads auto.yaml next to fields.yaml


def test_firewall_is_protected_not_isolated():
    from engine.api.app import recommended_actions
    from engine.cluster.score import blast_radius
    steps = [{"technique": "T1078", "_rows": [{"host": "FGT60FTK00000000", "user": "tejas.roy", "src_ip": "78.120.139.0"},
                                              {"host": "10.10.40.5", "reporter": "FGT60FTK00000000"}]}]
    br = blast_radius(steps, [])
    assert br["infrastructure"] == ["FGT60FTK00000000"]
    acts = recommended_actions({"blast_radius": {"confirmed": br}, "steps": steps})
    assert acts[0] == "Isolate: 10.10.40.5" and acts[1].startswith("Protect (do not isolate)")
