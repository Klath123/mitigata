"""Mapping suggestions: proposed, validated in code, written as pending, never applied as confirmed events."""
import shutil

import duckdb
import pytest
import yaml

from engine.ingest import suggest as S
from engine.ingest.mapper import DEFAULT_FIELDS
from engine.ingest.to_parquet import ingest

LINES = [f"2026-10-06 10:00:{i:02d} actor={u} remote=10.0.0.{i} operation={op}"
         for i, (u, op) in enumerate([("frank", "SIGNON_REFUSED"), ("frank", "SIGNON_REFUSED"), ("alice", "LOGIN_OK"),
                                      ("bob", "SIGNON_REFUSED"), ("bob", "FILE_READ"), ("carol", "LOGIN_OK")] * 3)]


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    root = tmp_path_factory.mktemp("sug")
    (root / "data").mkdir()
    (root / "data" / "vendor.out").write_text("\n".join(LINES) + "\n", encoding="utf-8")
    out = root / "run"
    ingest(str(root / "data"), str(out), workers=1, log=lambda *_: None)
    return root, out


def test_heuristic_suggestions(env):
    root, out = env
    path = root / "suggested.yaml"
    res = S.suggest(str(out), use_llm=False, path=str(path), log=lambda *_: None)
    got = {(a["source_field"], a["canonical"]) for a in res["field_aliases"]}
    assert ("actor", "user") in got and ("remote", "src_ip") in got and ("operation", "action") in got
    assert any(r["event_type"] == "auth:fail" for r in res["event_semantics"])
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert doc["status"] == "pending"


def test_validation_rejects_bad_llm_output(env):
    _, out = env
    s = S.sample(str(out))
    props = {"field_aliases": [
        {"source_field": "actor", "canonical": "username", "confidence": 0.9, "reason": "x", "source": "llm"},
        {"source_field": "nonexistent", "canonical": "user", "confidence": 0.9, "reason": "x", "source": "llm"},
        {"source_field": "actor", "canonical": "src_ip", "confidence": 0.9, "reason": "x", "source": "llm"}],
        "event_semantics": [
        {"name": "bare_failed", "event_type": "auth:fail", "confidence": 0.9, "reason": "x", "source": "llm",
         "all": [{"fields": ["operation"], "matches": "refused"}]},                      # no context condition
        {"name": "everything", "event_type": "auth:fail", "confidence": 0.9, "reason": "x", "source": "llm",
         "all": [{"fields": ["message"], "matches": "."}, {"fields": ["message"], "matches": "."}]},  # too broad
        {"name": "bad_regex", "event_type": "auth:fail", "confidence": 0.9, "reason": "x", "source": "llm",
         "all": [{"fields": ["message"], "matches": "("}, {"fields": ["message"], "matches": "x"}]},
        {"name": "good", "event_type": "auth:fail", "confidence": 0.8, "reason": "x", "source": "llm",
         "all": [{"fields": ["operation", "message"], "matches": "signon"},
                 {"fields": ["operation", "message"], "matches": "refused"}]}]}
    res = S.validate(props, s)
    reasons = {r.get("source_field", r.get("name")) + ":" + r["rejected"].split(":")[0] for r in res["rejected"]}
    assert "actor:unknown canonical field" in reasons
    assert "nonexistent:field not present in the sample" in reasons
    assert "actor:values are not IP addresses" in reasons
    assert "bare_failed:needs a context AND an outcome condition" in reasons
    assert any(x.startswith("everything:too broad") for x in reasons)
    assert any(x.startswith("bad_regex:invalid rule") for x in reasons)
    assert [r["name"] for r in res["event_semantics"]] == ["good"]


def test_pending_suggestion_is_not_a_confirmed_event(env, tmp_path):
    root, _ = env
    fields_dir = tmp_path / "mappings"
    fields_dir.mkdir()
    shutil.copy(DEFAULT_FIELDS, fields_dir / "fields.yaml")
    (fields_dir / "suggested.yaml").write_text(yaml.safe_dump({"status": "pending", "event_semantics": [
        {"name": "vendor_signon_refused", "event_type": "auth:fail", "confidence": 0.7,
         "all": [{"fields": ["operation"], "matches": "signon"}, {"fields": ["operation"], "matches": "refused"}]}]}),
        encoding="utf-8")
    out = tmp_path / "run2"
    ingest(str(root / "data"), str(out), workers=1, log=lambda *_: None, fields_path=str(fields_dir / "fields.yaml"))
    c = duckdb.connect()
    c.execute(f"CREATE VIEW e AS SELECT * FROM read_parquet('{(out / 'events').as_posix()}/*.parquet')")
    rows = c.execute("SELECT event_type, suggested_event_type, mapping_confidence, count(*) FROM e "
                     "GROUP BY ALL ORDER BY 4 DESC").fetchall()
    denied = [r for r in rows if r[1] == "auth:fail"]
    assert denied and denied[0][0] == "generic" and denied[0][2] == 0.7 and denied[0][3] == 9
