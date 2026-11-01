"""The ATT&CK label table (rules/mappings/attack_labels.yaml): valid against MITRE's bundle, examples labelled as
written, and the SQL labeller (detection) agreeing with the Python one (chain checks)."""
import os

import duckdb
import pytest

from engine.attack import stix
from engine.hunt import labels

BUNDLE = os.path.join(os.path.dirname(__file__), "..", "rules", "attack", "enterprise-attack.json")
TECHNIQUES = {e["technique"] for e in labels.load()} | {t for e in labels.load() for t in (e.get("by_source") or {}).values()} \
    | {e["recently_created"]["technique"] for e in labels.load() if e.get("recently_created")}


@pytest.mark.skipif(not os.path.exists(BUNDLE), reason="MITRE bundle not installed (rules/attack/enterprise-attack.json)")
def test_every_label_is_a_live_attack_technique_on_its_stage():
    rv = stix.revoked()
    for tid in sorted(TECHNIQUES):
        assert tid not in rv, f"{tid} is retired in ATT&CK, use {rv[tid]}"
        assert stix.name(tid), f"{tid} is not in the ATT&CK bundle"
    for e in labels.load():
        for tid, stage in [(e["technique"], e["stage"])] + [(t, e["stage"]) for t in (e.get("by_source") or {}).values()] \
                + ([(e["recently_created"]["technique"], e["recently_created"]["stage"])] if e.get("recently_created") else []):
            assert stage in stix.tactics(tid), f"{e['key']}: {tid} is {stix.tactics(tid)}, not {stage}"


def test_examples_get_their_label():
    for e in labels.load():
        for ex in e["examples"]:
            assert labels.key_of(ex.lower()) == e["key"], f"{ex!r} -> {labels.key_of(ex.lower())}, want {e['key']}"


def test_sql_labeller_agrees_with_python():
    con = duckdb.connect()
    labels.install(con)
    for e in labels.load():
        for ex in e["examples"]:
            assert con.execute("SELECT change_label(?)", [ex.lower()]).fetchone()[0] == e["key"], ex
    assert con.execute("SELECT change_label('ping succeeded')").fetchone()[0] is None


def test_same_change_same_label_whatever_reports_it():
    fw = labels.classify("Delete firewall.policy 12", "fw")
    win = labels.classify("Delete firewall rule 'Allow RDP'", "win")
    assert (fw["technique"], fw["sub_technique"]) == ("T1686", "T1686.002")       # network device firewall
    assert (win["technique"], win["sub_technique"]) == ("T1686", "T1686.003")     # Windows host firewall
    assert labels.classify("Delete system.admin bob", "fw")["technique"] == "T1531"            # locks an owner out
    assert labels.classify("Delete system.admin bob", "fw", recently_created=True)["technique"] == "T1070"  # backdoor


def test_retired_ids_from_any_rule_become_current():
    assert stix.current("T1562", "T1562.004") == ("T1686", None)
    assert stix.current("T1562", "T1562.013") == ("T1686", "T1686.002")
    assert stix.current("T1070", "T1070.001") == ("T1685", "T1685.005")
    assert stix.current("T1078", "T1078.003") == ("T1078", "T1078.003")
