"""Single-tactic clusters: never an incident; reviewed only when severe AND driven from the internet."""
from engine.cluster.score import REPORT, REVIEW, score
from engine.graph.build import Node


def node(key, sev, src_ip):
    return Node(key, "r", "t", "known_bad", "T1078", None, "Initial Access", sev, 0.5,
                rows=[{"ts": 1, "host": "FW", "user": "svc_backup", "src_ip": src_ip}])


def test_internet_logon_goes_to_review_not_attack():
    S, _ = score([node("a", 0.9, "203.0.113.7"), node("b", 0.9, "203.0.113.7")], ["Initial Access"])
    assert REVIEW <= S < REPORT


def test_internal_admin_work_stays_out():
    S, _ = score([node("a", 0.9, "10.0.0.5"), node("b", 0.9, "10.0.0.5")], ["Initial Access"])
    assert S < REVIEW


def test_low_severity_internet_noise_stays_out():
    S, _ = score([node("a", 0.25, "203.0.113.7"), node("b", 0.25, "203.0.113.7")], ["Initial Access"])
    assert S < REVIEW


def test_severe_multi_tactic_chain_on_a_critical_asset_is_an_attack():
    def n(key, sev, tactic, host):
        return Node(key, "r", "t", "known_bad", "T1562", None, tactic, sev, 0.5,
                    rows=[{"ts": 1, "host": host, "user": "tejas.roy", "src_ip": "78.120.139.0"}])
    nodes = [n("a", 0.45, "Initial Access", "FGT60"), n("b", 0.75, "Defense Evasion", "FGT60")]
    stages = ["Initial Access", "Defense Evasion"]
    S, br = score(nodes, stages, {"FGT60": 0.9})
    assert S >= REPORT and br["escalated_critical_asset"]
    S2, br2 = score(nodes, stages, {"FGT60": 0.3})                # same chain on a workstation: not escalated
    assert S2 < REPORT and not br2["escalated_critical_asset"]


def test_admin_work_on_a_critical_server_does_not_escalate():
    def n(key, sev, tactic, host):
        return Node(key, "r", "t", "known_bad", "T1569", None, tactic, sev, 0.5,
                    rows=[{"ts": 1, "host": host, "user": "it_admin", "src_ip": "10.0.0.5"}])
    nodes = [n("a", 0.6, "Lateral Movement", "FS-01"), n("b", 0.75, "Execution", "FS-01")]
    S, br = score(nodes, ["Lateral Movement", "Execution"], {"FS-01": 0.85})    # PsExec + service = admin work
    assert S < REPORT and not br["escalated_critical_asset"]
