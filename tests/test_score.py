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
