from engine.cluster.score import build_steps
from engine.graph.build import Node


def _node(key, tech, tactic, line):
    row = {"ts": 1_000, "host": "FGT1", "user": "rakes", "src_file": "fw.log", "line": line, "src_ip": "203.0.113.9",
           "event_type": "fw:config", "message": "x"}
    return Node(key, key, key, "rule", tech, None, tactic, 0.7, 0.5, rows=[row])


def test_same_second_steps_follow_the_kill_chain():
    nodes = [_node("evasion", "T1562", "Defense Evasion", 2), _node("logon", "T1078", "Initial Access", 1)]
    for order in (nodes, nodes[::-1]):
        assert [s["technique"] for s in build_steps(order)] == ["T1078", "T1562"]


def test_a_broad_step_gives_up_the_line_a_specific_step_owns():
    """Incident 2 of the hackathon file: 'access from the internet' grouped the account-creation line with the new
    account's login; 'account created' is that line's own step. The access step keeps only the login."""
    def node(key, tech, tactic, rows, sev):
        return Node(key, key, key, "rule", tech, None, tactic, sev, 0.5, rows=rows)
    add = {"ts": 1_000, "host": "FGT1", "user": "rakes", "src_file": "fw.log", "line": 1, "src_ip": "203.0.113.9",
           "event_type": "fw:config", "message": "Add system.admin svc"}
    login = {**add, "ts": 60_000, "line": 2, "user": "svc", "event_type": "auth:success", "message": "svc logged in"}
    steps = build_steps([node("access", "T1078", "Initial Access", [add, login], 0.75),
                         node("create", "T1136", "Persistence", [add], 0.75)])
    assert [(s["technique"], s["evidence"]) for s in steps] == [("T1136", ["fw.log:1"]), ("T1078", ["fw.log:2"])]
    assert steps[0]["also"][0]["technique"] == "T1078"          # line 1 is also the first access from that address
    assert steps[1]["user"] == "svc" and "sign-in from 203.0.113.9" in steps[1]["summary"]   # rebuilt from its own line


def test_one_log_line_is_one_step_with_both_labels():
    """A change made from a new internet address is the access AND the tampering: one step, two labels, both
    stages still counted (score, verdict rules)."""
    from engine.cluster.score import step_stages
    access = _node("access", "T1078", "Initial Access", 7)
    tamper = _node("tamper", "T1562", "Defense Evasion", 7)
    tamper.severity = 0.75
    steps = build_steps([access, tamper])
    assert len(steps) == 1 and steps[0]["order"] == 1
    assert steps[0]["technique"] == "T1562" and steps[0]["also"][0]["technique"] == "T1078"
    assert set(step_stages(steps)) == {"Initial Access", "Defense Evasion"}
