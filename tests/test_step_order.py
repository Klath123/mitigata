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
