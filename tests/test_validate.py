from engine.validate import check_incident

EV = {"fw:1": {"src_file": "fw", "line": 1, "ts": 1000, "host": "FW-01", "src_ip": "10.0.1.22", "dst_ip": "8.8.4.4",
               "user": None},
      "fw:2": {"src_file": "fw", "line": 2, "ts": 2000, "host": "FW-01", "src_ip": "203.0.113.9", "user": "rakes"},
      "fw:3": {"src_file": "fw", "line": 3, "ts": 3000, "host": "FW-01", "src_ip": "203.0.113.9", "user": "rakes"}}


def step(order, ts, stage, tech, host, user, ev):
    return {"order": order, "ts": ts, "stage": stage, "technique": tech, "sub_technique": None, "host": host,
            "user": user, "evidence": ev}


def status(inc, ev=EV):
    return {c["check"]: (c["status"], c["steps"]) for c in check_incident(inc, ev)["checks"]}


def test_consistent_chain_passes_and_resolved_host_counts():
    inc = {"verdict": "attack", "resolved_hosts": {"10.0.1.22": "FS-02"},
           "steps": [step(1, 2000, "Initial Access", "T1078", "FW-01", "rakes", ["fw:2"]),
                     step(2, 3000, "Defense Evasion", "T1562", "FW-01", "rakes", ["fw:3"]),
                     step(3, 3000, "Exfiltration", "T1041", "FS-02", None, ["fw:1"])],
           "graph": {"edges": [{"kind": "evidence", "src": "step1", "dst": "step2"},
                               {"kind": "evidence", "src": "step2", "dst": "step3"}]},
           "report": [{"text": "FS-02 sent data to 8.8.4.4.", "citations": ["fw:1"]}]}
    s = status(inc)
    assert all(v[0] == "pass" for v in s.values()), s


def test_flaws_are_flagged_on_the_right_steps():
    inc = {"verdict": "attack",
           "steps": [step(1, 2000, "Defense Evasion", "T1562", "FW-01", "rakes", ["fw:2", "fw:3"]),
                     step(2, 2000, "Initial Access", "T1078", "FW-01", "rakes", ["fw:2"]),
                     step(3, 3000, "Exfiltration", "T1041", "FS-02", None, ["fw:1", "fw:9"])],
           "graph": {"edges": [{"kind": "evidence", "src": "step1", "dst": "step2"}]},
           "report": [{"text": "rakes logged on from 198.51.100.7.", "citations": ["fw:2"]}]}
    s = status(inc)
    assert s["evidence_exists"][0] == "fail"                       # fw:9 does not exist
    assert s["evidence_matches_step"] == ("fail", [3])            # FS-02 named, no mapping given
    assert s["killchain_order"] == ("warn", [2])
    assert s["steps_linked"] == ("warn", [3])
    assert s["distinct_evidence"] == ("warn", [2])
    assert s["report_grounded"][0] == "fail"                      # IP not in the cited event
