import json

from engine.narrate import llm


def test_story_carries_event_detail_and_needs_a_key(monkeypatch):
    row = {"src_file": "fw.log", "line": 7, "ts": 1792773060000, "host": "FGT1", "user": "tejas.roy",
           "message": "Attribute 'status' of setting 'log disk' changed", "cmdline": None, "src_ip": "78.120.139.0"}
    step = {"order": 1, "time": "2026-10-23T16:31:00Z", "host": "FGT1", "user": "tejas.roy", "technique": "T1562",
            "stage": "Defense Evasion", "summary": "logging disabled", "_rows": [row]}
    story = json.loads(llm.story_json({"incident_id": 1, "risk": 0.7, "path": ["FGT1"]}, [step]))
    ev = story["events"][0]
    assert ev["id"] == "fw.log:7" and "log disk" in ev["message"] and "cmdline" not in ev
    assert ev["time"] == "2026-10-23 16:31 UTC"          # the format checker.py verifies
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert llm.narrate({"incident_id": 1, "risk": 0.7, "path": []}, [step]) is None
