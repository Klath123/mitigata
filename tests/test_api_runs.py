from fastapi.testclient import TestClient

from engine.api import app as api
from engine.results import store


def test_runs_are_listed_and_switchable_by_name_only(tmp_path, monkeypatch):
    inc = lambda i, v: {"incident_id": i, "risk": 0.8 if v == "attack" else 0.5, "verdict": v, "steps": [],
                        "stages": [], "path": [], "alerts_merged": 1, "first_seen": "", "last_seen": ""}
    store.write(str(tmp_path / "a"), {"dataset": "a"}, [inc(1, "attack")], [], {})
    store.write(str(tmp_path / "b"), {"dataset": "b"}, [], [inc(1, "review"), inc(2, "review")], {})
    monkeypatch.setattr(api, "RESULTS", str(tmp_path))
    c = TestClient(api.create_app(str(tmp_path / "a")))
    runs = c.get("/runs").json()
    assert runs["active"] == "a" and {r["run"]: r["review_incidents"] for r in runs["runs"]} == {"a": 0, "b": 2}
    assert c.post("/reload", params={"run": "b"}).json()["run"] == "b"
    assert c.get("/incidents", params={"include_review": True}).json()["count"] == 2
    assert c.post("/reload", params={"run": "../a"}).status_code == 404
