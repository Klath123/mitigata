"""Sending log files to the backend (engine/api/uploads.py): safe paths, size limit, one job at a time."""
import os

from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.api import uploads


class FakeProc:
    def __init__(self, cmd, **kw):
        self.cmd, self.returncode = cmd, None

    def poll(self):
        return self.returncode


def client(tmp_path, monkeypatch, max_gb="20"):
    monkeypatch.setenv("ATTACKSTORY_UPLOAD_MAX_GB", max_gb)
    started = []
    monkeypatch.setattr(uploads.subprocess, "Popen", lambda cmd, **kw: started.append(FakeProc(cmd)) or started[-1])
    app = FastAPI()
    uploads.register(app, str(tmp_path), str(tmp_path / "results"))
    return TestClient(app), started


def test_upload_then_run(tmp_path, monkeypatch):
    c, started = client(tmp_path, monkeypatch)
    job = c.post("/jobs").json()["job"]
    assert c.post(f"/jobs/{job}/run").status_code == 400                       # nothing uploaded yet
    r = c.put(f"/jobs/{job}/files", params={"name": "../../etc/evil.sh"}, content=b"date=2026-10-23 a=1\n")
    assert r.json() == {"job": job, "file": "evil.sh", "bytes": 20}             # no way out of the job folder
    assert os.path.exists(tmp_path / "data" / "uploads" / job / "logs" / "evil.sh")
    s = c.post(f"/jobs/{job}/run", params={"llm": "false"}).json()
    cmd = started[0].cmd
    assert s["state"] == "running" and "--no-llm" in cmd and cmd[cmd.index("--out") + 1].endswith(job)
    other = c.post("/jobs").json()["job"]
    c.put(f"/jobs/{other}/files", params={"name": "b.log"}, content=b"x\n")
    assert c.post(f"/jobs/{other}/run").status_code == 409                     # one analysis at a time
    started[0].returncode = 0
    os.makedirs(tmp_path / "results" / job)
    (tmp_path / "results" / job / "incidents.json").write_text("{}")
    assert c.get(f"/jobs/{job}").json()["state"] == "done"


def test_bad_ids_and_size_limit(tmp_path, monkeypatch):
    c, _ = client(tmp_path, monkeypatch, max_gb=str(10 / 2**30))                # 10 bytes
    assert c.get("/jobs/..%2F..%2Fresults").status_code == 404
    assert c.get("/jobs/upload-1").status_code == 404
    job = c.post("/jobs").json()["job"]
    assert c.put(f"/jobs/{job}/files", params={"name": "big.log"}, content=b"x" * 64).status_code == 413
    assert os.listdir(tmp_path / "data" / "uploads" / job / "logs") == []


def test_uploads_can_be_switched_off(tmp_path, monkeypatch):
    c, _ = client(tmp_path, monkeypatch)
    monkeypatch.setenv("ATTACKSTORY_UPLOADS", "0")
    assert c.post("/jobs").status_code == 403
