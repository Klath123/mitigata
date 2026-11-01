"""Send log files to the backend and analyse them: upload -> engine run in the background -> a new run in the UI.

    POST /jobs                         -> {"job": "upload-20261101-091500"}       (a new, empty upload folder)
    PUT  /jobs/{job}/files?name=fw.log  body = the file's raw bytes (streamed to disk; any size up to the limit)
    POST /jobs/{job}/run                -> starts `python -m engine.run` on the folder (one job at a time)
    GET  /jobs/{job}                    -> status: uploading | running (stage n/6) | done | failed, last log lines
    GET  /jobs                          -> recent jobs

Files go to data/uploads/<job>/, results to results/<job>/ (so the run appears in the run picker). Raw bodies, not
multipart forms: nothing extra to install and gigabyte files stream straight to disk. The API listens on 127.0.0.1
by default; ATTACKSTORY_UPLOADS=0 turns uploads off, ATTACKSTORY_UPLOAD_MAX_GB caps one job (default 20).
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import time

from fastapi import FastAPI, HTTPException, Query, Request

JOB = re.compile(r"^upload-\d{8}-\d{6}(-\d+)?$")


def register(app: FastAPI, root: str, results: str) -> None:
    uploads = os.path.join(root, "data", "uploads")
    max_bytes = float(os.environ.get("ATTACKSTORY_UPLOAD_MAX_GB", "20")) * 2**30
    procs: dict[str, subprocess.Popen] = {}

    def enabled():
        if os.environ.get("ATTACKSTORY_UPLOADS", "1") == "0":
            raise HTTPException(403, "uploads are disabled on this server (ATTACKSTORY_UPLOADS=0)")

    def folder(job: str) -> str:
        if not JOB.match(job):                       # the job id is the only part of a path a client chooses
            raise HTTPException(404, "unknown job")
        d = os.path.join(uploads, job)
        if not os.path.isdir(d):
            raise HTTPException(404, "unknown job")
        return d

    def busy() -> str | None:
        return next((j for j, p in procs.items() if p.poll() is None), None)

    @app.post("/jobs")
    def new_job():
        enabled()
        os.makedirs(uploads, exist_ok=True)
        base = time.strftime("upload-%Y%m%d-%H%M%S", time.gmtime())
        job, n = base, 1
        while os.path.exists(os.path.join(uploads, job)):
            n += 1
            job = f"{base}-{n}"
        os.makedirs(os.path.join(uploads, job, "logs"))
        return {"job": job}

    @app.put("/jobs/{job}/files")
    async def put_file(job: str, request: Request, name: str = Query(..., description="file name, e.g. fw.log.gz")):
        enabled()
        d = folder(job)
        if job in procs:
            raise HTTPException(409, "this job is already running; start a new one")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(name.replace("\\", "/"))).lstrip(".") or "upload.log"
        used = sum(os.path.getsize(os.path.join(d, "logs", f)) for f in os.listdir(os.path.join(d, "logs")))
        path, size = os.path.join(d, "logs", safe), 0
        try:
            with open(path, "wb") as f:
                async for chunk in request.stream():
                    size += len(chunk)
                    if used + size > max_bytes:
                        raise HTTPException(413, f"upload limit is {max_bytes / 2**30:.0f} GB per job")
                    f.write(chunk)
        except HTTPException:
            os.remove(path)
            raise
        return {"job": job, "file": safe, "bytes": size}

    @app.post("/jobs/{job}/run")
    def run(job: str, llm: bool = Query(True, description="use the LLM agents if a key is set on the server")):
        enabled()
        d = folder(job)
        if not os.listdir(os.path.join(d, "logs")):
            raise HTTPException(400, "upload at least one file first")
        if (other := busy()) and other != job:
            raise HTTPException(409, f"job {other} is still running; one analysis at a time")
        if job in procs:
            return status(job)
        cmd = [sys.executable, "-u", "-m", "engine.run", os.path.join(d, "logs"), "--out", os.path.join(results, job)]
        if not llm:
            cmd.append("--no-llm")
        log = open(os.path.join(d, "run.log"), "w", encoding="utf-8")
        procs[job] = subprocess.Popen(cmd, cwd=root, stdout=log, stderr=subprocess.STDOUT)
        return status(job)

    @app.get("/jobs/{job}")
    def status(job: str):
        d = folder(job)
        files = sorted(os.listdir(os.path.join(d, "logs")))
        lines = []
        lp = os.path.join(d, "run.log")
        if os.path.exists(lp):
            with open(lp, encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        stages = [ln for ln in lines if re.match(r"^\[\d/6\]", ln)]
        p = procs.get(job)
        done_file = os.path.exists(os.path.join(results, job, "incidents.json"))
        if p is not None and p.poll() is None:
            state = "running"
        elif p is not None:
            state = "done" if p.returncode == 0 and done_file else "failed"
        else:
            state = "done" if done_file else ("uploaded" if files else "uploading")
        return {"job": job, "state": state, "files": files,
                "bytes": sum(os.path.getsize(os.path.join(d, "logs", f)) for f in files),
                "stage": stages[-1] if stages else None, "log_tail": lines[-12:],
                "run": job if state == "done" else None}

    @app.get("/jobs")
    def jobs():
        if not os.path.isdir(uploads):
            return {"jobs": []}
        return {"jobs": [status(j) for j in sorted(os.listdir(uploads), reverse=True)[:20] if JOB.match(j)]}
