"""run_manifest.json: what exactly produced this result (inputs, engine, config, counts).

Lets anyone check, re-run and compare: same input hashes + same engine commit + same config hash
should give the same incidents. File hashes are FAST by default (sha256 of size + first/middle/last MB,
seconds even for 15 GB); --hash-full computes a full SHA-256 of every input file.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import platform
import subprocess
import uuid
from datetime import datetime, timezone
from importlib import metadata

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHUNK = 1 << 20


def file_hash(path: str, full: bool = False) -> dict:
    size = os.path.getsize(path)
    h = hashlib.sha256()
    with open(path, "rb") as f:
        if full:
            for block in iter(lambda: f.read(8 * CHUNK), b""):
                h.update(block)
        else:
            h.update(str(size).encode())
            for pos in sorted({0, max(0, size // 2 - CHUNK // 2), max(0, size - CHUNK)}):
                f.seek(pos)
                h.update(f.read(CHUNK))
    return {"size": size, "sha256": h.hexdigest(), "hash_kind": "full" if full else "fast(size+first/mid/last MB)"}


def config_hash() -> dict:
    """One hash over every rule and mapping file (the 'config version'), plus per-file hashes."""
    files = sorted(glob.glob(os.path.join(ROOT, "rules", "**", "*.*"), recursive=True))
    per, total = {}, hashlib.sha256()
    for p in files:
        with open(p, "rb") as f:
            data = f.read()
        rel = os.path.relpath(p, ROOT).replace(os.sep, "/")
        per[rel] = hashlib.sha256(data).hexdigest()[:16]
        total.update(rel.encode() + b"\0" + data)
    return {"sha256": total.hexdigest(), "files": per}


def engine_version() -> dict:
    def git(*args):
        try:
            return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""
    commit = git("rev-parse", "HEAD")
    dirty = bool(git("status", "--porcelain", "--untracked-files=no"))
    libs = {}
    for name in ("duckdb", "pyarrow", "networkx", "drain3", "orjson", "python-evtx", "anthropic"):
        try:
            libs[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            pass
    return {"git_commit": commit or None, "uncommitted_changes": dirty, "python": platform.python_version(),
            "libraries": libs}


def write(run_dir: str, dataset: str, started: float, finished: float, ingest_report: dict, stats: dict,
          full_hash: bool = False) -> dict:
    files = {}
    fp = os.path.join(run_dir, "files.json")
    if os.path.exists(fp):
        with open(fp, encoding="utf-8") as f:
            for rel, info in json.load(f).items():
                try:
                    files[rel] = {**file_hash(info["path"], full_hash), "format": info.get("format")}
                except OSError as ex:
                    files[rel] = {"error": str(ex)}
    proc = stats.get("processed", {})
    m = {
        "run_id": str(uuid.uuid4()),
        "dataset": os.path.abspath(dataset),
        "started_at": datetime.fromtimestamp(started, timezone.utc).isoformat(timespec="seconds"),
        "completed_at": datetime.fromtimestamp(finished, timezone.utc).isoformat(timespec="seconds"),
        "status": "completed",
        "engine": engine_version(),
        "config": config_hash(),
        "inputs": files,
        "skipped_inputs": ingest_report.get("skipped", []),
        "records": {"lines_read": ingest_report.get("lines"), "records": proc.get("events"),
                    "parsed": (proc.get("events") or 0) - (proc.get("unparsed") or 0),
                    "failed_to_parse": proc.get("unparsed"),
                    "excluded_from_detection": stats.get("data_quality", {}).get("records_excluded_from_detection")},
        "results": {"attack_incidents": stats.get("counts", {}).get("attack_incidents"),
                    "review_incidents": stats.get("counts", {}).get("review_incidents"),
                    "incident_ids": sorted(int(f[:-5]) for f in os.listdir(os.path.join(run_dir, "incidents"))
                                           if f.endswith(".json")) if os.path.isdir(
                        os.path.join(run_dir, "incidents")) else []},
    }
    with open(os.path.join(run_dir, "run_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(m, f, indent=1)
    return m
