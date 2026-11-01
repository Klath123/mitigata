"""Build the submission archive: python -m eval.package [--out dist/attackstory-submission.zip]

Contents: every file git would commit (tracked + new, minus .gitignore), the prebuilt UI (frontend/dist) and the
finished demo runs under results/ that are named on the command line (default: firex, kbtest-kb), so the UI opens
without a run or Node. Never included: .env, keys, docs/*.local.md, datasets, Parquet / DuckDB files, caches.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NEVER = (".env", ".pem", ".key", ".local.md", ".duckdb", ".duckdb.wal", ".parquet")
RUN_FILES = ("incidents", "incidents.json", "evidence.json", "stats.json", "quality.json", "graph", "files.json",
             "ingest_report.json", "run_manifest.json", "validation.json", "entities.json")


def files(runs: list[str]) -> list[str]:
    out = subprocess.run(["git", "ls-files", "-co", "--exclude-standard", "-z"], cwd=ROOT, capture_output=True,
                         check=True).stdout.decode().split("\0")
    out = [f for f in out if f and os.path.isfile(os.path.join(ROOT, f))]
    extra = []
    for d in ["frontend/dist"] + [f"results/{r}/{x}" for r in runs for x in RUN_FILES]:
        p = os.path.join(ROOT, d)
        if os.path.isfile(p):
            extra.append(d)
        for base, _, fs in os.walk(p):
            extra += [os.path.relpath(os.path.join(base, f), ROOT).replace(os.sep, "/") for f in fs]
    return sorted({f for f in out + extra if not f.endswith(NEVER) and "/__pycache__/" not in f})


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", default=os.path.join(ROOT, "dist", "attackstory-submission.zip"))
    p.add_argument("--runs", nargs="*", default=["firex", "kbtest-kb"])
    a = p.parse_args(argv)
    fs = files(a.runs)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with zipfile.ZipFile(a.out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for f in fs:
            z.write(os.path.join(ROOT, f), f"attackstory/{f}")
    print(f"{a.out}: {len(fs)} files, {os.path.getsize(a.out) / 2**20:.1f} MB")


if __name__ == "__main__":
    main()
