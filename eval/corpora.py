"""Turn public attack-recording corpora into engine datasets plus labels (blind benchmark input).

python -m eval.corpora <bench_dir> [--splunk-budget-mb 3000]

<bench_dir> holds the raw clones (EVTX-ATTACK-SAMPLES, Security-Datasets, attack_data). For each corpus this writes
<bench_dir>/corpora/<name>/ (one folder per labelled recording) and <bench_dir>/corpora/<name>.labels.json:
  {"corpus": name, "units": {"<folder>": {"techniques": [...], "tactics": [...], "source": "..."}}}
A unit is labelled by folder, so every file the engine reads from it inherits the label.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import zipfile

import yaml

TA = {"TA0043": "Reconnaissance", "TA0042": "Resource Development", "TA0001": "Initial Access",
      "TA0002": "Execution", "TA0003": "Persistence", "TA0004": "Privilege Escalation",
      "TA0005": "Defense Evasion", "TA0006": "Credential Access", "TA0007": "Discovery",
      "TA0008": "Lateral Movement", "TA0009": "Collection", "TA0011": "Command and Control",
      "TA0010": "Exfiltration", "TA0040": "Impact"}
SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def _write(out_dir: str, name: str, units: dict) -> None:
    with open(os.path.join(out_dir, f"{name}.labels.json"), "w") as f:
        json.dump({"corpus": name, "units": units}, f, indent=1)
    print(f"{name}: {len(units)} labelled units")


def evtx(bench: str, out: str) -> None:
    """EVTX-ATTACK-SAMPLES: folder = tactic (technique mapping lives in an external sheet)."""
    src = os.path.join(bench, "EVTX-ATTACK-SAMPLES")
    dst = os.path.join(out, "evtx")
    units = {}
    for p in sorted(glob.glob(os.path.join(src, "*", "*.evtx"))):
        tactic = os.path.basename(os.path.dirname(p))
        if tactic not in TA.values():
            continue
        unit = SAFE.sub("_", f"{tactic}__{os.path.splitext(os.path.basename(p))[0]}")
        os.makedirs(os.path.join(dst, unit), exist_ok=True)
        shutil.copy(p, os.path.join(dst, unit, os.path.basename(p)))
        units[unit] = {"techniques": [], "tactics": [tactic], "source": os.path.relpath(p, bench)}
    _write(out, "evtx", units)


def otrf(bench: str, out: str) -> None:
    """OTRF Security-Datasets atomic/windows: metadata YAML gives techniques + tactics and the zip it describes."""
    root = os.path.join(bench, "Security-Datasets")
    dst = os.path.join(out, "otrf")
    units = {}
    for m in sorted(glob.glob(os.path.join(root, "datasets", "atomic", "_metadata", "*.yaml"))):
        try:
            d = yaml.safe_load(open(m, encoding="utf-8"))
        except Exception:
            continue
        techs, tacs = [], []
        for am in d.get("attack_mappings") or []:
            t = am.get("technique")
            if t:
                sub = am.get("sub-technique")
                techs.append(f"{t}.{sub}" if sub else t)
            tacs += [TA.get(x, x) for x in am.get("tactics") or []]
        zips = []
        for f in d.get("files") or []:
            link = f.get("link") or ""
            i = link.find("datasets/atomic/windows/")
            if i >= 0 and link.endswith(".zip"):
                zips.append(os.path.join(root, link[i:]))
        zips = [z for z in zips if os.path.exists(z)]
        if not techs or not zips:
            continue
        unit = SAFE.sub("_", d.get("id") or os.path.basename(m))
        os.makedirs(os.path.join(dst, unit), exist_ok=True)
        for z in zips:
            with zipfile.ZipFile(z) as zf:
                for member in zf.infolist():
                    if member.is_dir() or ".." in member.filename:
                        continue
                    target = os.path.join(dst, unit, SAFE.sub("_", os.path.basename(member.filename)))
                    with zf.open(member) as a, open(target, "wb") as b:
                        shutil.copyfileobj(a, b)
        units[unit] = {"techniques": sorted(set(techs)), "tactics": sorted(set(tacs)),
                       "source": os.path.relpath(m, bench), "title": d.get("title")}
    _write(out, "otrf", units)


LFS_SIZE = re.compile(rb"^size (\d+)$", re.M)
WIN_LOG = re.compile(r"(sysmon|security|powershell)[^/]*\.log$", re.I)


def splunk(bench: str, out: str, budget_mb: int) -> None:
    """Splunk attack_data: technique folder = label. Picks Windows Sysmon/Security/PowerShell logs (smallest first,
    one recording per technique folder first) within a download budget, then pulls only those LFS objects."""
    repo = os.path.join(bench, "attack_data")
    cands = []
    for y in sorted(glob.glob(os.path.join(repo, "datasets", "attack_techniques", "T*", "*", "*.yml"))):
        try:
            d = yaml.safe_load(open(y, encoding="utf-8"))
        except Exception:
            continue
        techs = [t for t in (d.get("mitre_technique") or []) if re.fullmatch(r"T\d{4}(\.\d{3})?", str(t))]
        for ds in d.get("datasets") or []:
            rel = (ds.get("path") or "").lstrip("/")
            p = os.path.join(repo, rel)
            if not techs or not WIN_LOG.search(rel) or not os.path.exists(p):
                continue
            head = open(p, "rb").read(200)
            m = LFS_SIZE.search(head)
            size = int(m.group(1)) if m else os.path.getsize(p)
            cands.append((size, rel, techs, os.path.relpath(y, repo)))
    # breadth first: the smallest recording of every technique folder, then the rest, until the budget is used
    first, rest, seen = [], [], set()
    for c in sorted(cands):
        key = c[1].split("/")[2]
        (rest if key in seen else first).append(c)
        seen.add(key)
    picked, total = [], 0
    for c in first + rest:
        if c[0] > 200 << 20:
            continue
        if total + c[0] > budget_mb << 20:
            break
        picked.append(c)
        total += c[0]
    print(f"splunk: pulling {len(picked)} files, {total / 2**20:.0f} MB")
    for i in range(0, len(picked), 100):
        inc = ",".join(c[1] for c in picked[i:i + 100])
        subprocess.run(["git", "lfs", "pull", "--include", inc], cwd=repo, check=False)
    dst = os.path.join(out, "splunk")
    units = {}
    for size, rel, techs, yml in picked:
        p = os.path.join(repo, rel)
        if open(p, "rb").read(40).startswith(b"version https://git-lfs"):
            continue                                       # pull failed for this one
        unit = SAFE.sub("_", "__".join(rel.split("/")[2:4]) + "__" + os.path.splitext(os.path.basename(rel))[0])
        os.makedirs(os.path.join(dst, unit), exist_ok=True)
        shutil.copy(p, os.path.join(dst, unit, os.path.basename(rel)))
        units[unit] = {"techniques": sorted(set(techs)), "tactics": [], "source": yml}
    _write(out, "splunk", units)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("bench")
    ap.add_argument("--splunk-budget-mb", type=int, default=3000)
    ap.add_argument("--only", default="evtx,otrf,splunk")
    a = ap.parse_args(argv)
    out = os.path.join(a.bench, "corpora")
    os.makedirs(out, exist_ok=True)
    only = a.only.split(",")
    if "evtx" in only:
        evtx(a.bench, out)
    if "otrf" in only:
        otrf(a.bench, out)
    if "splunk" in only:
        splunk(a.bench, out, a.splunk_budget_mb)


if __name__ == "__main__":
    main()
