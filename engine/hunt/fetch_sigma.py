"""Fetch SigmaHQ community rules into rules/sigma/sigmahq/ (git-ignored; Detection Rule License 1.1).

python -m engine.hunt.fetch_sigma [--ref master] [--hunting]

Kept: every log family the engine can ingest - windows, linux, network (FortiGate, DNS, firewall, Zeek, Cisco),
web (webserver, proxy), cloud and identity; --hunting adds rules-threat-hunting (broader, noisier, weak signals).
The converter refuses what it can't run faithfully and reports why, so unused families cost nothing.
"""
from __future__ import annotations

import argparse
import io
import os
import shutil
import urllib.request
import zipfile
from datetime import datetime, timezone

from .rules import RULES_DIR

DEST = os.path.join(RULES_DIR, "sigma", "sigmahq")


def fetch(ref: str = "master", hunting: bool = False) -> int:
    url = f"https://github.com/SigmaHQ/sigma/archive/{ref}.zip"
    data = urllib.request.urlopen(url, timeout=120).read()
    keep = [f"rules/{d}/" for d in ("windows", "linux", "network", "web", "cloud", "identity")] +         (["rules-threat-hunting/windows/", "rules-threat-hunting/linux/"] if hunting else [])
    shutil.rmtree(DEST, ignore_errors=True)
    n = 0
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for m in z.infolist():
            rel = m.filename.split("/", 1)[1] if "/" in m.filename else ""
            if m.is_dir() or not rel.endswith(".yml") or not any(rel.startswith(k) for k in keep) or ".." in rel:
                continue
            out = os.path.join(DEST, *rel.split("/"))
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with z.open(m) as a, open(out, "wb") as b:
                shutil.copyfileobj(a, b)
            n += 1
    with open(os.path.join(DEST, "SOURCE.txt"), "w") as f:
        f.write(f"SigmaHQ {url}\nfetched {datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}, {n} rules, "
                f"folders {keep}\nLicense: Detection Rule License (DRL) 1.1 - https://github.com/SigmaHQ/Detection-Rule-License\n")
    return n


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ref", default="master")
    ap.add_argument("--hunting", action="store_true")
    a = ap.parse_args(argv)
    print(f"{fetch(a.ref, a.hunting)} rules -> {DEST}")


if __name__ == "__main__":
    main()
