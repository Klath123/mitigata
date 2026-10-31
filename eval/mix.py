"""Mix mode: inject real attack recordings into a generated clean network, so baseline-driven (behaviour,
first-seen) detectors are tested on attacks nobody on the team wrote.

python -m eval.mix <clean_dataset> <corpus_dir> <corpus.labels.json> <out_dir> [--n 30] [--seed 1]

Each picked recording is time-shifted into the second half of the clean dataset (after the warm-up) and its
host name is replaced by one of the clean network's hosts. Output: the clean files + inj__<unit>/ folders,
and <out_dir>.labels.json in eval/blind.py format (score: python -m eval.blind <out_dir>.labels.json <run>).
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
from datetime import datetime, timedelta, timezone

TS = re.compile(r"(\d{4}-\d\d-\d\d)([T ])(\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:?\d\d)?")
HOSTKEYS = ("Hostname", "Computer", "host", "computer_name", "ComputerName")


def _parse(m: re.Match) -> datetime:
    return datetime.strptime(f"{m.group(1)} {m.group(3)}", "%Y-%m-%d %H:%M:%S")


def _first_ts(path: str) -> tuple[datetime | None, set[str]]:
    lo, hosts = None, set()
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            m = TS.search(line)
            if m:
                t = _parse(m)
                lo = t if lo is None or t < lo else lo
            for k in HOSTKEYS:
                hm = re.search(rf'"{k}"\s*:\s*"([^"]+)"', line)
                if hm:
                    hosts.add(hm.group(1))
            if i > 200_000:
                break
    return lo, hosts


def _shift(line: str, delta: timedelta) -> str:
    def rep(m: re.Match) -> str:
        t = _parse(m) + delta
        return f"{t:%Y-%m-%d}{m.group(2)}{t:%H:%M:%S}{m.group(4) or ''}{m.group(5) or ''}"
    return TS.sub(rep, line)


def mix(clean: str, corpus: str, labels_path: str, out: str, n: int = 30, seed: int = 1) -> dict:
    r = random.Random(seed)
    labels = json.load(open(labels_path))["units"]
    gt = json.load(open(os.path.join(clean, "ground_truth.json")))
    start = datetime.fromisoformat(gt["start"].replace("Z", "+00:00")).replace(tzinfo=None)
    end = datetime.fromisoformat(gt["end"].replace("Z", "+00:00")).replace(tzinfo=None)
    with open(os.path.join(clean, "windows", "security.jsonl"), encoding="utf-8") as f:
        hosts = sorted({m.group(1).split(".")[0] for line in f.readlines()[:50000]
                        for m in [re.search(r'"Computer":"([^"]+)"', line)] if m})
    hosts = [h for h in hosts if not h.startswith(("DC-", "FS-", "SQL-", "BK-"))] or hosts
    shutil.rmtree(out, ignore_errors=True)
    shutil.copytree(clean, out, ignore=shutil.ignore_patterns("ground_truth.json"))
    units = sorted(u for u in labels if os.path.isdir(os.path.join(corpus, u)))
    small = sorted(units, key=lambda u: sum(os.path.getsize(os.path.join(corpus, u, f))
                                             for f in os.listdir(os.path.join(corpus, u))))
    picked = r.sample(small[:max(n * 2, n)], min(n, len(small)))
    span = end - start
    out_units = {}
    for k, u in enumerate(sorted(picked)):
        at = start + span * (0.55 + 0.4 * k / max(1, len(picked)))     # spread over the post-warm-up half
        victim = r.choice(hosts)
        files = [os.path.join(corpus, u, f) for f in os.listdir(os.path.join(corpus, u))]
        lo = min((t for t, _ in map(_first_ts, files) if t), default=None)
        if lo is None:
            continue
        rec_hosts = set().union(*(_first_ts(p)[1] for p in files))
        names = sorted({h for h in rec_hosts if h}, key=len, reverse=True)
        rx = re.compile("|".join(re.escape(h) for h in names), re.I) if names else None
        delta = at - lo
        dst = os.path.join(out, f"inj__{u}")
        os.makedirs(dst, exist_ok=True)
        for p in files:
            with open(p, encoding="utf-8", errors="replace") as a, \
                    open(os.path.join(dst, os.path.basename(p)), "w", encoding="utf-8", newline="\n") as b:
                for line in a:
                    line = _shift(line, delta)
                    if rx:
                        line = rx.sub(lambda m: victim if "." not in m.group(0) else victim + ".corp.local", line)
                    b.write(line)
        out_units[f"inj__{u}"] = {**labels[u], "injected_at": at.isoformat() + "Z", "host": victim}
    with open(out.rstrip("/\\") + ".labels.json", "w") as f:
        json.dump({"corpus": f"mix:{os.path.basename(corpus)}", "units": out_units}, f, indent=1)
    return {"units": len(out_units), "hosts": len(hosts)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("clean"); ap.add_argument("corpus"); ap.add_argument("labels"); ap.add_argument("out")
    ap.add_argument("--n", type=int, default=30); ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args(argv)
    print(mix(a.clean, a.corpus, a.labels, a.out, a.n, a.seed))


if __name__ == "__main__":
    main()
