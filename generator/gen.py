"""Synthetic dataset generator with exact ground truth.

python -m generator.gen --out data/s1 --size 200MB --seed 1 [--days 3] [--scenarios prd,A,B,C | --clean]
"""
from __future__ import annotations

import argparse
import heapq
import json
import os
import time
from datetime import datetime, timezone

from .attacks import SCENARIOS
from .noise import MIN, Noise
from .world import build_world
from .writers import Sink, iso_z

START = int(datetime(2026, 10, 5, tzinfo=timezone.utc).timestamp() * 1000)   # a Monday


def parse_size(s: str) -> int:
    s = s.strip().upper()
    for unit, mul in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if s.endswith(unit):
            return int(float(s[:-2]) * mul)
    return int(s)


class NullSink(Sink):
    def __init__(self):
        super().__init__("")

    def _fh(self, rel, header=None, host=None):
        self.lines.setdefault(rel, 0)
        self.files.setdefault(rel, None)

    def _write(self, rel, text):
        self.bytes += len(text) + 1
        self.lines[rel] += 1
        return ""


def _bytes_per_day(seed: int, scale: float) -> int:
    w = build_world(seed)
    n = Noise(w, START, 1, scale)
    sink = NullSink()
    for m in range(1440):
        for e in n.tick(START + m * MIN):
            e.run(sink)
    return sink.bytes


def calibrate(seed: int, target: int, days: int) -> float:
    fixed = _bytes_per_day(seed, 0.0)
    bulk = _bytes_per_day(seed, 1.0) - fixed
    return max(0.02, (target / days - fixed) / max(bulk, 1))


def generate(out: str, size: int, seed: int, days: int, scenarios: list[str]) -> dict:
    t_start = time.time()
    os.makedirs(out, exist_ok=True)
    scale = calibrate(seed, size, days)
    w = build_world(seed)
    sink = Sink(out)
    noise = Noise(w, START, days, scale)
    rng = w.rng

    # schedule: attack i on day 1 + i % (days-1), start between 12:00 and 17:00
    pending = []
    for i, sc in enumerate(scenarios):
        day = 1 + (i % max(1, days - 1)) if days > 1 else 0
        t0 = START + day * 1440 * MIN + rng.randint(12 * 60, 17 * 60) * MIN
        pending.append((t0 - 330 * MIN, t0, i + 1, sc))    # built 5.5 h early so leases are current
    pending.sort()
    attacks = []
    queue: list = []                      # heap of attack Ev
    end = START + days * 1440 * MIN
    gt_evidence: dict[tuple, list[str]] = {}
    gt_first_ts: dict[tuple, int] = {}
    for m in range((end - START) // MIN):
        t = START + m * MIN
        while pending and pending[0][0] <= t:
            _, t0, aid, sc = pending.pop(0)
            at = SCENARIOS[sc](w, aid, t0)
            attacks.append(at)
            for e in at.events:
                heapq.heappush(queue, e)
        evs = noise.tick(t)
        while queue and queue[0].ts < t + MIN:
            evs.append(heapq.heappop(queue))
        evs.sort()
        for e in evs:
            eid = e.run(sink)
            if e.tag is not None:
                gt_evidence.setdefault(e.tag, []).append(eid)
                gt_first_ts[e.tag] = min(gt_first_ts.get(e.tag, e.ts), e.ts)
    while queue:                          # attack tail past the end of the span
        e = heapq.heappop(queue)
        eid = e.run(sink)
        if e.tag is not None:
            gt_evidence.setdefault(e.tag, []).append(eid)
            gt_first_ts[e.tag] = min(gt_first_ts.get(e.tag, e.ts), e.ts)
    sink.close()
    mpath = os.path.join(out, "manifest.json")          # the generator knows the year: declare it
    with open(mpath) as f:
        man = json.load(f)
    man["year"] = datetime.fromtimestamp(START / 1000, timezone.utc).year
    with open(mpath, "w") as f:
        json.dump(man, f, indent=1)

    gt = {"dataset": os.path.basename(os.path.abspath(out)), "seed": seed, "days": days,
          "start": iso_z(START), "end": iso_z(end), "bytes": sink.bytes,
          "lines": sum(sink.lines.values()), "attacks": [],
          # benign lookalikes the engine must NOT pull into an incident
          "decoys": {tag[1]: ev for tag, ev in gt_evidence.items() if tag[0] == "decoy"}}
    for at in attacks:
        steps = []
        for s in at.steps:
            tag = (at.id, s["step"])
            steps.append({**s, "time": iso_z(gt_first_ts[tag]), "ts": gt_first_ts[tag],
                          "evidence": gt_evidence.get(tag, [])})
        gt["attacks"].append({"attack_id": at.id, "scenario": at.scenario, "steps": steps})
    with open(os.path.join(out, "ground_truth.json"), "w") as f:
        json.dump(gt, f, indent=1)
    gt["seconds"] = round(time.time() - t_start, 1)
    return gt


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", required=True)
    p.add_argument("--size", default="100MB")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--days", type=int, default=3)
    p.add_argument("--scenarios", default="prd,A,B,C")
    p.add_argument("--clean", action="store_true", help="no attacks")
    a = p.parse_args(argv)
    scen = [] if a.clean else [s for s in a.scenarios.split(",") if s]
    for s in scen:
        if s not in SCENARIOS:
            p.error(f"unknown scenario {s}; choose from {list(SCENARIOS)}")
    gt = generate(a.out, parse_size(a.size), a.seed, a.days, scen)
    print(f"wrote {gt['bytes'] / 2**20:.1f} MB, {gt['lines']:,} lines, {len(gt['attacks'])} attacks, "
          f"{sum(len(x['steps']) for x in gt['attacks'])} steps in {gt['seconds']}s -> {a.out}")


if __name__ == "__main__":
    main()
