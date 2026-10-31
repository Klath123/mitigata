# AttackStory scoreboard

How detection quality changed, measured on data the engine was **not** written for. Produced by
`eval/bench.sh <tag> <bench_dir> <python> [all|synth|blind]` on the benchmark boxes; raw JSON per round lives in
`<bench_dir>/out/<tag>/`.

## Datasets

| Set | What | Labels |
|---|---|---|
| `dev_s1` | our scenarios prd, A, B, C (100 MB, 3 days) | exact (generator) |
| `clean` | normal activity + decoys, no attack | any attack incident = false alarm |
| `hold_de` | holdout D (loader → Kerberoast → RDP → DLL side-load → DNS exfil), E (Security-log-only server attack) | exact — **no longer blind** (looked at during Phase 2) |
| `vary` | `dev_s1` attacks with every tool/path/host/account renamed and timing stretched | exact |
| `nosysmon` | `vary` + Sysmon removed | exact; steps with no evidence left are excluded |
| EVTX | EVTX-ATTACK-SAMPLES, 261 recordings | tactic (folder) |
| OTRF | OTRF Security-Datasets atomic/windows, 97 recordings | technique + tactic (metadata) |
| Splunk | Splunk attack_data, 530 Windows/Sysmon/PowerShell recordings | technique (folder) |
| mix | 30 OTRF recordings injected into `clean` (time-shifted, host renamed) | technique + tactic |

Blind metrics per recording: *detected* = any hit; *technique/tactic right* = a hit with the label's parent
technique / tactic; *in incident* = its events are in a reported attack incident.
Tactic scores below use ATT&CK v18 tactics mapped back onto Defense Evasion (see `engine/attack/stix.py`).

## Synthetic (exact ground truth)

| Round | dev_s1 steps / paths / precision | clean false incidents | hold_de steps | vary paths | nosysmon steps / paths | hunt s (dev_s1) |
|---|---|---|---|---|---|---|
| baseline | 100% / 100% / 99% | 0 | 31% | 100% | 82% / 50% | 4 |
| phase2 (behaviour, noise guard, long-dwell links) | 100% / 100% / 99% | 0 | 75% | 100% | 85% / 75% | 5 |
| phase3 (+ SigmaHQ all levels, first version) | 100% / 50% / 89% | 0 (670 review) | 81% | 75% | 82% / 50% | 117 |
| phase3_high (+ SigmaHQ high/critical only) | 100% / 75% / 89% | 0 | 81% | 75% | 82% / 50% | 81 |
| phase3b (OS guard, low/medium = labels, shape batching) | 100% / 100% / 99% | 0 (16 review) | 81% | 100% | 85% / 75% | 36 |
| phase3c (+ Hayabusa) | 100% / 100% / 99% | 0 | 81% | 100% | 85% / 75% | 36 |

## Blind public corpora

| Round | EVTX detected / tactic | OTRF technique / tactic / in incident | Splunk technique / tactic / in incident | mix technique / tactic / in incident |
|---|---|---|---|---|
| baseline | 34% / 8% | 23% / 53% / 13% | 12% / 17% / 17% | — |
| phase2 | 60% / 15% | 35% / 66% / 43% | 14% / 22% / 18% | — |
| phase3 (SigmaHQ all) | 73% / 39% | 63% / 86% / 40% | 39% / 62% / 14% | — |
| phase3c | 73% / 39% | 63% / 86% / 47% | 39% / 55% / 9% | 70% / 83% / 23% |
| engine + Hayabusa (EVTX, single run) | **93% / 54%** | (running) | n/a (XML not read by Hayabusa) | |
| Hayabusa alone, all levels | 92% / 52% | 74% / 88% / — | n/a | |
| Hayabusa alone, medium+ | 81% / 46% | 69% / 87% / — | n/a | |

## Cost (Splunk corpus, 2.06 M events)

| Round | ingest | detection | correlation + reports |
|---|---|---|---|
| phase2 | 236 s | 24 s | 113 s |
| phase3 (SigmaHQ all, first version) | 252 s | 401 s | 1494 s |
| phase3b/c | ~250 s | 90 s | — |

## Findings

- Rules written next to our own scenarios score 100% on them and 8–23% on public recordings: the baseline was overfit.
- Name-free behaviour detectors + a noise guard lifted every blind number without hurting our scenarios.
- SigmaHQ roughly doubles blind technique labelling, but only after: refusing rules it can't run faithfully,
  applying the rule's OS, keeping low/medium hits as labels (not incident steps), baselining routine hits, and
  evaluating rules on distinct event shapes (4× faster, identical hits).
- Hayabusa (curated Sigma, native) beats our Sigma path on Windows event logs; integrated as an optional detector.
- ATT&CK v18 split Defense Evasion into Stealth / Defense Impairment; unmapped, it silently lowered tactic scores.
