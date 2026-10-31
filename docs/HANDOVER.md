# AttackStory — handover (2026-11-01)

Start here in a new session. Read with `README.md` (setup, pipeline by log family) and `bench/scoreboard.md`
(numbers per round, partly outdated — the table below is current).

## 1. Where the code is

- Repo: `D:\mitigata\attackstory`, GitHub `Klath123/mitigata`, branch `main`.
- **Pushed** up to `088e3a1` (merge of the teammate's `feature/frontend-and-improvements`: React UI + engine work).
- **Local only (not pushed yet):** `40932fe` quality accepts old ingest reports · `245c65d` speed (skip flow-ownership
  queries without process telemetry, Sigma compile cache, cheaper memory sampler) · `5164377` incident formation
  (critical-asset escalation, `same_endpoint` links, firewall role) · `cdbf587` prevalence noise + admin-from-internet
  severity. Push only when the user says so.
- Tests: `python -m pytest` → 44 pass (also under Python 3.11 on AWS).
- SigmaHQ rules are not in git: `python -m engine.hunt.fetch_sigma` (windows, linux, network, web, cloud, identity).

## 2. The three benchmark machines

| Box | Login | Role | Data |
|---|---|---|---|
| **GCP #1** (4 vCPU / 15 GB) | `ssh -i ~/.ssh/gcp-vm.pem pater@34.130.250.84` | synthetic scoreboard, tool tests | `/data/logs/bench/{synth,corpora,out,runs,tools}`; hackathon original `/data/logs/firex-10G.log.gz` |
| **AWS** (4 vCPU / 15 GB, Amazon Linux 2023, py3.11) | `ssh -i ~/.ssh/mitigata.pem ec2-user@13.207.5.250` | blind scoreboard | `~/bench/{corpora,synth,out,runs,tools}`; IP changes if the instance is stopped |
| **Big box** (8 vCPU / 30 GB) | `ssh -i ~/.ssh/gce-big.pem pater@34.85.120.251` | hackathon file (full size) | `/data/logs/bench/hackathon/firex/firex-10G.log.gz`, runs in `/data/logs/bench/runs/firex_{before,after}` |

Code is synced by `tar czf - ... | ssh ... tar xzf -` (no git on the boxes). Each box has `~/venv` (DuckDB 2.0).
Hayabusa: GCP `/data/logs/bench/tools/hayabusa/hayabusa-4.3.1-lin-x64-gnu`; AWS `~/bench/tools/hayabusa/hayabusa-4.3.1-lin-x64-musl`
(gnu build needs glibc 2.38). Zircolite in `~/zvenv` on GCP #1 (benchmarked, not integrated). Heavy runs go on the
boxes, not the laptop (user preference).

**Done:** GCP #1 synthetic check of `cdbf587` passed (`/data/logs/bench/out/phase6/summary.txt`, 2026-10-31 19:32Z).
**Done:** big box hackathon rerun with `cdbf587` (351 s, peak 6.02 GB, **5 incidents: 2 attack + 3 review**; the
earlier "44 review" was a misread, see section 5 item 6).
**Stopped 2026-11-01:** big box "before" baseline (old engine): never left correlation in 2 h 52 m and reached
9.07 GB RSS, over the 8 GB budget. The new engine does the same file in 351 s at a 6.0 GB peak.

## 3. How to measure

- Full scoreboard: `bash eval/bench.sh <tag> <bench_dir> ~/venv/bin/python [all|synth|blind]`, with
  `ATTACKSTORY_HAYABUSA=<binary>` to enable Hayabusa. `synth` = dev_s1, clean, hold_de, vary, nosysmon;
  `blind` = EVTX-ATTACK-SAMPLES (261), OTRF (97), Splunk attack_data (530), Splunk Linux (148), mix (30 OTRF in clean).
- Scoring: `eval/score.py` (synthetic, exact ground truth), `eval/blind.py` (public corpora), `eval/tool_score.py`
  (Hayabusa / Zircolite alerts). Generator: `generator/gen.py` (`--vary`, `--drop`), holdout D/E in `generator/holdout.py`
  (no longer blind — looked at while developing).
- **Gate for every change:** `clean` 0 false attack incidents, dev_s1 100%, then blind numbers.

## 4. Current numbers

| Set | Result |
|---|---|
| dev_s1 (ours) | 100% steps / paths, event recall 100%, precision 99%, 0 decoys (with `5164377`) |
| clean | 0 attack incidents / 16 review (with `cdbf587`) |
| holdout D/E | 81% steps, 75% labels, 50% paths, 0% false alarms (1 decoy included) |
| vary / nosysmon | 100% / 85% steps, 0 false alarms |
| EVTX blind | 93% any hit, 54% tactic right (with Hayabusa) |
| OTRF blind | 70% technique, 89% tactic, 42% in attack incident |
| Splunk blind | 41% technique, 56% tactic, **28% in attack incident** (was 9%; measured with a looser escalation — rerun with final code) |
| Splunk Linux blind | 7–10% technique — weakest area |
| mix (real attacks in our network) | 80–83% technique, 70% in attack-or-review |
| Hackathon file (9.17 M events) | correlation 53 s (was 2 h+), peak 6.0 GB (was 8.9), 2 attack incidents |

## 5. Hackathon file (FortiGate, from the organisers, no answer key)

`firex-10G.log.gz`: 9.1 M FortiGate key=value lines + ~6.7 M lines of binary/PDF junk (skipped) + 919 k duplicates.
`eventtime` equals local `date`/`time` read as UTC (5h30 inconsistency in the data; ordering unaffected).
Found so far:
1. **attack** — `tejas.roy`: admin access to the FortiGate from the internet (78.120.139.0) → disk logging disabled →
   firewall policy objects purged → logging re-enabled (T1078 → T1562), 23 Oct 16:31–20:36.
2. **attack** — `rakes`: admin logon from the internet + config change.
3. review — `keerat.ghughal`: SSL-VPN tunnels alternating Türkiye ↔ United States within minutes (shared/stolen creds).
4. foreign admin logins: `deepika.khan` (Russia, ×3), `parul.sinha` (Türkiye), `svc_backup30` (service account, Ireland)
   — after `cdbf587`: parul.sinha and deepika.khan are review incidents (0.51); svc_backup30 not in the top 15 (check).
5. 416 k failed admin logins (invalid user names, random IPs) — spray/noise, grouped.
6. "scan → upload" on endpoints = artefact (flows sharing the last timestamp). **Fixed by `cdbf587`** (both rules are
   `prevalent` + `noisy`, so weak links are blocked). The ~40 review incidents at 0.481 were **stale files** in
   `incidents/` from the 19:08 run: `results/store.write` never cleared the folder (now fixed, `tests/test_store.py`).
   The stale files were moved to `/data/logs/bench/runs/firex_after_stale/`. Lesson: count incidents from `incidents.json`.
Rules for these were written after seeing the file: not a blind measurement.

## 6. Next steps (agreed order)

1. ~~Endpoint scan→upload review flood~~: not a real problem, it was stale files (section 5 item 6). Baseline stopped.
2. Rerun the **blind** set on AWS with the final code (`bash ~/round6.sh $HOME/bench blind <hayabusa-musl>`) — honest
   before/after for incident formation; check the small drops (Linux 10→7%, mix technique 83→80%).
3. Write the **hackathon findings report** (timeline, evidence lines, what the logs cannot show) — as an Artifact.
4. Correlation, remaining: build links set-based in DuckDB (Python loops still dominate on huge hit sets); hub
   handling (relative fan-out instead of `MAX_FANOUT`); incident ranking / merging / campaigns.
5. Speed: Hayabusa `-m low` (informational alerts make the OTRF hunt ~5× slower) — a first attempt was rejected
   by the user mid-edit, re-propose.
6. Linux detection (weakest); fresh hidden scenarios F/G + one final blind score; update `bench/scoreboard.md`.
7. Optional: onboarding agent (auto-mapping new log formats from samples, validated in code, once per vendor —
   user liked the idea, do after correlation); (narrator + mapping suggestions now use Gemini `gemini-4-argon` via `GEMINI_API_KEY`; hackathon rerun with narration: put the key in `~/.gemini_key` on the big box, run `~/work/after/eval/narrate_firex.sh`); ChopChopGo / Wazuh for Linux.

## 7. Gotchas learned the hard way

- **Shell escaping:** backslashes in heredocs / `python -c` get mangled (`\b` became a backspace, `\x00` a NUL byte in a
  source file). Write scripts/tests to files with the Write/Edit tools; after patching, `grep -cP "[\x00-\x08]"` and
  check for NUL bytes with Python.
- **`pkill -f <pattern>`** over ssh matched the ssh command line itself and killed the session. Use
  `for p in $(pgrep -f "exact engine.run args"); do kill $p; done` with a pattern that can't match the shell.
- **Never edit a script that a running `bash` is executing** (bench.sh mid-run → broken summary).
- **Background waits:** a `until grep -q DONE log` can see the previous round's marker — remove the log first or check
  the summary timestamp.
- AWS is Python 3.11: no backslashes inside f-string expressions.
- Profiling with `python -m cProfile -m engine.run` slows the forked ingest workers badly: profile with `--skip-ingest`.
- Installing external code (git clone + pip, binary downloads) may be blocked by the permission checker → give the user a
  one-line `! ssh ...` command, or a script uploaded to the box that they run.
- Commits are GPG-signed; the passphrase prompt can time out (ask the user, never bypass signing).
- The GCP #1 key (`gcp-vm.pem`) was printed into a session by accident → **rotation pending** (user decision).
