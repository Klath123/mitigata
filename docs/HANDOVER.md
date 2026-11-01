# AttackStory: team handover (updated 2026-11-01)

Start here in a new session, together with `README.md` (what it is, how to run it) and `bench/scoreboard.md`
(numbers per round, partly outdated; section 4 below is current). Server logins and keys are in
`docs/INFRA.local.md`, which is git-ignored on purpose: never commit them.

## 1. Where the code is

- Repo `Klath123/mitigata`, branch `main`. Commits are GPG-signed (the passphrase prompt can time out: ask, never
  bypass signing). Push only when the team agrees.
- Tests: `python -m pytest` → 69 pass (Python 3.11-3.14).
- Not in git: SigmaHQ rules (`python -m engine.hunt.fetch_sigma`), the MITRE ATT&CK bundle
  (`rules/attack/enterprise-attack.json`, see README), datasets, run outputs, the built UI.

## 2. What changed on 2026-11-01

| Area | Change |
|---|---|
| Ingest | bounded line reading: a 15 GB newline-free stretch (firex-19g) is skipped in 1 MiB pieces instead of loaded (was a 30 GB OOM) |
| Detection | command-line cleaner (`engine/ingest/clean.py`): caret / quote / backtick / concatenation / Unicode-dash / env-alias tricks undone, `-enc` and `FromBase64String` decoded; every Sigma rule matches the original OR the cleaned text |
| Labels | full MITRE ATT&CK bundle; retired ids (T1562.x, T1070.001...) translated to current ones (T1685, T1686.x) in one place for every source; one label table for change events (`rules/mappings/attack_labels.yaml`, 20 change kinds, platform-aware, validated against the bundle by tests); chain check `label_matches_evidence` |
| Steps | one log line is one step (merged labels carried in `also`); a broad step gives up lines a specific step owns; a single event is never an attack on its own |
| Knowledge base | `engine/kb.py`: hourly batches carry hits of the last 24 h plus every open incident, incidents grow in place, entity first/last seen, sign-in history, `first_only` rules, `python -m engine.kb watch`; continuing batches skip the per-batch warm-up |
| History detection | known account signing in from an internet address it never used (knowledge base, no public rule to evade) |
| Agents | verification agent (`engine/verify_agent.py`, second opinion per incident, code-checked, shown as a chain check); config agent (`engine/ingest/suggest.py`: proposals verified by code + agent, `--auto-apply`) |
| LLM | Groq `openai/gpt-oss-120b` → `gpt-oss-20b` → Gemini, first that answers; JSON mode + our own checks; rate-limit wait |
| Narration | plain-English prompt with summary / why suspicious / timeline / impact / actions / unknowns; firewalls are protected, never isolated |
| UI | knowledge-base page (batches, incidents across batches, entity explorer), knowledge graph (`/graph`), verification agent card, full narrative sentences, corrected pipeline details |

## 3. How to measure

- Full scoreboard: `bash eval/bench.sh <tag> <bench_dir> ~/venv/bin/python [all|synth|blind]` (Hayabusa via
  `ATTACKSTORY_HAYABUSA=<binary>`). `synth` = dev_s1, clean, hold_de, vary, nosysmon; `blind` = EVTX-ATTACK-SAMPLES,
  OTRF, Splunk attack_data, Splunk Linux, mix.
- Scoring: `eval/score.py` (synthetic, exact ground truth; compares in current ATT&CK ids), `eval/blind.py`,
  `eval/tool_score.py`. Gate for every change: `clean` 0 false attack incidents, dev_s1 100%, then blind numbers.
- Knowledge base on real data: `bash eval/kb_split_test.sh` (first 1 M lines of the hackathon file in two batches,
  cut inside incident 1).

## 4. Current numbers

| Set | Result |
|---|---|
| dev_s1 (ours) | 100% steps / paths, event recall 100%, precision 99%, 0 decoys |
| clean | 0 attack incidents |
| holdout D/E | 81% steps, 75% labels, 50% paths, 0% false alarms |
| EVTX / OTRF / Splunk blind | 93% any hit / 70% technique / 41% technique (rerun pending with final code) |
| Hackathon firex-10G (9.17 M events, 6.1 GB) | 294 s, peak 7.96 GB, 2 attacks + 3 review; incident 1 passes all 11 chain checks |
| Hackathon firex-19g | 11.5 min, peak 6 GB, 0 incidents: the file is broken (every line has the same timestamp; 14.6 GB NUL tail at 4 GiB) |
| Two-batch knowledge-base test | batch 1: 1 review → batch 2: same incident updated in place, promoted to attack, 3 steps = full-file result |

## 5. Hackathon findings (FortiGate, no answer key)

1. **attack**: `tejas.roy` from 78.120.139.0 on the FortiGate: logging off 16:31 (T1685, + first access T1078) →
   firewall policies purged 18:28 (T1686.002) → logging back on 20:36 (T1070), 23 Oct.
2. **attack**: `rakes` from 203.228.177.117 creates admin `svc_backup30` 03:55 (T1136.001) → it signs in 04:02
   (T1078.003) → deleted 04:07 (T1070, backdoor removed), 29 Oct.
3. review: `keerat.ghughal` SSL-VPN alternating Türkiye ↔ United States; review: foreign admin logins
   (`deepika.khan` Russia, `parul.sinha` Türkiye).
4. 1.1 M failed admin logins (spray/noise, grouped). Rules for these were written after seeing the file: not blind.
5. firex-19g should be reported to the organisers as broken (fixed timestamp, NUL tail, file starts mid-line).

## 6. Next steps

1. Recall checks: independent SQL hunts for attacks the engine missed.
2. Behaviour baselines per account from the knowledge base (hours, countries, admin actions).
3. A systemd service around `engine.kb watch` with alerts on new / grown incidents.
4. Decoy accounts and keys; logging-tamper alerts beyond the firewall.
5. Peak memory on the 10G file is 7.96 GB: trim before the 15 GB scale run.
6. Rerun the blind set with the final code; Linux detection is still the weakest area.

## 7. Gotchas learned the hard way

- Shell escaping: backslashes in heredocs / `python -c` get mangled. Write scripts to files and run them.
- `pkill -f <pattern>` over ssh can match the ssh command line itself and kill the session; use a pattern that
  cannot match the shell (e.g. `python -m [e]ngine`).
- Never edit a script that a running `bash` is executing.
- Background waits can see the previous round's marker: remove the log first.
- AWS is Python 3.11: no backslashes inside f-string expressions.
- Profile with `--skip-ingest` (cProfile slows the forked ingest workers).
- LLM providers: Gemini Flash models returned 503 "high demand" for long stretches; Groq's on-demand tier allows
  8,000 tokens per minute (run batches one after another). The engine falls back to the next model and finally to
  the template report, so a run never stalls on the LLM.
