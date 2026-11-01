# AttackStory

**Raw security logs in any format → ranked attack incidents, each with its kill chain, attack path, what the
attacker could reach next, and a plain-English report in which every sentence is tied to a log line.**

Built for Mitigata's *Kill Chain and Attack Path Analysis* challenge: no alerts are given, the engine hunts the raw
logs itself, links what belongs together, explains it, and checks its own work. 15 GB in under an hour with under
8 GB RAM, served over an API with an analyst UI.

| On the hackathon FortiGate file (6.1 GB, 9.17 M events) | |
|---|---|
| Time / peak memory | 294 s / 7.96 GB on 8 vCPU |
| Found | 2 attacks + 3 incidents for review, every step backed by a log line |
| Attack 1 | `tejas.roy` from 78.120.139.0 turns the firewall's logging **off** (16:31) → **purges the firewall policies** (18:28) → turns logging back **on** to hide the gap (20:36) |
| Attack 2 | `rakes` from 203.228.177.117 **creates admin `svc_backup30`** (03:55) → the new account **signs in from the internet** (04:02) → it is **deleted 12 minutes after creation** (04:07) |

---

## How it answers the PRD

**The problem** (PRD §1): security tools raise alerts one at a time, so "failed login", "new admin account" and
"big upload" look like three alerts instead of one attack; linking them by hand takes an expert hours; and nobody can
tell noise from step three of a break-in, with ATT&CK mapping done by hand, after the fact.

**Our answer:** AttackStory needs no alerts as input. It reads the raw logs in a streaming pass, hunts them with
~2,300 detections, labels every finding with a current MITRE ATT&CK technique and kill-chain stage, links findings
that share a host, account, IP, session or process into one incident, scores incidents so real attacks rise to the
top, and explains each one as a timeline, a path between machines, a "could reach next" list and a plain-English
report in which every sentence cites a log line. It then checks its own work.

### Goals (PRD §2)

| Goal | How AttackStory meets it |
|---|---|
| **Detect** | own SQL and sequence rules, rarity / first-seen rules, vendor verdicts, SigmaHQ (converted to DuckDB SQL), optional Hayabusa, history checks against the knowledge base; command lines are de-obfuscated first so disguised commands still match ([§3](#3-how-it-works)) |
| **Label** | every step carries a current ATT&CK technique and kill-chain stage from MITRE's own bundle; change events use one validated label table ([§5](#5-labels-you-can-trust-attck)) |
| **Connect** | evidence links between hits (process GUID, logon session, logon hop, account, internet address, indicators), each with a confidence; one incident per linked cluster, across hosts, users and time, and across batches ([§3](#3-how-it-works), [§4](#4-logs-that-keep-arriving-the-knowledge-base)) |
| **Explain** | story view (summary, attack path, what to do), timeline with replay, kill map, host graph, knowledge graph, report for a manager and an analyst ([§8](#8-the-analyst-ui)) |
| **Look ahead** | reachability over a privilege graph built from the logs: which hosts the accounts involved can reach next ([§3](#3-how-it-works)) |
| **Accurate** | 11 chain checks per incident, a citation checker on every report sentence, a verification agent, and scoring against ground truth ([§6](#6-checking-its-own-work), [§11](#11-evaluation-and-results)) |
| **Scales** | streaming ingest in bounded memory, parallel parsing, Parquet + DuckDB with a memory limit and spill to disk ([§11](#11-evaluation-and-results)) |

### Functional requirements (PRD §3)

| ID | Requirement | Where it is |
|---|---|---|
| **FR-1** | Read the full data set without loading it all into memory | `engine/ingest/` streams files in chunks with parallel workers into Parquet; bounded line reading (a 15 GB line without a newline is skipped in 1 MiB pieces); DuckDB queries with `--memory` and spill to disk. Measured: the 6.1 GB hackathon file at 7.96 GB peak; the 18.7 GB `firex-19g` file at 6 GB peak |
| **FR-2** | Detect suspicious events | `engine/hunt/` + `rules/`: e.g. `rules/sequences/` brute force (many failures then a success), admin access from the internet, logging disabled, policy purge, new admin account, exfiltration, beaconing |
| **FR-3** | Map each detection to an ATT&CK technique and kill-chain stage | every step has `technique`, `sub_technique`, `technique_name`, `stage`; current ids from MITRE's bundle, retired ids translated (`engine/attack/stix.py`), change events labelled from `rules/mappings/attack_labels.yaml` |
| **FR-4** | Link related events into one incident by host, user, IP and time | `engine/graph/build.py` (evidence links with confidence) + `engine/cluster/score.py` (steps, ordering); the svc_backup30 incident links an admin-account creation, the new account's internet login and its deletion into one attack |
| **FR-5** | Attack path as a timeline and a graph of hosts and users | UI: Story (attack path), Timeline (with replay), Graph (hosts, hops, steps), Kill map, Knowledge graph; API: `GET /incidents/{id}/path` |
| **FR-6** | What the attacker could reach next | `engine/lookahead/reach.py`: reach over a privilege graph (sessions, admin rights, exposed credentials); UI tab "Reach next"; API `GET /incidents/{id}/lookahead` |
| **FR-7** | Simple API or page, with a README | FastAPI (`engine/api/`, docs at `/docs`) + React UI; `GET /incidents/12/path` works as in the PRD; this README |

### Bonus (PRD §3)

| ID | Bonus | Status |
|---|---|---|
| **B-1** | Risk score per incident, worst on top | done: `S = 0.35·tactics + 0.20·order + 0.15·hosts + 0.20·severity + 0.10·rarity`, attack ≥ 0.7, review 0.4-0.7; incidents sorted by risk; the score table is in the UI |
| **B-2** | Auto-written report in plain English | done: template report always, LLM report when a key is set; every sentence checked against its cited log lines; `GET /incidents/{id}/report?format=md` |
| **B-3** | How many raw alerts were merged into each incident | done: `alerts_merged` and `hits_merged` per incident, shown on every incident card |
| **B-4** | New detection rule by editing a config file | done: a YAML file in `rules/detections/` or `rules/sequences/`, a Sigma `.yml` in `rules/sigma/`, a label entry in `rules/mappings/attack_labels.yaml`; no code |
| **B-5** | Live mode: new log lines update the attack path | near-live: `python -m engine.kb watch` processes each new file or folder as a batch and grows existing incidents in place (a 250 k-line batch takes about a minute end to end); the UI's **Upload logs** button analyses files sent from the browser. Not per-line seconds-level streaming |

### Targets (PRD §4)

| What is measured | Good | Great | AttackStory |
|---|---|---|---|
| Detection (planted steps found) | > 70% | > 90% | 100% on the synthetic dev set; 81% on hidden scenarios D/E |
| Correct labels | > 60% | > 85% | 75% on hidden scenarios D/E (dev set 100%) |
| Attack path (right steps, right order) | half | all | all on the dev set; 50% on hidden scenarios D/E |
| False alarms | < 30% | < 10% | 0 attack incidents on the clean set; 0% on D/E |
| Processing time (full tier) | < 3 h | < 1 h | 6.1 GB in 294 s; 18.7 GB file in 11.5 min (8 vCPU) |
| Peak memory | < 16 GB | < 8 GB | 7.96 GB (6.1 GB file), 6.0 GB (18.7 GB file) |
| Investigation speed (open one attack path) | < 2 s | < 500 ms | 3-5 ms per API call (precomputed results) |
| Runs easily | README | Docker Compose a plus | `pip install` + two commands, or `docker compose up --build` ([§1](#1-quick-start)) |

The synthetic dev set and hidden scenarios are generated by `generator/` with exact ground truth and scored by
`eval/score.py`; the public blind corpora are in [§11](#11-evaluation-and-results).

---

## Contents

1. [Quick start](#1-quick-start)
2. [What it does](#2-what-it-does)
3. [How it works](#3-how-it-works)
4. [Logs that keep arriving: the knowledge base](#4-logs-that-keep-arriving-the-knowledge-base)
5. [Labels you can trust: ATT&CK](#5-labels-you-can-trust-attck)
6. [Checking its own work](#6-checking-its-own-work)
7. [LLM agents](#7-llm-agents)
8. [The analyst UI](#8-the-analyst-ui)
9. [API](#9-api)
10. [Configuration](#10-configuration)
11. [Evaluation and results](#11-evaluation-and-results)
12. [Repository layout](#12-repository-layout)
13. [Limits and honest notes](#13-limits-and-honest-notes)

---

## 1. Quick start

Python 3.11+ (tested 3.11-3.14) on Windows, Linux or macOS. Node 18+ only if you rebuild the UI.

```bash
git clone https://github.com/Klath123/mitigata.git && cd mitigata
python -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# reference data (both git-ignored, both optional but recommended)
python -m engine.hunt.fetch_sigma      # SigmaHQ community rules
curl -L --create-dirs -o rules/attack/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json   # MITRE ATT&CK, ~49 MB

# the UI (once)
cd frontend && npm ci && npm run build && cd ..
```

**Run it on logs** (a folder; files are recognised by content: gz / zip / EVTX / UTF-16 included):

```bash
python -m engine.run /path/to/logs --out results/mylogs            # add --no-llm to skip the LLM agents
python -m engine.api results/mylogs                                 # open http://localhost:8000
```

**Try it without data of your own:** generate a synthetic company with planted attacks and exact ground truth.

```bash
python -m generator.gen --out data/s1 --size 100MB --seed 1 --days 3
python -m engine.run data/s1 --out results/s1 --serve              # runs, then serves the UI
python -m eval.score data/s1 results/s1                            # score against the ground truth
```

**Logs that arrive in batches** (e.g. 20 GB every hour):

```bash
python -m engine.kb watch /data/inbox --runs results --kb results/kb   # each new file or folder = one batch
```

**Send logs from the browser:** the **⇪ Upload logs** button in the UI (or `POST /jobs` in the API) uploads files,
runs the engine on them in the background, shows its progress and opens the result as a new run.

**With Docker** (no Python or Node on the host):

```bash
docker compose up --build                       # UI + API on http://localhost:8000
docker compose run --rm attackstory python -m engine.run /logs --out results/mylogs   # analyse ./logs
```

**Tests:** `pytest` (72 tests).

The submission archive also contains a prebuilt UI (`frontend/dist`) and two finished runs (`results/firex`,
`results/kbtest-kb`): `python -m engine.api` shows them straight away, with no run and no Node.

---

## 2. What it does

- **Any log format in, one schema out.** JSON, CSV, syslog, CEF/LEEF, key=value (FortiGate), auditd, Apache, W3C,
  Zeek, EVTX, XML; unknown formats get mined templates and meaning-based typing. A config agent proposes mappings
  for new formats.
- **Hunts without alerts.** About 2,300 detections: our own SQL rules, sequence rules, rarity / first-seen rules,
  vendor verdicts, the SigmaHQ community rules (converted to DuckDB SQL), optional Hayabusa for Windows logs, and a
  history check against the knowledge base.
- **Hard to evade.** Command lines are de-obfuscated and decoded before matching (carets, split quotes, backticks,
  string concatenation, Unicode dashes, `%COMSPEC%`, `-enc` base64), so public rules still fire on disguised commands.
- **Links what belongs together.** Hits are joined by process GUIDs, logon sessions, logon hops, shared accounts,
  internet addresses and indicators, each link with a confidence; clusters are scored and only multi-stage chains
  become attacks.
- **Tells the story.** Ordered kill-chain steps, the attack path between machines, logging gaps, blast radius,
  "could reach next" over a privilege graph, and a report written for a manager and an analyst at once.
- **Checks itself.** Every report sentence is verified against the log lines it cites; every incident runs 11 chain
  checks; a verification agent gives a second opinion that code checks in turn.
- **Remembers.** Hourly batches feed a knowledge base: an attack split across batches is one incident that grows,
  entities keep their history, and a knowledge graph shows how everything connects.

---

## 3. How it works

```
 raw logs ─► [1] ingest ─► Parquet ─► [2] DuckDB + entities ─► data quality
                                                 │
            ┌────────────────────────────────────┘
            ▼
 [3] hunt: own rules · sequences · rarity · vendor verdicts · SigmaHQ · Hayabusa · history  ─► hits
            │
            ▼
 [4] correlate (evidence links, noisy-OR) ─► score ─► steps · path · gaps · look-ahead · blast radius
            │
            ▼
 [5] narrate (template + LLM) ─► citation check ─► verification agent ─► 11 chain checks
            │
            ▼
 [6] results/<run>: incidents, evidence index, knowledge graph (+ Neo4j / GraphML) ─► API + UI
            │
            └─► knowledge base (batches over time): carry hits forward, grow incidents, entity memory
```

| Stage | Code | What happens |
|---|---|---|
| Ingest | `engine/ingest/` | find files by content, sniff the format, parse, map fields (`rules/mappings/fields.yaml`), clean command lines, write Parquet in parallel; over-long or binary lines are skipped in bounded memory |
| Store, entities | `engine/store/`, `engine/entities/`, `engine/lookahead/privmap.py` | DuckDB over Parquet; IP → host over time; host roles; privilege map from the logs |
| Data quality | `engine/quality.py` | parsed / duplicate / late / unknown-type records, missing telemetry, warnings shown in the UI |
| Hunt | `engine/hunt/`, `rules/` | every detector pack runs only on the log families it understands; packs with nothing to read are reported, never silently empty |
| Correlate, score | `engine/graph/`, `engine/cluster/` | link hits, cluster, score `S = 0.35·tactics + 0.20·order + 0.15·hosts + 0.20·severity + 0.10·rarity`; ≥ 0.7 attack, 0.4-0.7 review; one event alone is never an attack |
| Look-ahead | `engine/lookahead/reach.py` | which hosts the attacker could reach with the accounts involved |
| Narrate | `engine/narrate/` | template report always; LLM report when a key is set; `checker.py` keeps only sentences whose hosts, accounts, IPs, times and techniques match the cited lines; `guard.py` flags prompt-injection text in logs |
| Checks | `engine/validate.py`, `engine/verify_agent.py` | see [section 6](#6-checking-its-own-work) |
| Results | `engine/results/`, `engine/graph/export.py` | precomputed JSON, evidence index, run manifest (inputs hashed, engine version, config), knowledge graph |
| Knowledge base | `engine/kb.py` | see [section 4](#4-logs-that-keep-arriving-the-knowledge-base) |

Every claim carries an evidence id `src_file:line`; `GET /events/{id}` returns the original record.

**Detector packs by log family**

| Log family | Packs |
|---|---|
| Windows (EVTX, JSON, XML) | Hayabusa (optional) + SigmaHQ windows + behaviour (process, logon, Kerberos) + sequences + own rules |
| Linux (auditd, auth, syslog, Sysmon for Linux) | SigmaHQ linux + own Linux rules + SSH brute-force sequences |
| Firewall / network (FortiGate, CEF, Zeek, flows, DNS) | SigmaHQ network + `firewall.yaml` (config changes labelled from the ATT&CK table, admin access from the internet, country jumps, vendor IPS / AV / web verdicts, scans) + behaviour (beaconing, DNS tunnelling, exfiltration) |
| Web servers / proxies | SigmaHQ web + web-shell / upload rules |
| Unknown formats | templates, meaning-based typing, behaviour rules on recognised fields |

---

## 4. Logs that keep arriving: the knowledge base

A single run sees one batch. Real logs arrive continuously, and an attack can start in one hour and finish in the
next. `engine/kb.py` is the memory across runs (one DuckDB file, no server):

1. **Carry in.** Before correlating a batch, detection hits of the last 24 h and every hit of a still-open incident
   join it, so the same correlator links an attack split across batches.
2. **Absorb.** The batch's hits (a bounded sample per hit, with the raw line), entities (first / last seen, batches)
   and successful internet sign-ins go into the knowledge base; old hits no open incident needs are pruned.
3. **Merge.** The batch's incidents merge into knowledge-base incidents by shared evidence: an incident that grows
   keeps its id; one that bridges two absorbs the newer. Quiet for 7 days → closed.
4. **View.** The knowledge base is written as a run folder, so the UI shows it like any run, plus its own page.

Details that matter: evidence of earlier batches is addressed `kb:<batch>/<file>:<line>` (no collisions); later
batches do not treat their first hours as "normal" (that would hide an attack that continues); "first time" rules do
not fire twice across batches; unchanged incidents reuse their LLM report.

**History detection:** a known account signing in from an internet address it has never used before. It needs no
warm-up and no public rule an attacker could study.

**Tested on real data** (`eval/kb_split_test.sh`): the first million lines of the hackathon file, cut into two batches
in the middle of attack 1. Batch 1 alone gives one *review* item; batch 2 updates the same incident in place,
promotes it to *attack*, and its three steps equal the full-file result.

```bash
python -m engine.kb watch <inbox> --runs results --kb results/kb [--every 60] [--quiet 120] [--once]
python -m engine.run <batch> --out results/<batch> --kb results/kb      # one batch by hand
python -m engine.kb view results/kb                                     # rebuild the UI view
```

---

## 5. Labels you can trust: ATT&CK

- **Current ATT&CK, not a frozen copy.** With MITRE's bundle installed, every name and tactic comes from it.
  ATT&CK v18 retired the *Impair Defenses* family (T1562.x) and T1070.001/.002; every hit from every source (own
  rules, SigmaHQ, Hayabusa, the knowledge base) is translated to the current id from MITRE's own *revoked-by* links,
  in one place (`engine/attack/stix.py`).
- **One label table for change events** (`rules/mappings/attack_labels.yaml`). Twenty kinds of change (logging off /
  back on, logs cleared, firewall rules removed or changed, management access opened, MFA removed, authentication
  changed, account created / deleted / privileges changed, SSH key added, VPN changed, config exported, firmware
  changed, automation added) each map to one technique, by platform: a firewall rule removed is T1686.002 on a
  network device, T1686.003 on Windows, T1686.001 in the cloud. Context decides one case: an account deleted soon
  after it was created is a backdoor removed (Indicator Removal), otherwise an owner locked out (Account Access Removal).
- **Tested against MITRE's data:** every technique in the table must exist, must not be retired and must belong to
  the stage given; every example in real vendor wording must get its label; the SQL and Python labellers must agree.
- **One log line, one step.** If a line proves two things (the first change from a new address is the access and the
  tampering), it is one step with two labels; nothing is counted twice.

---

## 6. Checking its own work

| Layer | What it checks |
|---|---|
| Citation checker (`engine/narrate/checker.py`) | each report sentence cites log lines that exist and name the same hosts, accounts, IPs, times (±1 min) and techniques; failing sentences are deleted; an LLM answer losing over 20% is rejected |
| Chain checks (`engine/validate.py`, 11 per incident) | evidence exists · evidence matches the step · time order · kill-chain order · technique fits the stage · steps linked by evidence · every step has its own lines · verdict rules (an attack needs ≥ 2 steps over ≥ 2 stages) · report grounded · labels match the label table · verification agent |
| Verification agent (`engine/verify_agent.py`) | an LLM second opinion: right labels? one attack or unrelated activity? false positive? safe actions? Code drops points that cite lines outside the incident, name steps that do not exist, or push retired ATT&CK ids |
| Safe actions | firewalls / VPN gateways are listed under "protect (do not isolate)", never "isolate" |

Run the checks on any finished run: `python -m engine.validate results/<run>`.

---

## 7. LLM agents

Everything works without an LLM (template reports, no agent reviews). With a key, three agents run, all checked by code:

| Agent | Job | Code that checks it |
|---|---|---|
| Narrator | report for a manager and an analyst: summary, why it is suspicious, timeline, how they got in, impact, what to do, what we do not know | citation checker |
| Verification agent | second opinion per incident | `verify_agent.check` + chain check |
| Config agent | field mappings / event rules for unknown formats; a second call confirms or rejects each | dry run on the sample; `--auto-apply` writes only verified, confident ones to `rules/mappings/auto.yaml` |

**Providers, first that answers wins:** Groq `openai/gpt-oss-120b` → `openai/gpt-oss-20b` (set `GROQ_API_KEY`), then
Gemini `gemini-3.5-flash` → `gemini-2.5-flash` (set `GEMINI_API_KEY`). Overload, rate limits and timeouts move on to the
next model, and finally to the template report: a run never stalls on the LLM. Log text is passed as a JSON data
block and treated as untrusted (prompt-injection attempts in logs are reported as attacker behaviour).

Rewrite the reports of a finished run in seconds (new prompt or model): `python -m engine.narrate results/<run>`;
re-review: `python -m engine.verify_agent results/<run>`.

---

## 8. The analyst UI

React + Cytoscape.js in `frontend/`, served by the API at `http://localhost:8000` once built.

- **Briefing:** attacks ranked by risk, the knowledge graph, how the hunt ran (stage timings, funnel, data quality,
  score table, rules that fired); for a knowledge base: batches, incidents across batches, entity explorer.
- **Incident:** the story (summary, attack path, what to do now, verification agent), kill map (tactics × hosts),
  timeline with replay, evidence graph, reach-next graph, ATT&CK matrix, evidence and excluded look-alikes, response
  checklist, and the narrative panel whose citations open the raw log lines.
- **Run picker** switches between runs and knowledge bases under `results/`. Deep links: `#i=<incident>&t=<tab>`.

Development: `cd frontend && npm run dev` (port 5173, proxies the API on 8000).

---

## 9. API

FastAPI, read-only over precomputed results (`python -m engine.api [run] [--port 8000]`). Interactive docs at `/docs`.

| Endpoint | Returns |
|---|---|
| `GET /incidents?include_review=true` | ranked incidents |
| `GET /incidents/{id}` | full incident: steps, path, hops, gaps, graph, look-ahead, blast radius, report, checks, agent review |
| `GET /incidents/{id}/report?format=json\|md\|text` | the report |
| `GET /incidents/{id}/path`, `/lookahead`, `/navigator` | attack path; reach-next; ATT&CK Navigator layer |
| `GET /events/{evidence_id}` | the original log record behind a citation |
| `GET /graph` | the run's knowledge graph (nodes + edges) |
| `GET /kb/entities?q=&kind=&only=` | knowledge-base entity memory |
| `GET /stats`, `/quality`, `/health`, `/runs`; `POST /reload?run=` | run statistics, data quality, health, run list / switch |
| `POST /jobs` → `PUT /jobs/{job}/files?name=` (raw file body) → `POST /jobs/{job}/run` → `GET /jobs/{job}` | send log files and analyse them in the background; the result appears as run `{job}` (one analysis at a time; `ATTACKSTORY_UPLOADS=0` disables, `ATTACKSTORY_UPLOAD_MAX_GB` caps a job, default 20) |

---

## 10. Configuration

Copy `.env.example` and export what you need (`set -a; source .env; set +a` on Linux/macOS).

| Variable | Default | Meaning |
|---|---|---|
| `GROQ_API_KEY` / `GEMINI_API_KEY` | unset | enable the LLM agents (Groq first) |
| `ATTACKSTORY_LLM` | `1` | `0` disables every LLM call |
| `ATTACKSTORY_LLM_MODEL` | provider defaults | comma-separated models to try in order |
| `ATTACKSTORY_LLM_THINKING` | `high` | Gemini thinking level |
| `ATTACKSTORY_GROQ_MAX_TOKENS` | `3500` | Groq answer budget (counts against tokens per minute) |
| `ATTACKSTORY_HAYABUSA` | unset | path to a Hayabusa binary for Windows logs |
| `ATTACKSTORY_RESULTS` / `ATTACKSTORY_RUN` | `results/` / newest | where the API looks / which run it opens |
| `ATTACK_STIX` | `rules/attack/enterprise-attack.json` | alternative ATT&CK bundle |
| `ATTACKSTORY_UPLOADS` / `ATTACKSTORY_UPLOAD_MAX_GB` | `1` / `20` | allow log uploads through the API / size cap per upload job |

`engine.run` options: `--workers N`, `--memory 6GB` (DuckDB limit), `--no-llm`, `--skip-ingest` (reuse Parquet),
`--kb DIR`, `--auto-apply`, `--hash-full`, `--serve [PORT]`.

New vendor = entries in `rules/mappings/fields.yaml`; new detection = a YAML file in `rules/detections/` (SQL over
the `events` view) or `rules/sequences/`; new change label = an entry with examples in `rules/mappings/attack_labels.yaml`.

---

## 11. Evaluation and results

- `generator/`: a synthetic company with planted attack scenarios and exact ground truth; `eval/score.py` scores steps,
  labels, paths, event recall / precision and decoys (in current ATT&CK ids).
- `eval/blind.py`: public corpora (EVTX-ATTACK-SAMPLES, OTRF, Splunk attack_data) the rules were not written against;
  `eval/bench.sh` runs the whole scoreboard (`bench/scoreboard.md`).

| Set | Result |
|---|---|
| Synthetic dev set | 100% steps and paths, event recall 100%, precision 99%, 0 decoys |
| Synthetic clean set (no attacks) | 0 attack incidents |
| Hidden scenarios D/E | 81% steps, 75% labels, 50% paths, 0 false alarms |
| EVTX / OTRF / Splunk blind | 93% any hit / 70% technique / 41% technique |
| Hackathon firex-10G | 294 s, 7.96 GB peak, 2 attacks + 3 review; attack 1 passes all 11 chain checks |
| Hackathon firex-19g | 11.5 min, 6 GB peak, 0 incidents: the file is malformed (every line has the same timestamp; a 14.6 GB block of NUL bytes from the 4 GiB mark; it starts mid-line). The engine reads it in bounded memory and reports the problems instead of inventing a chain |

---

## 12. Repository layout

```
engine/            the engine
  ingest/            discovery, format sniffing, parsers, field mapping, command-line cleaner, config agent
  store/ entities/   DuckDB, IP → host, host roles
  hunt/              rule runner, Sigma converter, Hayabusa, ATT&CK label table loader
  graph/ cluster/    evidence links, scoring, steps, paths, gaps, knowledge-graph export
  lookahead/         privilege map and reach-next
  narrate/           template + LLM narrator, citation checker, prompt-injection guard
  attack/            ATT&CK names, tactics, retired-id translation, Navigator layers
  results/ api/      result files, FastAPI
  kb.py              knowledge base (batches over time)
  validate.py        chain checks
  verify_agent.py    verification agent
  run.py             the pipeline
rules/             detections, sequences, Sigma, macros, field mappings, ATT&CK label table
frontend/          React UI (prebuilt in the submission archive: frontend/dist)
generator/ eval/   synthetic data with ground truth; scoring and benchmark scripts
tests/             69 tests
bench/ docs/       scoreboard; team handover
```

Not in git (regenerate or keep local): `data/`, `results/`, Parquet / DuckDB files, `rules/sigma/sigmahq/`,
`rules/attack/enterprise-attack.json`, `frontend/dist`, `.env`, keys, `docs/*.local.md`.

---

## 13. Limits and honest notes

- The hackathon file came without an answer key; its rules were written after seeing it, so it is not a blind
  measurement. The blind corpora are (section 11).
- Linux detection is the weakest area on the blind sets.
- Peak memory on the 10G file is 7.96 GB, at the 8 GB budget; it needs trimming before larger single files.
- LLM quality depends on the provider: gpt-oss and Gemini models trained before ATT&CK v18 may question current ids
  (the agent is told the release in use and code drops retired-id advice). On Groq's on-demand tier
  (8,000 tokens / minute), process batches one after another.
- Third-party content: SigmaHQ rules (Detection Rule License 1.1) and MITRE ATT&CK (MITRE terms of use) are
  downloaded, not redistributed in git.
