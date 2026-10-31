# AttackStory

Raw security logs in any format → ranked attack incidents with kill chain, attack path, look-ahead
("what can the attacker reach next") and an evidence-cited report. Built for Mitigata's *Kill Chain and
Attack Path Analysis* PRD: 15 GB in under 1 h with under 8 GB RAM, served over an API.

## Quick start

Python 3.11+ (tested on 3.13 and 3.14), Windows / Linux / macOS.

```bash
git clone https://github.com/Klath123/mitigata.git
cd mitigata                       # repo root = this folder
python -m venv .venv
# Windows: .venv\Scripts\activate      Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt

# 1. make a dataset with planted attacks + exact ground truth (datasets are NOT in git)
python -m generator.gen --out data/s1 --size 100MB --seed 1 --days 3
python -m generator.gen --out data/clean --size 100MB --seed 7 --days 3 --clean   # no attacks: false-positive check

# 2. run the engine (add --no-llm to skip the optional Claude narrator)
python -m engine.run data/s1 --out results/s1 --no-llm

# 3. score it against ground truth
python -m eval.score data/s1 results/s1

# 4. browse it: http://localhost:8000
#    Windows PowerShell: $env:ATTACKSTORY_RUN="results/s1"; uvicorn engine.api.app:app --port 8000
ATTACKSTORY_RUN=results/s1 uvicorn engine.api.app:app --port 8000

# tests
pytest
```

Re-run detection/correlation without re-parsing: `python -m engine.run data/s1 --out results/s1 --skip-ingest --no-llm`.
Your own logs: point `engine.run` at any folder; files are recognised by content (gz/zip/EVTX/UTF-16 included).

## Pipeline

```
raw logs → [1] ingest → Parquet → [2] DuckDB + entities → data quality → [3] hunt (rules → hits)
        → [4] correlate · score · trace · look-ahead · narrate · check → [5] results/ → API + UI
```

| Stage | Code | What it does |
|---|---|---|
| Ingest | `engine/ingest/` | discover by content, sniff format, parse (JSON, CSV, syslog, CEF/LEEF, auditd, Apache, W3C, Zeek, EVTX, XML, unknown → Drain3 templates), map to one event schema (`engine/schema.py`), parallel → Parquet |
| Store & entities | `engine/store/`, `engine/entities/`, `engine/lookahead/privmap.py` | DuckDB view over Parquet; IP→host over time; host roles; privilege map from logs |
| Data quality | `engine/quality.py` | parse/duplicate/late/unknown-type stats and warnings |
| Hunt | `engine/hunt/`, `rules/` | YAML/SQL rules, sequence DSL, rarity rules, vendor alerts, Sigma → DuckDB SQL → `hits` table |
| Correlate | `engine/graph/`, `engine/cluster/` | hits linked by GUIDs, sessions, logon hops, IOCs (noisy-OR confidence); clusters scored; steps, hops, path, gaps, tracer context |
| Look-ahead | `engine/lookahead/reach.py` | reachability on the privilege graph |
| Narrate | `engine/narrate/` | template report always; optional Claude report; `checker.py` verifies every claim against cited evidence; `guard.py` flags prompt injection in logs |
| Results / API | `engine/results/`, `engine/api/app.py`, `ui/index.html` | precomputed JSON + run manifest; FastAPI serves it read-only |
| Eval | `generator/`, `eval/score.py` | synthetic company + planted scenarios (prd, A, B, C) with ground truth; PRD metrics |

Every claim is tied to an evidence id `src_file:line`, which `/events/{id}` resolves to the original record.

## Rules

- `rules/detections/*.yaml` — SQL over the `events` view; header `id, title, technique, sub_technique, tactic, severity, kind`.
  Optional output columns: `hit_key` (group rows into one hit), `hit_severity`, `hit_host`, `hit_user`, per-row `technique`.
- `rules/sequences/*.yaml` — burst DSL (`first`, `by`, `min_count`, `gap`, `then`, `within`, `emit`) compiled to window SQL.
- `rules/sigma/*.yml` — Sigma rules, converted by `engine/hunt/sigma.py`.
- `rules/macros.sql` — SQL helpers (`bn`, `is_proc`, `is_external`, `host_of`, `role_of`, ...).
- `rules/mappings/fields.yaml` — source field names → normalized columns.
- `stats.json → rules` in each run shows hits, seconds and errors per rule.

## Optional extras

- **MITRE ATT&CK names/tactics:** download `enterprise-attack.json` from https://github.com/mitre/cti
  (`enterprise-attack/enterprise-attack.json`) to `rules/attack/enterprise-attack.json` (git-ignored); otherwise a built-in table is used.
- **LLM narrator / mapping suggestions:** set `ANTHROPIC_API_KEY` (model via `ATTACKSTORY_LLM_MODEL`); `ATTACKSTORY_LLM=0` disables it.
- **Fast EVTX:** `evtx_dump` on `PATH` is used if present; otherwise pure-Python `python-evtx`.

## Not in git (regenerate or keep local)

`data/`, `results/`, `*.parquet`, `*.duckdb`, `spill/`, `.env`, keys (`*.pem`, `*.key`), `rules/attack/enterprise-attack.json`.
