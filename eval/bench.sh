#!/bin/bash
# Full scoreboard on the benchmark box: synthetic dev/holdout/variation sets + three public corpora.
#   bash eval/bench.sh <tag> [bench_dir=/data/logs/bench] [python=~/venv/bin/python] [sets=all|synth|blind]
# Split across two boxes: one runs `synth`, the other `blind`; summary.txt lists whatever ran.
# Writes <bench_dir>/out/<tag>/{<set>.txt,<set>.json,<set>.stats.json} and a one-page summary.txt.
set -u
TAG=$1; B=${2:-/data/logs/bench}; PY=${3:-$HOME/venv/bin/python}; SETS=${4:-all}
REPO=$(cd "$(dirname "$0")/.." && pwd); OUT=$B/out/$TAG; SY=$B/synth; RUNS=$B/runs/$TAG
mkdir -p "$OUT" "$SY" "$RUNS"; cd "$REPO"

if [ "$SETS" != blind ]; then
gen() {  # name args...
  local n=$1; shift
  [ -f "$SY/$n/ground_truth.json" ] || $PY -m generator.gen --out "$SY/$n" "$@" > "$OUT/gen_$n.log" 2>&1
}
gen dev_s1   --size 100MB --seed 1 --days 3 --scenarios prd,A,B,C
gen clean    --size 100MB --seed 7 --days 3 --clean
gen hold_de  --size 100MB --seed 3 --days 4 --scenarios D,E
gen vary     --size 100MB --seed 1 --days 3 --scenarios prd,A,B,C --vary 11
gen nosysmon --size 100MB --seed 1 --days 3 --scenarios prd,A,B,C --vary 12 --drop sysmon
fi

run() {  # set_name dataset_dir
  $PY -m engine.run "$2" --out "$RUNS/$1" --no-llm > "$OUT/$1.engine.log" 2>&1
  cp "$RUNS/$1/stats.json" "$OUT/$1.stats.json" 2>/dev/null
}
synth() { run "$1" "$SY/$1"; $PY -m eval.score "$SY/$1" "$RUNS/$1" > "$OUT/$1.txt" 2>&1
          $PY -m eval.score "$SY/$1" "$RUNS/$1" --json > "$OUT/$1.json" 2>/dev/null; }
blind() { run "$1" "$B/corpora/$1"; $PY -m eval.blind "$B/corpora/$1.labels.json" "$RUNS/$1" --json "$OUT/$1.json" > "$OUT/$1.txt" 2>&1; }

if [ "$SETS" != blind ]; then
  (synth dev_s1; synth clean; synth hold_de) &
  (synth vary; synth nosysmon) &
  wait
fi
mixed() {  # real OTRF recordings injected into the clean synthetic network (behaviour detectors get a baseline)
  [ -f "$B/corpora/mix_otrf.labels.json" ] || $PY -m eval.mix "$SY/clean" "$B/corpora/otrf"       "$B/corpora/otrf.labels.json" "$B/corpora/mix_otrf" --n 30 > "$OUT/gen_mix.log" 2>&1
  run mix_otrf "$B/corpora/mix_otrf"
  $PY -m eval.blind "$B/corpora/mix_otrf.labels.json" "$RUNS/mix_otrf" --json "$OUT/mix_otrf.json" > "$OUT/mix_otrf.txt" 2>&1
}
if [ "$SETS" != synth ]; then
  [ -f "$SY/clean/ground_truth.json" ] || $PY -m generator.gen --out "$SY/clean" --size 100MB --seed 7 --days 3 --clean > "$OUT/gen_clean.log" 2>&1
  (blind evtx; blind otrf; mixed) & (blind splunk) &
  wait
fi

{
  echo "# scoreboard $TAG  $(date -u +%FT%TZ)  engine $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null)"
  for s in dev_s1 clean hold_de vary nosysmon; do
    [ -f "$OUT/$s.txt" ] || continue
    echo "## $s"; grep -E "Detection|Correct labels|Attack paths|False alarms|extrapolated|entry point|attack [0-9]+ \(" "$OUT/$s.txt"
    $PY -c "import json;s=json.load(open('$OUT/$s.stats.json'));print('  incidents',s['counts']['attack_incidents'],'attack /',s['counts']['review_incidents'],'review; hunt',s['stages_seconds']['detection'],'s')" 2>/dev/null
  done
  for s in evtx otrf splunk mix_otrf; do
    [ -f "$OUT/$s.txt" ] || continue
    echo "## $s (blind)"; sed -n '2,7p' "$OUT/$s.txt"
    $PY -c "import json;s=json.load(open('$OUT/$s.stats.json'));p=s['processed'];print('  ',p['events'],'events',p['seconds'],'s; hunt',s['stages_seconds']['detection'],'s; unparsed',p['unparsed'])" 2>/dev/null
  done
} > "$OUT/summary.txt"
echo BENCHDONE
