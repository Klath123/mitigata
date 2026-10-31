#!/bin/bash
# Full run of the hackathon firex-19g file on GCP #1 (ingest -> hunt -> correlate -> Gemini narration).
set -e
D=/data/logs/bench/hackathon/firex19
OUT=/data/logs/bench/runs/firex19
mkdir -p "$D"; [ -e "$D/firex-19g.log.gz" ] || ln -sf /data/logs/firex-19g.log.gz "$D/firex-19g.log.gz"   # big box: file copied in; GCP #1: link
[ -s ~/.gemini_key ] && export GEMINI_API_KEY=$(tr -d '[:space:]' < ~/.gemini_key)
cd ~/work/f19
~/venv/bin/python -u -m engine.run "$D" --out "$OUT" --memory 6GB > ~/firex19.log 2>&1
echo RUNDONE >> ~/firex19.log
