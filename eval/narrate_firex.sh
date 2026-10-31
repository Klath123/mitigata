#!/bin/bash
# Rerun the hackathon file (ingest reused) with the Gemini narrator on. Key: ~/.gemini_key (one line, chmod 600).
set -e
[ -s ~/.gemini_key ] || { echo "put the Gemini API key in ~/.gemini_key first"; exit 1; }
export GEMINI_API_KEY=$(tr -d '[:space:]' < ~/.gemini_key)
cd ~/work/after
~/venv/bin/python -u -m engine.run /data/logs/bench/hackathon/firex --out /data/logs/bench/runs/firex_after \
  --skip-ingest --memory 6GB > ~/firex_llm.log 2>&1
echo RUNDONE >> ~/firex_llm.log
