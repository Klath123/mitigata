#!/bin/bash
# Rerun the hackathon file (ingest reused) with the Claude narrator on. Key: ~/.anthropic_key (one line, chmod 600).
set -e
[ -s ~/.anthropic_key ] || { echo "put the API key in ~/.anthropic_key first"; exit 1; }
export ANTHROPIC_API_KEY=$(tr -d '[:space:]' < ~/.anthropic_key)
cd ~/work/after
~/venv/bin/python -u -m engine.run /data/logs/bench/hackathon/firex --out /data/logs/bench/runs/firex_after \
  --skip-ingest --memory 6GB > ~/firex_llm.log 2>&1
echo RUNDONE >> ~/firex_llm.log
