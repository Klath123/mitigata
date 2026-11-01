#!/usr/bin/env bash
# Knowledge-base test on real data: the first 1M lines of the hackathon 10G file, cut in two batches in the middle of
# incident 1 (16:31 -> 20:36). Batch A holds its first step only, batch B the later steps. Expected: batch B's run
# carries batch A's hits in, rebuilds incident 1 with steps from both batches, and the KB holds it once.
#   bash eval/kb_split_test.sh        (on the big box; results in /data/logs/bench/runs/kbtest)
set -euo pipefail
SRC=/data/logs/bench/hackathon/firex/firex-10G.log.gz
T=/data/logs/bench/kbtest
R=/data/logs/bench/runs/kbtest
rm -rf "$T" "$R"
mkdir -p "$T/inbox" "$R"
zcat "$SRC" | head -n 1000000 > "$T/first1m.log" || true      # head closes the pipe early: zcat's SIGPIPE is fine
head -n 250000 "$T/first1m.log" > "$T/inbox/h01.log"
touch -d '2 hours ago' "$T/inbox/h01.log"
tail -n +250001 "$T/first1m.log" > "$T/inbox/h02.log"
rm "$T/first1m.log"
touch -d '1 hour ago' "$T/inbox/h02.log"
[ -f ~/.groq_key ] && export GROQ_API_KEY="$(cat ~/.groq_key)"        # gpt-oss on Groq first
[ -f ~/.gemini_key ] && export GEMINI_API_KEY="$(cat ~/.gemini_key)"    # Gemini as fallback
source ~/venv/bin/activate
cd ~/work/kb
python -m engine.kb watch "$T/inbox" --runs "$R" --kb "$R/kb" --once --quiet 0 --memory 6GB
echo KBDONE
