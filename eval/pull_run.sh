#!/bin/bash
# Copy a finished run's results (not its Parquet/DuckDB) from a benchmark box into results/<name>,
# then tell a running local API to switch to it.
#   bash eval/pull_run.sh ~/.ssh/<key>.pem <user>@<host> /path/to/run firex
set -e
[ $# -eq 4 ] || { echo "usage: $0 <ssh-key> <user@host> <remote-run-dir> <local-name>"; exit 1; }
key=$1; host=$2; remote=$3; name=$4
dest="$(dirname "$0")/../results/$name"
mkdir -p "$dest"
rm -rf "$dest/incidents"                       # incident files of an older pull must not linger
ssh -i "$key" "$host" "cd '$remote' && tar czf - --ignore-failed-read incidents incidents.json evidence.json \
  stats.json quality.json graph files.json ingest_report.json run_manifest.json validation.json entities.json 2>/dev/null" | tar xzf - -C "$dest"
echo "pulled $(ls "$dest/incidents" | wc -l) incidents into $dest"
curl -s -X POST "http://127.0.0.1:${ATTACKSTORY_PORT:-8000}/reload?run=$name" >/dev/null && echo "UI switched to $name" || true
