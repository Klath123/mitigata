"""DuckDB over the Parquet event store, with a hard memory cap and spill-to-disk."""
from __future__ import annotations

import os

import duckdb

TS_MIN = 946_684_800_000          # 2000-01-01: anything earlier is a parse error, not a log
# identical records: the same event written twice into the same file
DUP_KEY = ("hash(ts, host, event_type, \"user\", process, cmdline, target, src_ip, dst_ip, dst_port, bytes_out, "
           "logon_id, src_file)")


def connect(run_dir: str, memory_limit: str = "6GB", threads: int | None = None,
            persist: bool = True) -> duckdb.DuckDBPyConnection:
    """Open the run's DuckDB (derived tables live in engine.duckdb) with `events` as a view over Parquet."""
    path = os.path.join(run_dir, "engine.duckdb") if persist else ":memory:"
    con = duckdb.connect(path)
    spill = os.path.join(run_dir, "spill")
    os.makedirs(spill, exist_ok=True)
    con.execute(f"SET memory_limit='{memory_limit}'")
    con.execute(f"SET temp_directory='{spill.replace(os.sep, '/')}'")
    con.execute("SET preserve_insertion_order=false")
    if threads:
        con.execute(f"SET threads={int(threads)}")
    glob = os.path.join(run_dir, "events", "*.parquet").replace(os.sep, "/")
    con.execute(f"CREATE OR REPLACE VIEW events_all AS SELECT * FROM read_parquet('{glob}')")
    try:                                   # Parquet written before cmdline_clean existed: rules still reference it
        cols = {c[0] for c in con.execute("DESCRIBE events_all").fetchall()}
        if cols and "cmdline_clean" not in cols:
            con.execute(f"CREATE OR REPLACE VIEW events_all AS SELECT *, NULL::VARCHAR AS cmdline_clean "
                        f"FROM read_parquet('{glob}')")
    except duckdb.Error:                   # no Parquet yet
        pass
    # detection runs only on records that can be placed on a timeline; the rest are reported, not hidden
    con.execute(f"CREATE OR REPLACE VIEW events AS SELECT * FROM events_all "
                f"WHERE ts BETWEEN {TS_MIN} AND epoch_ms(now()::TIMESTAMP) + {2 * 86_400_000}")
    return con


def dedup_events(con: duckdb.DuckDBPyConnection) -> int:
    """Detection sees each identical record once (first occurrence kept); events_all still has every copy."""
    con.execute(f"""CREATE OR REPLACE TABLE events_det AS SELECT * FROM events
                    QUALIFY row_number() OVER (PARTITION BY {DUP_KEY} ORDER BY src_file, line) = 1""")
    before = con.execute("SELECT count(*) FROM events").fetchone()[0]
    con.execute("CREATE OR REPLACE VIEW events AS SELECT * FROM events_det")
    return before - con.execute("SELECT count(*) FROM events").fetchone()[0]


def set_dataset_vars(con: duckdb.DuckDBPyConnection, warmup_frac: float = 0.2, min_warmup_h: float = 12,
                     continuing: bool = False) -> dict:
    """Dataset time bounds and the warm-up horizon used by first-seen (rarity) rules.
    continuing: a later batch of a stream (engine/kb.py). Its first hours are not a warm-up: treating them as
    "normal" would hide an attack that continues into this batch, so warm-up baselining and per-batch first-seen
    rules are off (warmup_end past the end, as for a short dataset)."""
    lo, hi = con.execute("SELECT min(ts), max(ts) FROM events WHERE ts IS NOT NULL").fetchone()
    lo, hi = lo or 0, hi or 0
    span = max(hi - lo, 1)
    if continuing or span < 6 * 3_600_000:
        # too little history to call anything "first-seen": rarity rules stay silent
        warm = hi + 1
    else:
        warm = lo + min(max(span * warmup_frac, min_warmup_h * 3_600_000), span * 0.5)
    v = {"ds_start": int(lo), "ds_end": int(hi), "warmup_end": int(warm),
         "rarity_enabled": bool(warm <= hi)}
    for k in ("ds_start", "ds_end", "warmup_end"):
        con.execute(f"SET VARIABLE {k} = {v[k]}")
    return v
