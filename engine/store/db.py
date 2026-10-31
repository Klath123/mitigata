"""DuckDB over the Parquet event store, with a hard memory cap and spill-to-disk."""
from __future__ import annotations

import os

import duckdb


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
    con.execute(f"CREATE OR REPLACE VIEW events AS SELECT * FROM read_parquet('{glob}')")
    return con


def set_dataset_vars(con: duckdb.DuckDBPyConnection, warmup_frac: float = 0.2, min_warmup_h: float = 12) -> dict:
    """Dataset time bounds and the warm-up horizon used by first-seen (rarity) rules."""
    lo, hi = con.execute("SELECT min(ts), max(ts) FROM events WHERE ts IS NOT NULL").fetchone()
    lo, hi = lo or 0, hi or 0
    span = max(hi - lo, 1)
    if span < 6 * 3_600_000:
        # too little history to call anything "first-seen": rarity rules stay silent
        warm = hi + 1
    else:
        warm = lo + min(max(span * warmup_frac, min_warmup_h * 3_600_000), span * 0.5)
    v = {"ds_start": int(lo), "ds_end": int(hi), "warmup_end": int(warm),
         "rarity_enabled": bool(warm <= hi)}
    for k in ("ds_start", "ds_end", "warmup_end"):
        con.execute(f"SET VARIABLE {k} = {v[k]}")
    return v
