"""A file with a huge newline-free stretch (the firex-19g tail: 15 GB of NUL bytes) must be read with bounded
memory: real lines keep their numbers and offsets, the stretch is skipped and counted as junk."""
import tracemalloc

from engine.ingest import lines, to_parquet


def test_newline_free_stretch_is_skipped_not_loaded(tmp_path, monkeypatch):
    monkeypatch.setattr(lines, "MAX_LINE", 64 * 1024)          # stands in for 1 MiB
    junk = b"\x00" * (5 << 20)                                 # 5 MB, no newline: one giant "line"
    data = b"date=1 a=1\ndate=2 a=2\n" + junk + b"\ndate=3 a=3\n"
    p = tmp_path / "fw.log"
    p.write_bytes(data)

    binary = {"lines": 0, "bytes": 0}
    tracemalloc.start()
    got = list(to_parquet._iter_lines(str(p), 0, len(data), 0, binary))
    bounds = to_parquet._boundaries(str(p), len(data), 1 << 20)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()

    assert [(n, text) for n, _, text in got] == [(1, "date=1 a=1"), (2, "date=2 a=2"), (4, "date=3 a=3")]
    assert got[2][1] == data.index(b"date=3")                  # byte offset of the line after the junk
    assert binary == {"lines": 1, "bytes": len(junk) + 1}
    assert bounds[0] == 0 and bounds[-1] == len(data)
    assert peak < 1 << 20, f"peak {peak:,} bytes: the junk line was held in memory"
