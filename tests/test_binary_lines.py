import gzip
import json
import os
import random

from engine.ingest.to_parquet import ingest, is_binary


def test_binary_detection():
    assert is_binary(b"abc" + bytes([0]) + b"def")
    assert is_binary(bytes(range(128, 256)) * 2)
    assert not is_binary(b'date=2026-10-23 time=08:48:26 devname="FGT60" type="traffic"')
    assert not is_binary(bytes([27]) + b"[31mERROR" + bytes([27]) + b"[0m disk full")    # colour codes = text
    assert not is_binary(b"endobj") and not is_binary(b"")


def test_binary_region_in_a_text_file_is_skipped_and_reported(tmp_path):
    good = [f'date=2026-10-23 time=08:48:{i % 60:02d} eventtime={1792745300 + i}000000000 devname="FGT60" '
            f'type="traffic" srcip=10.0.0.{i} dstip=8.8.8.8 dstport=53' for i in range(100)]
    rnd = random.Random(0)
    junk = [bytes(b for b in rnd.randbytes(300) if b != 10) for _ in range(40)]   # raw binary after the logs
    d = tmp_path / "ds"
    d.mkdir()
    with gzip.open(d / "fw.log.gz", "wb") as f:
        f.write(b"\n".join([g.encode() for g in good] + junk) + b"\n")
    rep = ingest(str(d), str(tmp_path / "run"), workers=1, log=lambda *_: None)
    f = next(iter(rep["files"].values()))
    assert f["rows"] == 100 and f["binary_lines"] >= 30, f                # junk never becomes events
    assert rep["binary_lines"] == f["binary_lines"] and rep["binary_bytes"] > 0
    assert json.load(open(os.path.join(tmp_path / "run", "ingest_report.json")))["binary_lines"] > 0
