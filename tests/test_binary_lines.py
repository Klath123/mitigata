import gzip
import json
import os
import random

from engine.ingest.to_parquet import _binary, ingest


def test_binary_detection():
    assert _binary("abc" + chr(0) + "def")
    assert _binary(chr(0xFFFD) * 3 + chr(1) + chr(2) + "abcdefg")
    assert not _binary('date=2026-10-23 time=08:48:26 devname="FGT60" type="traffic"')
    assert not _binary("") and not _binary("endobj")


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
    assert f["rows"] == 100 and f["binary"] >= 30, f                      # junk never becomes events
    assert rep["binary_lines_skipped"] == f["binary"]
    lo, hi = f["binary_lines"]
    assert lo == 101
    assert json.load(open(os.path.join(tmp_path / "run", "ingest_report.json")))["binary_lines_skipped"] > 0
