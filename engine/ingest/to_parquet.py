"""Parallel streaming ingest: any log files -> normalized Parquet.

Steps: discover (unpack .gz/.zip, transcode UTF-16) -> sniff each file -> split large
line-oriented files into byte ranges at line boundaries (with exact line numbers) ->
a process pool parses, maps and writes one Parquet file per task -> ingest report.
"""
from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import time
import zipfile
from collections import Counter
from datetime import timedelta, timezone
from multiprocessing import get_context

import pyarrow as pa
import pyarrow.parquet as pq

from ..schema import EVENT_SCHEMA, FIELD_NAMES, RAW_MAX
from .mapper import DEFAULT_FIELDS, Mapper, TimeParser
from .discover import discover
from .parsers import PARSERS, SPLITTABLE, iter_evtx, parse_line_any
from .lines import bounded_lines, skip_line
from .sniff import read_sample, sniff, year_hint

BATCH = 50_000
_MAPPER: Mapper | None = None


# ====================================================================== discovery
def _tz(spec) -> timezone:
    if not spec or str(spec).upper() in ("UTC", "Z", "GMT"):
        return timezone.utc
    m = re.fullmatch(r"([+-])(\d\d):?(\d\d)", str(spec).strip())
    if m:
        mins = int(m.group(2)) * 60 + int(m.group(3))
        return timezone(timedelta(minutes=mins if m.group(1) == "+" else -mins))
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(str(spec))
    except Exception:
        return timezone.utc


def load_manifest(root: str) -> dict:
    p = os.path.join(root, "manifest.json")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    return {}


def _file_meta(manifest: dict, rel: str) -> dict:
    files = manifest.get("files") or {}
    if rel in files:
        return files[rel]
    best = ""
    for k in files:                                   # directory-prefix entries: "linux/WEB-01/"
        if k.endswith("/") and rel.startswith(k) and len(k) > len(best):
            best = k
    return files.get(best, {})


_HOSTISH = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*\d[A-Za-z0-9_-]*$")


def _dir_host(rel: str) -> str | None:
    parts = rel.replace("\\", "/").split("/")[:-1]
    for p in reversed(parts):
        if _HOSTISH.match(p):
            return p.upper()
    return None


# ====================================================================== task planning
def _boundaries(path: str, size: int, chunk: int) -> list[int]:
    bounds = [0]
    with open(path, "rb") as f:
        pos = chunk
        while pos < size:
            f.seek(pos)
            skip_line(f)
            b = f.tell()
            if b >= size:
                break
            if b > bounds[-1]:
                bounds.append(b)
            pos = b + chunk
    bounds.append(size)
    return bounds


def _count_newlines(args) -> int:
    path, start, end = args
    n = 0
    with open(path, "rb") as f:
        f.seek(start)
        left = end - start
        while left > 0:
            buf = f.read(min(1 << 23, left))
            if not buf:
                break
            n += buf.count(b"\n")
            left -= len(buf)
    return n


# ====================================================================== worker
def _init(fields_path: str) -> None:
    global _MAPPER
    _MAPPER = Mapper(fields_path)


_CTRL = re.compile(rb"[\x00-\x08\x0e-\x1a\x1c-\x1f\x7f]")   # ESC (\x1b) allowed: colour-coded log lines are text
_HIGH = re.compile(rb"[\x80-\xff]")


def is_binary(raw: bytes) -> bool:
    """Binary junk inside a text file (embedded archives, packages): control bytes, or invalid UTF-8
    that is mostly non-ASCII. A log line with a few Latin-1 characters is still text."""
    if _CTRL.search(raw):
        return True
    try:
        raw.decode("utf-8")
        return False
    except UnicodeDecodeError:
        return len(_HIGH.findall(raw)) > 0.3 * len(raw.rstrip(b"\r\n"))


def _iter_lines(path: str, start: int, end: int, base_line: int, binary: dict | None = None):
    with open(path, "rb") as f:
        f.seek(start)
        pos, n = start, base_line
        for raw, size in bounded_lines(f):
            if pos >= end:
                break
            n += 1
            if raw is None or (binary is not None and is_binary(raw)):   # over-long line or binary junk
                if binary is not None:
                    binary["lines"] += 1
                    binary["bytes"] += size
                pos += size
                continue
            text = raw.decode("utf-8", "replace").rstrip("\r\n")
            if pos == 0 and text.startswith("﻿"):
                text = text[1:]
            yield n, pos, text
            pos += len(raw)


def run_task(t: dict) -> dict:
    t0 = time.time()
    mapper = _MAPPER
    fmt, ctx = t["fmt"], dict(t["ctx"])
    ctx["mapper"] = mapper
    if t["start"] > 0:
        ctx["preamble"] = False
    tp = TimeParser(_tz(t["tz"]), t["year"], tz_declared=t["tz_declared"], year_declared=t["year_declared"])
    seekable = fmt != "evtx"
    line_count = [0]
    binary = {"lines": 0, "bytes": 0}

    def counted(it):
        for x in it:
            line_count[0] += 1
            yield x

    if fmt == "evtx":
        records = counted(iter_evtx(t["path"]))
    else:
        records = PARSERS[fmt](counted(_iter_lines(t["path"], t["start"], t["end"], t["base_line"], binary)), ctx)
    cols: dict[str, list] = {f: [] for f in FIELD_NAMES}
    writer = None
    st = {"rows": 0, "unparsed": 0, "no_ts": 0, "min_ts": None, "max_ts": None}
    etypes: Counter = Counter()
    unmapped_c: Counter = Counter()
    hosts: Counter = Counter()

    def flush():
        nonlocal writer, cols
        if not cols["ts"]:
            return
        tbl = pa.Table.from_pydict(cols, schema=EVENT_SCHEMA)
        tbl = tbl.sort_by([("host", "ascending"), ("ts", "ascending")])
        if writer is None:
            writer = pq.ParquetWriter(t["out"], EVENT_SCHEMA, compression="zstd", use_dictionary=True)
        writer.write_table(tbl, row_group_size=BATCH)
        cols = {f: [] for f in FIELD_NAMES}

    k = 0
    for n, off, rec, raw in records:
        rfmt, status, error = fmt, "ok", None
        if rec is None:
            st["unparsed"] += 1
            status = "fallback"
            error = ctx.pop("_err", None) or f"{fmt} parser could not read this record"
            rec = parse_line_any(raw, ctx)
            rfmt = "generic"
        try:
            row, unmapped = mapper.map(rec, tp, t["host"], rfmt)
        except Exception as ex:
            st["unparsed"] += 1
            status, error = "map_error", f"{type(ex).__name__}: {str(ex)[:160]}"
            row, unmapped = mapper.map({"message": str(raw)[:4000]}, tp, t["host"], "generic")
        row["parse_status"], row["parse_error"], row["ingest_ts"] = status, error, t["ingest_ts"]
        if unmapped:
            extra = {}
            for key in unmapped:
                v = rec.get(key)
                if v not in (None, "", "-"):
                    extra[key] = v if isinstance(v, (int, float, bool)) else str(v)[:300]
            if extra:
                s = json.dumps(extra, default=str)
                row["extra"] = s[:2000]
            k += 1
            if k % 25 == 1:
                unmapped_c.update(unmapped)
        row["src_file"] = t["rel"]
        row["line"] = n
        row["format"] = rfmt
        row["offset"] = off if seekable else -1
        if not seekable or not raw or t.get("store_raw"):
            row["raw"] = (raw or "")[:RAW_MAX]
        ts = row.get("ts")
        if ts is None:
            st["no_ts"] += 1
        else:
            if st["min_ts"] is None or ts < st["min_ts"]:
                st["min_ts"] = ts
            if st["max_ts"] is None or ts > st["max_ts"]:
                st["max_ts"] = ts
        etypes[row.get("event_type")] += 1
        hosts[row.get("host")] += 1
        for f in FIELD_NAMES:
            cols[f].append(row.get(f))
        st["rows"] += 1
        if len(cols["ts"]) >= BATCH:
            flush()
    flush()
    if writer:
        writer.close()
    st["lines"] = line_count[0] + binary["lines"]
    st["binary_lines"], st["binary_bytes"] = binary["lines"], binary["bytes"]
    st.update(task=t["id"], rel=t["rel"], fmt=fmt, bytes=t["end"] - t["start"], seconds=time.time() - t0,
              event_types=dict(etypes.most_common(40)), unmapped=dict(unmapped_c.most_common(25)),
              hosts=len(hosts), domains=sorted(mapper.domains)[:20])
    return st


# ====================================================================== driver
def ingest(root: str, out: str, workers: int | None = None, chunk_mb: int = 32,
           fields_path: str = DEFAULT_FIELDS, log=print) -> dict:
    t0 = time.time()
    workers = workers or max(1, (os.cpu_count() or 2))
    ev_dir = os.path.join(out, "events")
    if os.path.isdir(ev_dir):
        shutil.rmtree(ev_dir)
    os.makedirs(ev_dir, exist_ok=True)
    manifest = load_manifest(root)
    files, skipped = discover(root, out)
    for sk in skipped:
        log(f"  skip {sk['file']}: {sk['reason']}")
    gtz = manifest.get("timezone", "UTC")

    sniffed = []
    years = Counter()
    template_report: dict[str, dict] = {}
    for path, rel in files:
        size = os.path.getsize(path)
        if size == 0:
            continue
        meta = _file_meta(manifest, rel)
        fmt, ctx = (meta["format"], {}) if meta.get("format") else sniff(path)
        if meta.get("format") in ("csv", "tsv", "w3c", "zeek"):
            _, ctx = sniff(path)
        if fmt == "empty":
            continue
        if fmt != "evtx":
            y = year_hint(read_sample(path, 20))
            if y:
                years[y] += 1
        if fmt == "generic":
            try:
                from .templates import discover as discover_templates
                tinfo = discover_templates(path)
                ctx = {**ctx, "templates": tinfo["templates"]}
                template_report[rel] = {k: tinfo[k] for k in ("sampled_lines", "coverage", "clusters_total")}
                template_report[rel]["templates"] = [{k: t[k] for k in ("template", "count", "share", "example")}
                                                     | {"fields": [x["name"] for x in t["slots"]]}
                                                     for t in tinfo["templates"][:20]]
                log(f"  templates {rel}: {len(tinfo['templates'])} templates cover "
                    f"{100 * tinfo['coverage']:.0f}% of {tinfo['sampled_lines']:,} sampled lines")
            except ImportError:
                log("  templates: drain3 not installed, generic files use key=value / timestamp heuristics only")
        host = meta.get("host") or _dir_host(rel)
        sniffed.append((path, rel, size, fmt, ctx, host, meta.get("tz", gtz),
                        bool(meta.get("tz") or manifest.get("timezone"))))
        log(f"  sniff {rel}: {fmt} ({size / 2**20:.1f} MB){' host=' + host if host else ''}")
    year = int(manifest.get("year") or (years.most_common(1)[0][0] if years else time.gmtime().tm_year))

    tasks = []
    count_jobs = []
    ingest_ts = int(time.time() * 1000)
    for path, rel, size, fmt, ctx, host, tz, tz_declared in sniffed:
        if fmt in SPLITTABLE and size > chunk_mb * 2**20:
            b = _boundaries(path, size, chunk_mb * 2**20)
        else:
            b = [0, size]
        for i in range(len(b) - 1):
            tasks.append({"id": len(tasks), "path": path, "rel": rel, "fmt": fmt, "ctx": ctx, "host": host,
                          "tz": tz, "tz_declared": tz_declared, "year_declared": bool(manifest.get("year")),
                          "ingest_ts": ingest_ts,
                          "year": year, "start": b[i], "end": b[i + 1], "base_line": 0,
                          "out": os.path.join(ev_dir, f"part-{len(tasks):05d}.parquet")})
            if i > 0:
                count_jobs.append((len(tasks) - 1, (path, b[i - 1], b[i])))
    ctx_mp = get_context("spawn")
    with ctx_mp.Pool(workers, initializer=_init, initargs=(fields_path,)) as pool:
        if count_jobs:
            counts = pool.map(_count_newlines, [j[1] for j in count_jobs], chunksize=4)
            by_task = dict(zip([j[0] for j in count_jobs], counts))
            for t in tasks:                       # prefix-sum within each file
                if t["start"] > 0:
                    prev = tasks[t["id"] - 1]
                    t["base_line"] = prev["base_line"] + by_task[t["id"]]
        log(f"  {len(tasks)} parse tasks over {len(sniffed)} files on {workers} workers")
        results = []
        order = sorted(tasks, key=lambda t: -(t["end"] - t["start"]))
        for r in pool.imap_unordered(run_task, order):
            results.append(r)

    # ---------------------------------------------------------- report
    per_file: dict[str, dict] = {}
    for r in sorted(results, key=lambda r: r["task"]):
        f = per_file.setdefault(r["rel"], {"format": r["fmt"], "bytes": 0, "lines": 0, "rows": 0, "unparsed": 0, "no_ts": 0,
                                           "binary_lines": 0, "binary_bytes": 0,
                                           "min_ts": None, "max_ts": None, "event_types": Counter(),
                                           "unmapped": Counter(), "tasks": 0})
        f["tasks"] += 1
        for k in ("bytes", "lines", "rows", "unparsed", "no_ts", "binary_lines", "binary_bytes"):
            f[k] += r[k]
        for k, fn in (("min_ts", min), ("max_ts", max)):
            if r[k] is not None:
                f[k] = r[k] if f[k] is None else fn(f[k], r[k])
        f["event_types"].update(r["event_types"])
        f["unmapped"].update(r["unmapped"])
    for f in per_file.values():
        f["event_types"] = dict(f["event_types"].most_common(25))
        f["unmapped"] = dict(f["unmapped"].most_common(15))
    total_bytes = sum(s[2] for s in sniffed)
    report = {"root": os.path.abspath(root), "files": per_file, "skipped": skipped, "templates": template_report, "year_assumed": year,
              "bytes": total_bytes, "rows": sum(f["rows"] for f in per_file.values()),
              "lines": sum(f["lines"] for f in per_file.values()),
              "unparsed": sum(f["unparsed"] for f in per_file.values()),
              "binary_lines": sum(f["binary_lines"] for f in per_file.values()),
              "binary_bytes": sum(f["binary_bytes"] for f in per_file.values()),
              "seconds": round(time.time() - t0, 2), "workers": workers, "tasks": len(tasks)}
    report["mb_per_s"] = round(total_bytes / 2**20 / max(report["seconds"], 1e-6), 2)
    with open(os.path.join(out, "ingest_report.json"), "w") as fh:
        json.dump(report, fh, indent=1, default=str)
    with open(os.path.join(out, "files.json"), "w") as fh:
        json.dump({rel: {"path": os.path.abspath(path), "format": fmt} for path, rel, _, fmt, *_ in sniffed}, fh,
                  indent=1)
    return report
