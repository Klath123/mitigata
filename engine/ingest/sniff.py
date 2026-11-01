"""Format detection from the first bytes/lines of a file."""
from __future__ import annotations

import json
import re

from .lines import bounded_lines
from .parsers import _APACHE, _AUDIT_HDR, _ISOSYS, _RFC3164, _RFC5424, parse_kv, sniff_csv_header

SAMPLE_LINES = 60
EVTX_MAGIC = b"ElfFile\x00"


def read_sample(path: str, n: int = SAMPLE_LINES) -> list[str]:
    out = []
    with open(path, "rb") as f:
        for raw, _ in bounded_lines(f):
            if raw is None:
                continue
            s = raw.decode("utf-8-sig", "replace").rstrip("\r\n")
            if s.strip():
                out.append(s)
            if len(out) >= n:
                break
    return out


def _frac(lines: list[str], pred) -> float:
    if not lines:
        return 0.0
    ok = 0
    for s in lines:
        try:
            ok += bool(pred(s))
        except Exception:
            pass
    return ok / len(lines)


def _is_json_obj(s: str) -> bool:
    s = s.strip().rstrip(",")
    if not s.startswith("{"):
        return False
    json.loads(s)
    return True


def sniff(path: str) -> tuple[str, dict]:
    """Return (format, ctx) where ctx carries format options (header, delimiter...)."""
    with open(path, "rb") as f:
        head = f.read(8)
    if head.startswith(EVTX_MAGIC):
        return "evtx", {}
    lines = read_sample(path)
    if not lines:
        return "empty", {}
    first = lines[0].lstrip("﻿")

    if first.startswith("#separator") or any(s.startswith("#fields\t") for s in lines[:10]):
        hdr = next((s.split("\t")[1:] for s in lines if s.startswith("#fields")), None)
        zp = next((s.split("\t")[1] for s in lines if s.startswith("#path")), "log")
        return "zeek", {"header": hdr, "zeek_path": zp}
    if first.startswith("#Software") or first.startswith("#Version") or first.startswith("#Fields:"):
        hdr = next((s[8:].split() for s in lines if s.startswith("#Fields:")), None)
        return "w3c", {"header": hdr}

    body = [s for s in lines if not s.startswith("#")] or lines
    if first.strip() == "[" or (first.strip().startswith("[") and first.strip()[1:2] in ("{", "")):
        return "json_stream", {}
    if _frac(body, _is_json_obj) >= 0.8:
        return "jsonl", {}
    if first.strip() == "{" or (first.startswith("{") and _frac(body[:5], _is_json_obj) < 0.5):
        return "json_stream", {}
    if any("<Event" in s for s in body[:5]) and any("</Event>" in s or "<System>" in s for s in body[:40]):
        return "xml_events", {}

    scores = {
        "auditd": _frac(body, lambda s: _AUDIT_HDR.search(s)),
        "cef": _frac(body, lambda s: "CEF:" in s and s.count("|") >= 7),
        "leef": _frac(body, lambda s: "LEEF:" in s and s.count("|") >= 4),
        "apache": _frac(body, lambda s: _APACHE.match(s)),
        "syslog": _frac(body, lambda s: _RFC5424.match(s) or _RFC3164.match(s) or _ISOSYS.match(s)),
        "kv": _frac(body, lambda s: len(parse_kv(s)) >= 4),
    }
    order = ["auditd", "cef", "leef", "apache", "syslog", "kv"]
    best = max(order, key=lambda k: (scores[k], -order.index(k)))
    if scores[best] >= 0.6:
        return best, {}

    # delimited text with consistent column counts (a preamble before the header is allowed, e.g. MS DHCP)
    from collections import Counter
    for delim in (",", "\t", "|", ";"):
        counts = [s.count(delim) for s in body[:40]]
        if not counts:
            continue
        big = [c for c in counts if c >= 2]
        if not big:
            continue
        mode, _ = Counter(big).most_common(1)[0]
        i = next(k for k, c in enumerate(counts) if c == mode)
        rest = counts[i:]
        if sum(abs(c - mode) <= 1 for c in rest) / len(rest) >= 0.9:
            header, d = sniff_csv_header(body[i:])
            fmt = "tsv" if d == "\t" else "csv"
            return fmt, {"header": header, "delimiter": d, "preamble": i > 0 and header is not None}
    return "generic", {}


_YEAR = re.compile(r"\b(20\d\d|19\d\d)-\d\d-\d\d|/(20\d\d):|\b(20\d\d)/\d\d/\d\d")


def year_hint(lines: list[str]) -> int | None:
    for s in lines:
        m = _YEAR.search(s)
        if m:
            return int(next(g for g in m.groups() if g))
    return None
