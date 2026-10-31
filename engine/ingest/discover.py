"""File discovery by CONTENT, never by extension.

- gzip / zip are unpacked whatever their extension (a .gz renamed .txt still works)
- UTF-16 (with or without a byte-order mark) is transcoded to UTF-8
- EVTX is recognised by its magic bytes (an .evtx renamed .txt still works)
- known binary formats (images, executables, PDF, pcap, SQLite, 7z/rar...) and unknown binary content
  are skipped AND reported with the reason, never read as junk text
Only the engine's own output files are skipped by extension.
"""
from __future__ import annotations

import gzip
import os
import shutil
import zipfile

SKIP_NAMES = {"ground_truth.json", "manifest.json", "files.json", "ingest_report.json", "quality.json",
              "evidence.json", "incidents.json", "stats.json"}
OWN_OUTPUT_EXT = {".parquet", ".duckdb", ".wal", ".pyc"}
BINARY_MAGIC = [
    (bytes([0x89]) + b"PNG", "PNG image"), (bytes([0xFF, 0xD8, 0xFF]), "JPEG image"), (b"GIF8", "GIF image"),
    (b"%PDF", "PDF document"), (b"MZ", "Windows executable"), (bytes([0x7F]) + b"ELF", "ELF executable"),
    (b"SQLite format 3", "SQLite database"), (bytes([0xD4, 0xC3, 0xB2, 0xA1]), "pcap capture"),
    (bytes([0xA1, 0xB2, 0xC3, 0xD4]), "pcap capture"), (bytes([0x0A, 0x0D, 0x0D, 0x0A]), "pcapng capture"),
    (b"7z" + bytes([0xBC, 0xAF, 0x27, 0x1C]), "7-Zip archive"), (b"Rar!", "RAR archive"), (b"PAR1", "Parquet file"),
    (b"BZh", "bzip2 archive"), (bytes([0xFD]) + b"7zXZ", "xz archive"),
]
EVTX_MAGIC = b"ElfFile" + bytes([0])
GZIP_MAGIC = bytes([0x1F, 0x8B])
ZIP_MAGIC = b"PK" + bytes([3, 4])
MAX_DEPTH = 3


def classify(path: str) -> tuple[str, str]:
    """text | evtx | gzip | zip | utf16 | utf16le | binary | empty, plus a human reason."""
    with open(path, "rb") as f:
        head = f.read(65536)
    if not head:
        return "empty", "empty file"
    if head.startswith(EVTX_MAGIC):
        return "evtx", "EVTX"
    if head.startswith(GZIP_MAGIC):
        return "gzip", "gzip"
    if head.startswith(ZIP_MAGIC):
        return "zip", "zip"
    if head[:2] in (bytes([0xFF, 0xFE]), bytes([0xFE, 0xFF])):
        return "utf16", "UTF-16 with BOM"
    for magic, what in BINARY_MAGIC:
        if head.startswith(magic):
            return "binary", what
    odd, even = head[1::2], head[0::2]
    if len(odd) > 64 and odd.count(0) / len(odd) > 0.9 and even.count(0) / max(1, len(even)) < 0.1:
        return "utf16le", "UTF-16LE without BOM"
    ctrl = sum(1 for b in head if b < 9 or 13 < b < 32)
    if head.count(0) / len(head) > 0.01 or ctrl / len(head) > 0.3:
        return "binary", f"unknown binary content ({head.count(0)} NUL bytes in the first {len(head)})"
    return "text", "text"


def discover(root: str, work: str) -> tuple[list[tuple[str, str]], list[dict]]:
    """Returns ([(physical_path, src_file_rel)], skipped[{file, reason}])."""
    out: list[tuple[str, str]] = []
    skipped: list[dict] = []
    unpack = os.path.join(work, "unpacked")
    work_abs = os.path.abspath(work)

    def handle(path: str, rel: str, depth: int = 0) -> None:
        try:
            kind, why = classify(path)
        except OSError as ex:
            skipped.append({"file": rel, "reason": f"unreadable: {ex}"})
            return
        if kind in ("text", "evtx"):
            out.append((path, rel))
        elif kind == "empty":
            skipped.append({"file": rel, "reason": why})
        elif kind == "binary":
            skipped.append({"file": rel, "reason": f"binary content: {why}"})
        elif depth >= MAX_DEPTH:
            skipped.append({"file": rel, "reason": f"{why} nested more than {MAX_DEPTH} levels"})
        elif kind == "gzip":
            base = rel[:-3] if rel.lower().endswith(".gz") else rel + ".ungz"
            dst = os.path.join(unpack, base.replace("!/", "/"))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                with gzip.open(path, "rb") as src, open(dst, "wb") as d:
                    shutil.copyfileobj(src, d, 1 << 20)
            except (OSError, EOFError) as ex:
                skipped.append({"file": rel, "reason": f"corrupt gzip: {ex}"})
                return
            handle(dst, base, depth + 1)
        elif kind == "zip":
            try:
                with zipfile.ZipFile(path) as z:
                    for m in z.namelist():
                        if m.endswith("/"):
                            continue
                        dst = os.path.join(unpack, rel.replace("!/", "/"), m)
                        os.makedirs(os.path.dirname(dst), exist_ok=True)
                        with z.open(m) as src, open(dst, "wb") as d:
                            shutil.copyfileobj(src, d, 1 << 20)
                        handle(dst, f"{rel}!/{m}", depth + 1)
            except (zipfile.BadZipFile, OSError) as ex:
                skipped.append({"file": rel, "reason": f"corrupt zip: {ex}"})
        elif kind in ("utf16", "utf16le"):
            dst = os.path.join(unpack, "utf8", rel.replace("!/", "/"))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            enc = "utf-16" if kind == "utf16" else "utf-16-le"
            with open(path, encoding=enc, errors="replace") as src, \
                    open(dst, "w", encoding="utf-8", newline="\n") as d:
                shutil.copyfileobj(src, d, 1 << 20)
            out.append((dst, rel))

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")
                       and not os.path.abspath(os.path.join(dirpath, d)).startswith(work_abs)]
        for fn in sorted(filenames):
            if fn in SKIP_NAMES or fn.startswith(".") or os.path.splitext(fn)[1].lower() in OWN_OUTPUT_EXT:
                continue
            path = os.path.join(dirpath, fn)
            handle(path, os.path.relpath(path, root).replace(os.sep, "/"))
    return out, skipped
