"""Line reading with bounded memory.

A "line" longer than MAX_LINE is never a log record: it is zero padding, an embedded blob or a truncated file
(the hackathon firex-19g file ends in 15 GB of NUL bytes with no newline). Plain `for raw in f` / `readline()`
would hold such a line whole and run the machine out of memory; these helpers skip it in MAX_LINE pieces.
"""
from __future__ import annotations

MAX_LINE = 1 << 20          # 1 MiB


def bounded_lines(f):
    """Yields (raw, n_bytes) per line of a binary file: raw is the line (with its newline), or None for an
    over-long line that was skipped; n_bytes is how many bytes the line took either way."""
    limit = MAX_LINE
    while True:
        raw = f.readline(limit)
        if not raw:
            return
        if len(raw) < limit or raw.endswith(b"\n"):
            yield raw, len(raw)
            continue
        n = len(raw)
        while True:                          # rest of the over-long line, one bounded piece at a time
            piece = f.readline(limit)
            n += len(piece)
            if not piece or piece.endswith(b"\n"):
                break
        yield None, n


def skip_line(f) -> None:
    """Move past the next newline (or to the end) without holding the line."""
    for _ in bounded_lines(f):
        return
