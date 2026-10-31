"""Injection guard: find instruction-like text that an attacker planted in log fields.

Log text never reaches an LLM as instructions (it is only ever a JSON value in a data block);
this detector additionally surfaces such text to the analyst as an indicator of attacker intent.
Encoded PowerShell (-enc) is decoded before scanning.
"""
from __future__ import annotations

import base64
import re

PATTERNS = [
    r"ignore (all |any )?(previous|prior|above) (instructions|prompts?)",
    r"(note|message|instruction)s? (to|for) (the )?(ai|llm|assistant|analyst|model|gpt|claude)",
    r"classify (this|it|the activity)? ?(as )?(benign|safe|legitimate|false positive)",
    r"(mark|treat|report) (this|it) as (benign|safe|legitimate)",
    r"(this|the) (script|activity|binary|file) is (approved|authori[sz]ed|whitelisted|safe)",
    r"you are (now )?(an?|the) (ai|assistant|model)",
    r"disregard (the )?(rules|instructions|system prompt)",
    r"system prompt",
    r"do not (report|alert|flag)",
]
RX = re.compile("|".join(f"(?:{p})" for p in PATTERNS), re.I)
ENC = re.compile(r"\s[-/]e(?:c|nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})", re.I)
FIELDS = ("cmdline", "message", "target", "process", "user")


def decode_ps(cmdline: str) -> str | None:
    m = ENC.search(cmdline or "")
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1) + "===").decode("utf-16-le", "replace")
    except Exception:
        return None


def scan_rows(rows: list[dict]) -> list[dict]:
    out, seen = [], set()
    for r in rows:
        ev = f"{r['src_file']}:{r['line']}"
        texts = [(f, r.get(f)) for f in FIELDS if r.get(f)]
        dec = decode_ps(r.get("cmdline") or "")
        if dec:
            texts.append(("cmdline (decoded -enc)", dec))
        for field, text in texts:
            m = RX.search(str(text))
            if m and (ev, field) not in seen:
                seen.add((ev, field))
                s = max(0, m.start() - 60)
                out.append({"evidence": ev, "field": field, "match": m.group(0),
                            "text": str(text)[s:m.end() + 120], "host": r.get("host"),
                            "note": "instruction-like text in a log field: treated as data and shown as an "
                                    "indicator of attacker intent; it cannot change the verdict"})
    return out
