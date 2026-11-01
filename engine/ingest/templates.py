"""Template discovery for logs in an unknown format (Drain3), compiled to regexes for the full pass.

Discovery runs on a SAMPLE of each generic file (fast at any dataset size). Each template's variable
slots get a field name from their value type and the constant word before them:
  "Failed login for <*> from <IP>"  ->  user, src_ip
  "ALERT user=<*> ip=<IP> action=<*>"  ->  user, ip, action   (key= names go through fields.yaml aliases)
Templates only extract fields; they never decide a security event type on their own.
"""
from __future__ import annotations

import re

from .lines import bounded_lines

TS_RX = (r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?"
         r"|[A-Z][a-z]{2}\s+\d{1,2}\s\d\d:\d\d:\d\d")
IP_RX = r"(?:\d{1,3}\.){3}\d{1,3}"
SLOT_RX = {"TS": f"(?:{TS_RX})", "IP": IP_RX, "HEX": r"0x[0-9a-fA-F]+", "NUM": r"-?\d+(?:\.\d+)?", "*": r"\S+"}
USER_WORDS = {"user", "username", "account", "for", "by", "login", "usr", "uid", "acct", "actor", "principal"}
SRC_WORDS = {"from", "src", "source", "client", "rhost", "remote", "caller", "origin", "srcip", "src_ip", "ip", "addr"}
DST_WORDS = {"to", "dst", "dest", "destination", "server", "target", "dstip", "dst_ip"}
HOST_WORDS = {"host", "hostname", "computer", "machine", "device", "node"}
NAMED_WORDS = {"status": "status", "result": "status", "outcome": "status", "action": "action", "op": "action",
               "operation": "action", "event": "action", "pid": "pid", "process": "process", "proc": "process",
               "exe": "process", "cmd": "cmdline", "command": "cmdline", "file": "target", "path": "target",
               "url": "target", "port": "port"}
MIN_CLUSTER = 2
MAX_TEMPLATES = 60


def _miner():
    from drain3 import TemplateMiner
    from drain3.masking import MaskingInstruction
    from drain3.template_miner_config import TemplateMinerConfig
    cfg = TemplateMinerConfig()
    cfg.profiling_enabled = False
    cfg.drain_sim_th = 0.5
    cfg.drain_depth = 4
    cfg.masking_instructions = [
        MaskingInstruction(TS_RX, "TS"),
        MaskingInstruction(rf"(?<![\d.]){IP_RX}(?![\d.])", "IP"),
        MaskingInstruction(r"0x[0-9a-fA-F]+", "HEX"),
        MaskingInstruction(r"(?<![\w.])-?\d+(?:\.\d+)?(?![\w.])", "NUM"),
    ]
    return TemplateMiner(config=cfg)


def _slot_name(prev: str, kind: str, used: set[str], i: int) -> str:
    prev = prev.strip()
    word = re.split(r"[\s\[(,;]+", prev)[-1] if prev else ""
    key = None
    if word.endswith(("=", ":")):
        key = word.rstrip("=:").lower()
        word = key
    w = word.lower().strip("'\"")
    if kind == "TS":
        name = "ts"
    elif kind == "IP":
        name = "dst_ip" if w in DST_WORDS else "src_ip" if (w in SRC_WORDS or "src_ip" not in used) else f"ip{i}"
    elif key:
        name = key                                    # key=value: keep the vendor key, aliases map it
    elif w in USER_WORDS:
        name = "user"
    elif w in HOST_WORDS:
        name = "host"
    elif w in NAMED_WORDS:
        name = NAMED_WORDS[w]
    else:
        name = f"tpl_slot{i}"
    base, k = name, 2
    while name in used:
        name, k = f"{base}{k}", k + 1
    used.add(name)
    return name


def compile_template(template: str) -> tuple[str, list[dict]]:
    """Drain template -> anchored regex with named groups, plus slot descriptions."""
    parts = re.split(r"<(TS|IP|HEX|NUM|\*)>", template)
    rx, slots, used, prev = "^", [], set(), ""
    for i, part in enumerate(parts):
        if i % 2 == 0:
            lit = re.escape(part)
            rx += re.sub(r"(\\ )+|\s+", r"\\s+", lit)
            prev = part
        else:
            name = _slot_name(prev, part, used, len(slots))
            group = re.sub(r"\W", "_", name)
            slots.append({"name": name, "group": group, "kind": part})
            rx += f"(?P<{group}>{SLOT_RX[part]})"
    return rx + r"\s*$", slots


def discover(path: str, sample_lines: int = 50_000) -> dict:
    """Mine templates from the start of a file; returns templates with coverage and examples."""
    tm = _miner()
    n = 0
    examples: dict[int, str] = {}
    with open(path, "rb") as f:
        for raw, _ in bounded_lines(f):
            if raw is None:
                continue
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            r = tm.add_log_message(line)
            examples.setdefault(r["cluster_id"], line)
            n += 1
            if n >= sample_lines:
                break
    clusters = sorted(tm.drain.clusters, key=lambda c: -c.size)
    templates = []
    covered = 0
    for c in clusters:
        if c.size < MIN_CLUSTER or len(templates) >= MAX_TEMPLATES:
            continue
        tpl = c.get_template()
        rx, slots = compile_template(tpl)
        try:
            ok = re.match(rx, examples.get(c.cluster_id, "")) is not None
        except re.error:
            continue
        if not ok:
            continue                      # template could not reproduce its own example: don't trust it
        covered += c.size
        templates.append({"id": c.cluster_id, "template": tpl, "count": c.size, "share": round(c.size / max(n, 1), 4),
                          "regex": rx, "slots": slots, "example": examples.get(c.cluster_id, "")[:300]})
    return {"sampled_lines": n, "templates": templates, "coverage": round(covered / max(n, 1), 4),
            "clusters_total": len(clusters)}


def apply(text: str, ctx: dict) -> dict | None:
    """Match one line against the file's templates (compiled once per worker task)."""
    comp = ctx.get("_tpl_compiled")
    if comp is None:
        comp = ctx["_tpl_compiled"] = [(re.compile(t["regex"]), t) for t in ctx.get("templates") or []]
    s = text.strip()
    for rx, t in comp:
        m = rx.match(s)
        if m:
            rec = {"template_id": t["id"], "template": t["template"]}
            for sl in t["slots"]:
                v = m.group(sl["group"])
                if v is not None:
                    rec[sl["name"]] = v
            return rec
    return None
