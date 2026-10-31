"""Minimal Sigma -> DuckDB SQL converter (no pySigma dependency).

Supports: logsource product/category/service mapping, selections as maps or lists of maps,
field modifiers contains/startswith/endswith/all/re/cidr(prefix)/windash, null values, keyword lists,
and conditions with and/or/not, parentheses, '1 of x*', 'all of x*', '1 of them', 'all of them'.
Unknown fields fall back to a regex over the `extra` JSON column.
"""
from __future__ import annotations

import glob
import os
import re

import yaml

FIELD_MAP = {
    "image": "process", "newprocessname": "process", "sourceimage": "process", "processname": "process",
    "exe": "process",
    "commandline": "cmdline", "processcommandline": "cmdline", "scriptblocktext": "message",
    "parentimage": "parent", "parentprocessname": "parent",
    "user": "\"user\"", "subjectusername": "\"user\"", "targetusername": "\"user\"", "accountname": "\"user\"",
    "targetfilename": "target", "targetobject": "target", "targetimage": "target", "objectname": "target",
    "sharename": "target", "taskname": "target", "servicename": "target", "queryname": "target",
    "c-uri": "target", "cs-uri-stem": "target", "url": "target",
    "details": "cmdline", "imagepath": "cmdline", "taskcontent": "cmdline", "servicefilename": "cmdline",
    "destinationip": "dst_ip", "dst_ip": "dst_ip", "destinationport": "dst_port", "dst_port": "dst_port",
    "sourceip": "src_ip", "ipaddress": "src_ip", "src_ip": "src_ip", "c-ip": "src_ip", "sourceport": "src_port",
    "destinationhostname": "dst_host", "workstationname": "src_host", "computer": "host", "computername": "host",
    "hostname": "host",
    "logontype": "logon_type", "processguid": "process_guid", "parentprocessguid": "parent_guid",
    "logonid": "logon_id", "targetlogonid": "logon_id", "subjectlogonid": "logon_id",
    "memberename": "target_user", "membername": "target_user", "samaccountname": "target_user",
    "cs-method": "action", "sc-status": "status", "cs-user-agent": "message", "c-useragent": "message",
}
NUMERIC = {"logon_type", "dst_port", "src_port"}

CATEGORY = {
    "process_creation": "e.event_type IN ('sysmon:1','win:4688','audit:execve')",
    "network_connection": "e.event_type IN ('sysmon:3','audit:connect')",
    "file_event": "e.event_type IN ('sysmon:11','audit:write')",
    "file_creation": "e.event_type IN ('sysmon:11','audit:write')",
    "file_access": "e.event_type IN ('audit:read')",
    "registry_set": "e.event_type IN ('sysmon:13','sysmon:12','sysmon:14')",
    "registry_event": "e.event_type IN ('sysmon:12','sysmon:13','sysmon:14')",
    "registry_add": "e.event_type = 'sysmon:12'",
    "process_access": "e.event_type = 'sysmon:10'",
    "image_load": "e.event_type = 'sysmon:7'",
    "dns_query": "e.event_type = 'sysmon:22'",
    "dns": "e.event_type = 'sysmon:22'",
    "create_remote_thread": "e.event_type = 'sysmon:8'",
    "ps_script": "e.event_type = 'ps:4104'",
    "webserver": "e.event_type = 'web:req'",
    "proxy": "e.event_type = 'web:req'",
    "firewall": "e.event_type IN ('net:flow','zeek:conn')",
}
SERVICE = {
    "security": "e.event_type LIKE 'win:%'", "system": "e.event_type LIKE 'win:%'",
    "sysmon": "e.event_type LIKE 'sysmon:%'", "powershell": "e.event_type LIKE 'ps:%'",
    "auditd": "e.event_type LIKE 'audit:%'", "auth": "e.event_type LIKE 'auth:%'",
    "sshd": "e.event_type LIKE 'auth:%'", "syslog": "(e.event_type LIKE 'syslog:%' OR e.event_type LIKE 'auth:%')",
}
LEVEL = {"informational": 0.1, "low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}


def _q(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def _like_escape(s: str) -> str:
    return str(s).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _wild(v: str) -> str:
    """Sigma wildcards * ? -> LIKE pattern."""
    out = []
    for ch in str(v):
        if ch == "*":
            out.append("%")
        elif ch == "?":
            out.append("_")
        elif ch in "%_\\":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _field_expr(field: str) -> tuple[str, bool]:
    f = field.lower()
    if f == "eventid":
        return "eventid", False
    if f in FIELD_MAP:
        col = FIELD_MAP[f]
        return (f"e.{col}" if not col.startswith('"') else f"e.{col}"), col in NUMERIC
    # fallback: pull the value out of the unmapped-fields JSON by key suffix
    return (f"regexp_extract(coalesce(e.extra, ''), '\"(?:[^\"]*\\.)?{re.escape(field)}\": ?\"?([^\",}}]*)', 1)",
            False)


def _value_cond(col: str, numeric: bool, val, mods: list[str]) -> str:
    if val is None:
        return f"({col} IS NULL OR CAST({col} AS VARCHAR) = '')"
    if col == "eventid":
        return f"regexp_extract(e.event_type, ':(\\d+)$', 1) = {_q(str(val))}"
    if numeric and not mods and str(val).lstrip("-").isdigit():
        return f"{col} = {int(val)}"
    c = f"lower(CAST({col} AS VARCHAR))"
    v = str(val)
    if "re" in mods:
        flags = "(?i)" if "i" in mods else ""
        return f"regexp_matches(CAST({col} AS VARCHAR), {_q(flags + v)})"
    if "cidr" in mods:
        prefix = v.split("/")[0].rsplit(".", 1)[0] if "/" in v else v
        return f"CAST({col} AS VARCHAR) LIKE {_q(_like_escape(prefix) + '%')} ESCAPE '\\'"
    vals = [v]
    if "windash" in mods:
        vals = [v, v.replace("-", "/", 1)] if v.startswith("-") else [v, v.replace("/", "-", 1)]
    parts = []
    for x in vals:
        p = _wild(x.lower())
        if "contains" in mods:
            p = f"%{p}%"
        elif "startswith" in mods:
            p = f"{p}%"
        elif "endswith" in mods:
            p = f"%{p}"
        parts.append(f"{c} LIKE {_q(p)} ESCAPE '\\'")
    return "(" + " OR ".join(parts) + ")"


def _selection(sel) -> str:
    if isinstance(sel, list):
        if all(isinstance(x, dict) for x in sel):
            return "(" + " OR ".join(_selection(x) for x in sel) + ")"
        # keyword list: search the text columns
        return "(" + " OR ".join(
            f"lower(coalesce(e.cmdline,'') || ' ' || coalesce(e.message,'') || ' ' || coalesce(e.target,'')) "
            f"LIKE {_q('%' + _wild(str(k).lower()) + '%')} ESCAPE '\\'" for k in sel) + ")"
    if not isinstance(sel, dict):
        return "TRUE"
    conds = []
    for key, val in sel.items():
        field, *mods = key.split("|")
        col, numeric = _field_expr(field)
        vals = val if isinstance(val, list) else [val]
        if not vals:
            continue
        sub = [_value_cond(col, numeric, v, mods) for v in vals]
        conds.append("(" + (" AND " if "all" in mods else " OR ").join(sub) + ")")
    return "(" + " AND ".join(conds or ["TRUE"]) + ")"


_TOK = re.compile(r"\(|\)|\bnot\b|\band\b|\bor\b|\b(?:1|all) of [\w*]+|[\w*]+", re.I)


def _condition(cond: str, sels: dict[str, str]) -> str:
    out = []
    for tok in _TOK.findall(cond):
        low = tok.lower()
        if low in ("(", ")"):
            out.append(tok)
        elif low in ("and", "or", "not"):
            out.append(low.upper())
        elif " of " in low:
            q, pat = low.split(" of ")
            names = list(sels) if pat == "them" else [n for n in sels if re.fullmatch(pat.replace("*", ".*"), n.lower())]
            if not names:
                out.append("FALSE")
                continue
            out.append("(" + (" OR " if q == "1" else " AND ").join(sels[n] for n in names) + ")")
        else:
            out.append(sels.get(tok, "FALSE"))
    return " ".join(out)


def sigma_to_rule(doc: dict, source: str = "") -> dict | None:
    det = doc.get("detection") or {}
    cond = det.get("condition")
    if not cond:
        return None
    if isinstance(cond, list):
        cond = " or ".join(f"({c})" for c in cond)
    if "|" in str(cond):                                   # aggregations (count() by) not supported
        return None
    sels = {k: _selection(v) for k, v in det.items() if k not in ("condition", "timeframe")}
    where = [f"({_condition(cond, sels)})"]
    ls = doc.get("logsource") or {}
    if ls.get("category") in CATEGORY:
        where.append(CATEGORY[ls["category"]])
    elif ls.get("service") in SERVICE:
        where.append(SERVICE[ls["service"]])
    elif ls.get("product") == "linux":
        where.append("(e.event_type LIKE 'audit:%' OR e.event_type LIKE 'auth:%' OR e.event_type LIKE 'syslog:%')")
    elif ls.get("product") == "windows":
        where.append("(e.event_type LIKE 'win:%' OR e.event_type LIKE 'sysmon:%' OR e.event_type LIKE 'ps:%')")
    tags = [t.lower() for t in doc.get("tags") or []]
    techs = [t.split(".", 1)[1].upper() for t in tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]
    tactic = next((t.split(".", 1)[1].replace("_", " ").replace("-", " ").title() for t in tags
                   if t.startswith("attack.") and not re.fullmatch(r"attack\.[tgs]\d{4}(\.\d{3})?", t)), None)
    if tactic:
        tactic = tactic.replace("And", "and")
    sub = next((t for t in techs if "." in t), None)
    tech = (sub.split(".")[0] if sub else next(iter(techs), None))
    rid = "sigma_" + re.sub(r"\W+", "_", str(doc.get("id") or doc.get("title", "rule")))[:60]
    return {"id": rid, "title": doc.get("title", rid), "technique": tech, "sub_technique": sub,
            "tactic": tactic, "severity": LEVEL.get(str(doc.get("level", "medium")).lower(), 0.5),
            "kind": "sigma", "source": source,
            "sql": "SELECT e.* FROM events e WHERE " + " AND ".join(where)}


def load_sigma_dir(path: str) -> list[dict]:
    out = []
    for p in sorted(glob.glob(os.path.join(path, "**", "*.y*ml"), recursive=True)):
        try:
            with open(p, encoding="utf-8") as f:
                for doc in yaml.safe_load_all(f):
                    if isinstance(doc, dict) and doc.get("status") != "deprecated":
                        r = sigma_to_rule(doc, os.path.relpath(p, os.path.dirname(path)))
                        if r:
                            out.append(r)
        except Exception:
            continue
    return out
