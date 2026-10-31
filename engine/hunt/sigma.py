"""Minimal Sigma -> DuckDB SQL converter (no pySigma dependency).

Supports: logsource product/category/service mapping, selections as maps or lists of maps,
field modifiers contains/startswith/endswith/all/re/cidr/windash, null values, keyword lists,
and conditions with and/or/not, parentheses, '1 of x*', 'all of x*', '1 of them', 'all of them'.
Unknown fields fall back to a regex over the `extra` JSON column.
"""
from __future__ import annotations

import glob
import ipaddress
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
    "parentcommandline": "parent_cmdline", "originalfilename": "original_file_name", "hashes": "hashes",
    "hash": "hashes", "integritylevel": "integrity_level", "imageloaded": "image_loaded",
    "signed": "signed", "signaturestatus": "signed", "ticketencryptiontype": "ticket_encryption",
    "pipename": "target", "relativetargetname": "target", "payload": "message", "contextinfo": "message",
    "query": "target", "action": "action",           # category dns / firewall rules (any vendor)
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
    "dns_query": "e.event_type IN ('sysmon:22', 'dns:query', 'zeek:dns')",
    "dns": "e.event_type IN ('sysmon:22', 'dns:query', 'zeek:dns')",
    "create_remote_thread": "e.event_type = 'sysmon:8'",
    "ps_script": "e.event_type = 'ps:4104'",
    "webserver": "e.event_type = 'web:req'",
    "proxy": "e.event_type IN ('web:req', 'fw:web')",
    "firewall": "e.event_type IN ('net:flow', 'fw:flow', 'zeek:conn')",
    "pipe_created": "e.event_type IN ('sysmon:17','sysmon:18')",
    "driver_load": "e.event_type = 'sysmon:6'",
    "file_delete": "e.event_type IN ('sysmon:23','sysmon:26')",
    "registry_delete": "e.event_type = 'sysmon:12'",
    "create_stream_hash": "e.event_type = 'sysmon:15'",
    "wmi_event": "e.event_type IN ('sysmon:19','sysmon:20','sysmon:21')",
    "ps_module": "e.event_type = 'ps:4103'",
    "ps_classic_start": "e.event_type = 'ps:400'",
    "ps_classic_provider_start": "e.event_type = 'ps:600'",
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


# network devices (FortiGate, Zeek, Cisco...): Sigma uses the vendor's own field names; ours where we have the
# column, else the exact key in `extra` (where ingest keeps every unmapped vendor field)
NETWORK_PRODUCTS = {"fortigate", "fortios", "zeek", "cisco", "juniper", "huawei", "paloalto", "checkpoint"}
NETWORK_FIELD_MAP = {"action": "action", "user": '"user"', "srcip": "src_ip", "dstip": "dst_ip", "src_ip": "src_ip",
                     "dst_ip": "dst_ip", "srcport": "src_port", "dstport": "dst_port", "dst_port": "dst_port",
                     "id.orig_h": "src_ip", "id.resp_h": "dst_ip", "id.resp_p": "dst_port", "query": "target",
                     "qname": "target", "hostname": "dst_host", "url": "target", "msg": "message",
                     "devname": "host", "attack": "rule", "virus": "rule"}
_PRODUCT: list[str | None] = [None]   # ponytail: converter-wide product, pass explicitly if conversion goes parallel


def _field_expr(field: str) -> tuple[str, bool]:
    f = field.lower()
    if f == "eventid":
        return "eventid", False
    if _PRODUCT[0] in NETWORK_PRODUCTS:
        if f in NETWORK_FIELD_MAP:
            col = NETWORK_FIELD_MAP[f]
            return f"e.{col}", col in NUMERIC
        return f"json_extract_string(e.extra, '$.\"{field}\"')", False
    if f in FIELD_MAP:
        col = FIELD_MAP[f]
        return (f"e.{col}" if not col.startswith('"') else f"e.{col}"), col in NUMERIC
    # fallback: pull the value out of the unmapped-fields JSON by key suffix
    return (f"regexp_extract(coalesce(e.extra, ''), '\"(?:[^\"]*\\.)?{re.escape(field)}\": ?\"?([^\",}}]*)', 1)",
            False)


def _cidr(c: str, v: str) -> str:
    """Real network membership. IPv4: numeric range on the four octets. IPv6: first-hextet range for /<=16,
    else exact match on the leading hextets (logs write IPv6 compressed, so string prefixes are unsafe)."""
    try:
        net = ipaddress.ip_network(v.strip(), strict=False)
    except ValueError:
        return "FALSE"
    lo, hi = int(net.network_address), int(net.broadcast_address)
    if net.version == 4:
        n = ("(" + " + ".join(f"TRY_CAST(split_part({c}, '.', {i + 1}) AS BIGINT) * {256 ** (3 - i)}"
                              for i in range(4)) + ")")
        return f"(regexp_matches(coalesce({c}, ''), '^\\d+\\.\\d+\\.\\d+\\.\\d+$') AND {n} BETWEEN {lo} AND {hi})"
    if net.prefixlen <= 16:
        h = f"TRY_CAST(('0x' || nullif(split_part(lower({c}), ':', 1), '')) AS BIGINT)"
        return f"(position(':' IN coalesce({c}, '')) > 0 AND {h} BETWEEN {lo >> 112} AND {hi >> 112})"
    if net.prefixlen == 128:
        return f"(lower({c}) = {_q(str(net.network_address))})"
    k = net.prefixlen // 16                               # whole hextets only; partial ones widen the match
    head = ":".join(net.network_address.exploded.split(":")[:k])
    hx = "regexp_replace(" + f"lower({c})" + ", '(^|:)0+([0-9a-f])', '\\1\\2', 'g')"
    return f"({hx} LIKE {_q(_like_escape(':'.join(p.lstrip('0') or '0' for p in head.split(':'))) + ':%')} ESCAPE '\\')"


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
        return _cidr(f"CAST({col} AS VARCHAR)", v)
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


SUPPORTED_MODS = {"contains", "startswith", "endswith", "all", "re", "i", "cidr", "windash"}
_NET = "(e.event_type LIKE 'fw:%' OR e.event_type IN ('auth:success', 'auth:fail', 'net:flow', 'dns:query'))"
PRODUCTS = {"windows": "(e.event_type LIKE 'win:%' OR e.event_type LIKE 'sysmon:%' OR e.event_type LIKE 'ps:%')",
            "linux": "(e.event_type LIKE 'audit:%' OR e.event_type LIKE 'auth:%' OR e.event_type LIKE 'syslog:%')",
            "fortigate": _NET, "fortios": _NET, "paloalto": _NET, "checkpoint": _NET,
            "zeek": "e.event_type LIKE 'zeek:%'",
            "cisco": f"({_NET} OR e.event_type LIKE 'syslog:%')", "juniper": f"({_NET} OR e.event_type LIKE 'syslog:%')",
            "huawei": f"({_NET} OR e.event_type LIKE 'syslog:%')"}
# Sigma levels are tuned for alert queues, not for evidence chains: low/medium become weak signals
SIGMA_SEVERITY = {"informational": 0.05, "low": 0.15, "medium": 0.3, "high": 0.6, "critical": 0.8}


def _fields_and_mods(det: dict) -> tuple[set[str], set[str]]:
    fields, mods = set(), set()

    def walk(v):
        if isinstance(v, dict):
            for k, x in v.items():
                f, *m = str(k).split("|")
                if f:
                    fields.add(f.lower())
                mods.update(m)
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
    for k, v in det.items():
        if k not in ("condition", "timeframe"):
            walk(v)
    return fields, mods


def refusal(doc: dict) -> str | None:
    """Why this Sigma rule can't run faithfully on our schema (None = it can). Refused rules are reported,
    never silently turned into slow or wrong SQL."""
    det = doc.get("detection") or {}
    cond = det.get("condition")
    if doc.get("status") in ("deprecated", "unsupported"):
        return f"status {doc.get('status')}"
    if not cond:
        return "no condition"
    if "|" in str(cond) or doc.get("correlation"):
        return "aggregation/correlation (write it in the sequence DSL)"
    ls = doc.get("logsource") or {}
    prod, cat, svc = ls.get("product"), ls.get("category"), ls.get("service")
    if prod not in (None, *PRODUCTS):
        return f"product {prod} not ingested"
    if cat and cat not in CATEGORY:
        return f"category {cat} not mapped"
    if not cat and svc and svc not in SERVICE and prod not in NETWORK_PRODUCTS:
        return f"service {svc} not mapped"
    if not (cat or svc or prod):
        return "no logsource"
    fields, mods = _fields_and_mods(det)
    bad = sorted(mods - SUPPORTED_MODS)
    if bad:
        return f"modifier {bad[0]} not supported"
    unmapped = [] if prod in NETWORK_PRODUCTS else         sorted(f for f in fields if f not in FIELD_MAP and f != "eventid")
    if unmapped:
        return f"field {unmapped[0]} not mapped"
    return None


_UNIX_PATH = "starts_with(coalesce(e.process, ''), '/')"
# a category (process_creation...) spans OSes; the rule's product must still hold, or a Windows rule such as
# "Image does not contain a backslash" fires on every Linux process. Sysmon for Linux shares the sysmon:* ids,
# so the OS of a Sysmon event comes from its process path.
OS_GUARD = {"windows": f"(e.event_type NOT LIKE 'audit:%' AND NOT {_UNIX_PATH})",
            "linux": f"(e.event_type NOT LIKE 'win:%' AND e.event_type NOT LIKE 'ps:%' "
                     f"AND (e.event_type NOT LIKE 'sysmon:%' OR {_UNIX_PATH}))"}


def logsource_filter(doc: dict) -> str:
    ls = doc.get("logsource") or {}
    prod = ls.get("product")
    if prod in NETWORK_PRODUCTS and ls.get("category") not in CATEGORY:
        return PRODUCTS[prod]                    # service (event, traffic, utm...) is the vendor's own split
    if ls.get("category") in CATEGORY:
        f = CATEGORY[ls["category"]]
    elif ls.get("service") in SERVICE:
        f = SERVICE[ls["service"]]
    else:
        return PRODUCTS.get(prod, "TRUE")
    return f"({f}) AND {OS_GUARD[prod]}" if prod in OS_GUARD else f


def sigma_to_rule(doc: dict, source: str = "") -> dict | None:
    if refusal(doc):
        return None
    _PRODUCT[0] = (doc.get("logsource") or {}).get("product")
    det = doc.get("detection") or {}
    cond = det.get("condition")
    if isinstance(cond, list):
        cond = " or ".join(f"({c})" for c in cond)
    sels = {k: _selection(v) for k, v in det.items() if k not in ("condition", "timeframe")}
    where = [f"({_condition(cond, sels)})"]
    group = logsource_filter(doc)
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
            "tactic": tactic, "severity": SIGMA_SEVERITY.get(str(doc.get("level", "medium")).lower(), 0.3),
            "kind": "sigma", "source": source, "level": doc.get("level"),
            "product": (doc.get("logsource") or {}).get("product"),
            # run_rules filters the log source once per group and runs `match` against that subset
            "group": group, "match": where[0],
            "sql": "SELECT e.* FROM events e WHERE " + " AND ".join(where + [group])}


def load_sigma_dir(path: str, report: dict | None = None,
                   statuses=("stable", "test", "experimental")) -> list[dict]:
    """Every rule file under path; `report` collects {loaded, refused: {reason: n}, errors}."""
    out, refused, detail, errors = [], {}, {}, 0
    for p in sorted(glob.glob(os.path.join(path, "**", "*.y*ml"), recursive=True)):
        try:
            with open(p, encoding="utf-8") as f:
                docs = list(yaml.safe_load_all(f))
        except Exception:
            errors += 1
            continue
        for doc in docs:
            if not isinstance(doc, dict) or "detection" not in doc:
                continue
            why = refusal(doc) or (None if doc.get("status", "experimental") in statuses
                                   else f"status {doc.get('status')}")
            if why:
                key = re.sub(r" \S+ not", " * not", why) if " not " in why else why
                refused[key] = refused.get(key, 0) + 1
                detail[why] = detail.get(why, 0) + 1
                continue
            try:
                r = sigma_to_rule(doc, os.path.relpath(p, os.path.dirname(path)))
            except Exception:
                errors += 1
                continue
            if r:
                out.append(r)
    if report is not None:
        report.update({"loaded": len(out), "refused": dict(sorted(refused.items(), key=lambda x: -x[1])),
                       "top_refusals": dict(sorted(detail.items(), key=lambda x: -x[1])[:25]), "errors": errors})
    return out
