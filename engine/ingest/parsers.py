"""Format parsers. Each parser consumes (line_no, offset, text) tuples and yields
(line_no, offset, flat_record, raw_text). Records use the source's own field names
(flattened with dots); the Mapper turns them into normalized rows.

Parsers may also emit already-normalized keys (event_type, user, src_ip, ...).
"""
from __future__ import annotations

import csv
import io
import json
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Iterable, Iterator

try:
    import orjson as _oj

    def jloads(s):
        return _oj.loads(s)
except ImportError:                                             # pragma: no cover
    jloads = json.loads

Line = tuple[int, int, str]          # (line_no, byte_offset, text without newline)
Rec = tuple[int, int, dict, str]     # (line_no, offset, flat record, raw text)


# ====================================================================== helpers
def flatten(obj, prefix: str = "", out: dict | None = None) -> dict:
    if out is None:
        out = {}
    if not isinstance(obj, dict):
        out[prefix or "value"] = obj
        return out
    for k, v in obj.items():
        if k == "#attributes" and isinstance(v, dict):
            flatten(v, prefix, out)
            continue
        if k == "#text":
            out[prefix or "text"] = v
            continue
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            flatten(v, key, out)
        elif isinstance(v, list):
            if v and all(isinstance(x, dict) and ("Name" in x or "@Name" in x or "#attributes" in x) for x in v):
                # [{"Name": "X", "#text": "v"}] style Data arrays
                for x in v:
                    name = x.get("Name") or x.get("@Name") or (x.get("#attributes") or {}).get("Name")
                    if name:
                        out[f"{key}.{name}"] = x.get("#text", x.get("text", x.get("Value")))
            elif all(not isinstance(x, (dict, list)) for x in v):
                out[key] = ",".join("" if x is None else str(x) for x in v)
            else:
                out[key] = json.dumps(v)[:1000]
        else:
            out[key] = v
    return out


_KV_RE = re.compile(r'([A-Za-z_][\w.\-]*)=("(?:[^"\\]|\\.)*"|\'[^\']*\'|[^\s,;]*)')


def parse_kv(s: str) -> dict:
    out = {}
    for k, v in _KV_RE.findall(s):
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out[k] = v
    return out


# ====================================================================== JSON
def parse_jsonl(lines: Iterable[Line], ctx: dict) -> Iterator[Rec]:
    for n, off, text in lines:
        s = text.strip().rstrip(",")
        if not s or s in ("[", "]"):
            continue
        if s[0] != "{":
            yield n, off, None, text
            continue
        try:
            obj = jloads(s)
        except Exception:
            yield n, off, None, text
            continue
        yield n, off, _json_record(obj, ctx), text


def _json_record(obj: dict, ctx: dict) -> dict:
    flat = flatten(obj)
    # Splunk / Wazuh / Elastic exports that wrap a raw line: parse that line too
    for k in ("_raw", "result._raw", "full_log", "event.original"):
        rawline = flat.get(k)
        if isinstance(rawline, str) and rawline and not rawline.lstrip().startswith("{"):
            inner = parse_line_any(rawline, ctx)
            for ik, iv in inner.items():
                flat.setdefault(ik, iv)
            break
    return flat


def parse_json_stream(lines: Iterable[Line], ctx: dict) -> Iterator[Rec]:
    """Pretty-printed JSON objects or a JSON array spanning many lines."""
    buf: list[str] = []
    depth = 0
    in_str = esc = False
    start_n = start_off = 0
    for n, off, text in lines:
        for ch in text:
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                if depth == 0:
                    start_n, start_off, buf = n, off, []
                depth += 1
            elif ch == "}":
                depth -= 1
        if depth > 0 or buf:
            buf.append(text)
        if depth == 0 and buf:
            s = "\n".join(buf).strip().strip(",").lstrip("[").rstrip("]").strip().rstrip(",")
            buf = []
            try:
                obj = jloads(s)
                if isinstance(obj, dict):
                    yield start_n, start_off, _json_record(obj, ctx), s
            except Exception:
                yield start_n, start_off, None, s
        elif depth == 0 and not buf and text.strip().strip("[],"):
            yield n, off, None, text


# ====================================================================== delimited
def parse_csv(lines: Iterable[Line], ctx: dict) -> Iterator[Rec]:
    header = ctx.get("header")
    delim = ctx.get("delimiter", ",")
    waiting = bool(ctx.get("preamble"))
    for n, off, text in lines:
        if not text.strip():
            continue
        try:
            row = next(csv.reader([text], delimiter=delim))
        except Exception:
            yield n, off, None, text
            continue
        if header is None:
            header = [f"col{i}" for i in range(len(row))]
        if row == header:
            waiting = False
            continue
        if waiting:
            continue
        if len(row) != len(header):
            if len(row) < len(header):
                row += [""] * (len(header) - len(row))
            else:
                row = row[:len(header) - 1] + [delim.join(row[len(header) - 1:])]
        yield n, off, dict(zip(header, row)), text


def parse_w3c(lines: Iterable[Line], ctx: dict) -> Iterator[Rec]:
    """IIS / W3C extended log: '#Fields:' directive defines the columns (may change mid-file)."""
    fields = ctx.get("header")
    for n, off, text in lines:
        if text.startswith("#"):
            if text.startswith("#Fields:"):
                fields = text[8:].split()
            continue
        if not text.strip() or not fields:
            continue
        vals = text.split(" ")
        rec = {f: (None if v == "-" else v.replace("+", " ") if f.startswith("cs(") else v) for f, v in zip(fields, vals)}
        rec.setdefault("event_type", "web:req")
        yield n, off, rec, text


def parse_zeek(lines: Iterable[Line], ctx: dict) -> Iterator[Rec]:
    fields = ctx.get("header")
    path = ctx.get("zeek_path", "log")
    for n, off, text in lines:
        if text.startswith("#"):
            if text.startswith("#fields"):
                fields = text.split("\t")[1:]
            elif text.startswith("#path"):
                path = text.split("\t")[1].strip()
            continue
        if not fields or not text.strip():
            continue
        vals = text.split("\t")
        rec = {f: (None if v in ("-", "(empty)") else v) for f, v in zip(fields, vals)}
        rec["event_type"] = f"zeek:{path}"
        yield n, off, rec, text


# ====================================================================== syslog family
_RFC5424 = re.compile(r"^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|\[.*?\])\s?(.*)$")
_RFC3164 = re.compile(r"^(?:<(\d{1,3})>)?([A-Z][a-z]{2}\s+\d{1,2} \d\d:\d\d:\d\d(?:\.\d+)?)(?: \d{4})?\s+(\S+)\s+"
                      r"([^\s\[:]+)(?:\[(\d+)\])?:\s?(.*)$")
_ISOSYS = re.compile(r"^(?:<(\d{1,3})>)?(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s+(\S+)\s+"
                     r"([^\s\[:]+)(?:\[(\d+)\])?:\s?(.*)$")


def parse_syslog_line(text: str, ctx: dict) -> dict | None:
    m = _RFC5424.match(text)
    if m:
        pri, ts, host, prog, pid, msgid, sd, msg = m.groups()
        rec = {"ts": ts, "host": host, "program": prog, "syslog_pid": pid, "message": msg}
        if sd and sd != "-":
            rec.update(parse_kv(sd))
    else:
        m = _RFC3164.match(text) or _ISOSYS.match(text)
        if not m:
            return None
        pri, ts, host, prog, pid, msg = m.groups()
        rec = {"ts": ts, "host": host, "program": prog, "syslog_pid": pid, "message": msg}
    _enrich_message(rec, prog, msg or "", ctx)
    return rec


def _enrich_message(rec: dict, prog: str | None, msg: str, ctx: dict) -> None:
    mapper = ctx["mapper"]
    if "CEF:" in msg:
        rec.update(parse_cef_text(msg[msg.index("CEF:"):]))
        return
    if "LEEF:" in msg:
        rec.update(parse_leef_text(msg[msg.index("LEEF:"):]))
        return
    if prog and "audit" in prog.lower() and "msg=audit(" in msg:
        rec.update(_audit_fields(msg))
        return
    before = rec.get("event_type")
    mapper.apply_patterns(rec, prog, msg)
    if rec.get("event_type") == before and msg.count("=") >= 3:
        for k, v in parse_kv(msg).items():
            rec.setdefault(k, v)
    if not rec.get("event_type"):
        rec["event_type"] = f"syslog:{(prog or 'unknown').lower()}"


def parse_syslog(lines: Iterable[Line], ctx: dict) -> Iterator[Rec]:
    for n, off, text in lines:
        if not text.strip():
            continue
        rec = parse_syslog_line(text, ctx)
        yield n, off, rec, text


# ====================================================================== CEF / LEEF / KV
def _split_unescaped(s: str, sep: str, maxsplit: int) -> list[str]:
    out, cur, esc = [], [], False
    for ch in s:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == sep and len(out) < maxsplit:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


_CEF_KEY = re.compile(r"(?:^|(?<=\s))([A-Za-z0-9_.\[\]]+)=")


def _cef_ext(ext: str) -> dict:
    out = {}
    ms = list(_CEF_KEY.finditer(ext))
    for i, m in enumerate(ms):
        end = ms[i + 1].start() if i + 1 < len(ms) else len(ext)
        out[m.group(1)] = ext[m.end():end].strip().replace("\\=", "=").replace("\\\\", "\\")
    # CEF custom labels: cs1Label=Foo cs1=bar -> Foo=bar
    for k in list(out):
        if k.endswith("Label") and k[:-5] in out:
            out[out[k]] = out.pop(k[:-5])
            del out[k]
    return out


def parse_cef_text(s: str) -> dict:
    parts = _split_unescaped(s, "|", 7)
    if len(parts) < 8:
        return {"message": s}
    _, vendor, product, version, sig, name, sev, ext = parts
    rec = {"cef_vendor": vendor, "cef_product": product, "signature_id": sig, "rule": name, "severity": sev,
           "event_type": f"cef:{product.lower().replace(' ', '_')}:{sig}"}
    rec.update(_cef_ext(ext))
    return rec


def parse_leef_text(s: str) -> dict:
    parts = s.split("|", 5)
    if len(parts) < 6:
        return {"message": s}
    ver, vendor, product, pver, eid, rest = parts
    delim = "\t"
    if ver.startswith("LEEF:2") and "|" in rest:
        d, rest = rest.split("|", 1)
        delim = bytes(d[2:], "ascii").decode("unicode_escape") if d.startswith(("x", "0x", "\\x")) else (d or "\t")
    rec = {"leef_vendor": vendor, "leef_product": product, "signature_id": eid,
           "event_type": f"leef:{product.lower().replace(' ', '_')}:{eid}"}
    for item in rest.split(delim):
        if "=" in item:
            k, v = item.split("=", 1)
            rec[k.strip()] = v
    return rec


def parse_cef(lines, ctx):
    for n, off, text in lines:
        i = text.find("CEF:")
        if i < 0:
            yield n, off, None, text
            continue
        rec = parse_cef_text(text[i:])
        if i > 0:
            hdr = parse_syslog_line(text[:i] + "x: -", ctx) or {}
            for k in ("ts", "host"):
                if k in hdr:
                    rec.setdefault(k, hdr[k])
        yield n, off, rec, text


def parse_leef(lines, ctx):
    for n, off, text in lines:
        i = text.find("LEEF:")
        if i < 0:
            yield n, off, None, text
            continue
        rec = parse_leef_text(text[i:])
        if i > 0:
            hdr = parse_syslog_line(text[:i] + "x: -", ctx) or {}
            for k in ("ts", "host"):
                if k in hdr:
                    rec.setdefault(k, hdr[k])
        yield n, off, rec, text


def parse_kvlines(lines, ctx):
    for n, off, text in lines:
        if not text.strip():
            continue
        rec = parse_kv(text)
        if not rec:
            yield n, off, None, text
            continue
        # FortiGate style split date= time=
        if "date" in rec and "time" in rec and "ts" not in rec:
            rec["ts"] = f"{rec['date']} {rec['time']}"
        yield n, off, rec, text


# ====================================================================== auditd
_AUDIT_HDR = re.compile(r"(?:node=(\S+) )?type=(\S+) msg=audit\((\d+(?:\.\d+)?):(\d+)\):\s?(.*)$")
SYSCALLS = {"59": "execve", "322": "execve", "42": "connect", "43": "accept", "288": "accept", "49": "bind",
            "2": "open", "257": "open", "87": "unlink", "263": "unlink", "82": "rename", "264": "rename",
            "316": "rename", "90": "chmod", "268": "chmod", "92": "chown", "260": "chown", "105": "setuid",
            "101": "ptrace", "165": "mount", "175": "init_module", "313": "finit_module"}
UIDS = {"0": "root", "33": "www-data", "48": "apache", "65534": "nobody", "1": "daemon", "999": "systemd"}


def _unhex(v: str) -> str:
    if v.startswith('"') and v.endswith('"'):
        return v[1:-1]
    if len(v) >= 2 and len(v) % 2 == 0 and all(c in "0123456789ABCDEFabcdef" for c in v):
        try:
            return bytes.fromhex(v).decode("utf-8", "replace").replace("\x00", " ")
        except ValueError:
            return v
    return v


def _audit_fields(body: str) -> dict:
    out = {}
    m = re.search(r"msg='(.*)'", body)
    if m:
        out.update(parse_kv(m.group(1)))
        body = body[:m.start()]
    for k, v in re.findall(r'([A-Za-z_][\w-]*)=("(?:[^"\\]|\\.)*"|\S+)', body):
        out.setdefault(k, v.strip('"'))
    return out


def _sockaddr(saddr: str) -> tuple[str | None, int | None]:
    try:
        b = bytes.fromhex(saddr)
    except ValueError:
        return None, None
    fam = int.from_bytes(b[0:2], "little")
    if fam == 2 and len(b) >= 8:
        return ".".join(str(x) for x in b[4:8]), int.from_bytes(b[2:4], "big")
    if fam == 10 and len(b) >= 24:
        import ipaddress
        return str(ipaddress.IPv6Address(b[8:24])), int.from_bytes(b[2:4], "big")
    return None, None


def _audit_build(group: list[tuple[str, str, str, str]], pidmap: dict) -> dict:
    """group: list of (node, type, body, ts) for one serial."""
    rec: dict = {}
    node, ts = group[0][0], group[0][3]
    if node:
        rec["host"] = node
    rec["ts"] = ts
    args: dict[int, str] = {}
    paths = []
    rtypes = []
    for _, typ, body, _ in group:
        rtypes.append(typ)
        f = _audit_fields(body)
        if typ == "SYSCALL":
            rec.update({"syscall": f.get("syscall"), "success": f.get("success"), "pid": f.get("pid"),
                        "ppid": f.get("ppid"), "uid": f.get("uid"), "auid": f.get("auid"), "comm": f.get("comm"),
                        "exe": f.get("exe"), "audit_key": f.get("key"), "flags": f.get("flags"), "a1": f.get("a1"),
                        "a2": f.get("a2"), "UID": f.get("UID"), "AUID": f.get("AUID")})
        elif typ == "EXECVE":
            for k, v in f.items():
                if k[0] == "a" and k[1:].isdigit():
                    args[int(k[1:])] = _unhex(v) if not v.startswith('"') else v
        elif typ == "PATH":
            paths.append((f.get("nametype", ""), _unhex(f.get("name", ""))))
        elif typ == "SOCKADDR":
            ip, port = _sockaddr(f.get("saddr", ""))
            if ip:
                rec["dst_ip"], rec["dst_port"] = ip, port
            if "laddr" in body:
                m = re.search(r"laddr=(\S+) lport=(\d+)", body)
                if m:
                    rec["dst_ip"], rec["dst_port"] = m.group(1), m.group(2)
        elif typ == "CWD":
            rec["cwd"] = f.get("cwd")
        elif typ == "PROCTITLE":
            rec.setdefault("proctitle", _unhex(f.get("proctitle", "")))
        else:
            for k, v in f.items():
                rec.setdefault(k, v)
    if args:
        rec["cmdline"] = " ".join(args[i] for i in sorted(args))
    elif rec.get("proctitle"):
        rec["cmdline"] = rec["proctitle"]
    if paths:
        pick = next((p for t, p in paths if t not in ("PARENT",)), paths[-1][1])
        rec["target"] = pick
    uid = rec.get("auid") if rec.get("auid") not in (None, "4294967295", "-1") else rec.get("uid")
    name = rec.get("AUID") if uid == rec.get("auid") and rec.get("AUID") not in (None, "unset") else rec.get("UID")
    if uid is not None:
        rec["user"] = name or UIDS.get(uid, f"uid{uid}")
    if rec.get("exe"):
        rec["process"] = rec["exe"].strip('"')
    if rec.get("pid") and rec.get("process") and rec.get("syscall") in ("59", "322"):
        pidmap[rec["pid"]] = rec["process"]
    if rec.get("ppid") and rec["ppid"] in pidmap:
        rec["parent"] = pidmap[rec["ppid"]]
    sc = rec.get("syscall")
    if "SYSCALL" in rtypes:
        kind = SYSCALLS.get(sc, f"syscall_{sc}")
        if kind == "open":
            flags = (rec.get("flags") or "")
            key = (rec.get("audit_key") or "").lower()
            try:
                fbits = int((rec.get("a2") if sc == "257" else rec.get("a1")) or "0", 16)
            except ValueError:
                fbits = 0
            write = "WRONLY" in flags or "RDWR" in flags or "CREAT" in flags or "write" in key or (fbits & 0x43)
            kind = "write" if write else "read"
        rec["event_type"] = f"audit:{kind}"
    else:
        rec["event_type"] = f"audit:{rtypes[0].lower()}"
        if rec.get("acct"):
            rec["user"] = rec["acct"]
        if rec.get("res"):
            rec["action"] = "success" if rec["res"].startswith("succ") else "failure"
    for k in ("flags", "a1", "a2", "UID", "AUID", "auid", "proctitle", "exe"):
        rec.pop(k, None)
    return rec


def _audit_safe(group, pidmap):
    try:
        return _audit_build(group, pidmap)
    except Exception:
        return None


def parse_auditd(lines: Iterable[Line], ctx: dict) -> Iterator[Rec]:
    pidmap: dict[str, str] = {}
    cur_serial = None
    group: list = []
    first = (0, 0)
    raws: list[str] = []
    for n, off, text in lines:
        m = _AUDIT_HDR.search(text)
        if not m:
            if text.strip():
                yield n, off, None, text
            continue
        node, typ, ts, serial, body = m.groups()
        if serial != cur_serial and group:
            yield first[0], first[1], _audit_build(group, pidmap), "\n".join(raws)
            group, raws = [], []
        if not group:
            first = (n, off)
        cur_serial = serial
        group.append((node, typ, body, ts))
        raws.append(text)
        if typ == "EOE":
            yield first[0], first[1], _audit_build(group, pidmap), "\n".join(raws)
            group, raws, cur_serial = [], [], None
    if group:
        yield first[0], first[1], _audit_build(group, pidmap), "\n".join(raws)


# ====================================================================== web access logs
_APACHE = re.compile(r'^(?:(?P<vhost>\S+:\d+) )?(?P<src_ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
                     r'"(?P<action>[A-Z]+|-) ?(?P<target>\S*)(?: (?P<proto>[^"]*))?" (?P<status>\d{3}|-) '
                     r'(?P<bytes_out>\d+|-)(?: "(?P<referer>[^"]*)" "(?P<message>[^"]*)")?')


def parse_apache(lines, ctx):
    for n, off, text in lines:
        m = _APACHE.match(text)
        if not m:
            if text.strip():
                yield n, off, None, text
            continue
        rec = {k: v for k, v in m.groupdict().items() if v is not None}
        rec["event_type"] = "web:req"
        yield n, off, rec, text


# ====================================================================== Windows XML / EVTX
def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1]


def xml_event_to_flat(xml: str) -> dict | None:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    rec: dict = {}
    for sec in root:
        sname = _strip_ns(sec.tag)
        if sname == "System":
            for el in sec:
                t = _strip_ns(el.tag)
                if el.text and el.text.strip():
                    rec[f"System.{t}"] = el.text.strip()
                for ak, av in el.attrib.items():
                    rec[f"System.{t}.{_strip_ns(ak)}"] = av
        elif sname in ("EventData", "UserData"):
            for el in sec.iter():
                if el is sec:
                    continue
                name = el.attrib.get("Name")
                if name:
                    rec[f"EventData.{name}"] = el.text
                elif el.text and el.text.strip() and len(el) == 0:
                    rec[f"EventData.{_strip_ns(el.tag)}"] = el.text
        elif sname == "RenderingInfo":
            for el in sec:
                if _strip_ns(el.tag) == "Message" and el.text:
                    rec["RenderedMessage"] = el.text[:2000]
    return rec


_EVENT_OPEN = re.compile(r"<Event[\s>]")


def parse_xml_events(lines, ctx):
    buf: list[str] = []
    start = (0, 0)
    for n, off, text in lines:
        m = _EVENT_OPEN.search(text) if not buf else None
        if m:
            text = text[m.start():]
            start = (n, off)
        if buf or m:
            buf.append(text)
            if "</Event>" in text:
                blob = "\n".join(buf)
                blob = blob[: blob.index("</Event>") + 8]
                buf = []
                yield start[0], start[1], xml_event_to_flat(blob), blob


def iter_evtx(path: str) -> Iterator[Rec]:
    """EVTX: native evtx_dump if on PATH (fast), else python-evtx (slow but pure Python)."""
    exe = shutil.which("evtx_dump") or shutil.which("evtx_dump.exe")
    if exe:
        proc = subprocess.Popen([exe, "-o", "jsonl", path], stdout=subprocess.PIPE, text=True, encoding="utf-8",
                                errors="replace")
        for i, line in enumerate(proc.stdout, 1):
            try:
                obj = jloads(line)
            except Exception:
                continue
            flat = flatten(obj)
            rid = next((v for k, v in flat.items() if k.endswith("EventRecordID")), i)
            yield int(rid), -1, flat, line.rstrip("\n")
        proc.wait()
        return
    from Evtx.Evtx import Evtx                                   # python-evtx
    with Evtx(path) as log:
        for rec in log.records():
            try:
                xml = rec.xml()
            except Exception:
                continue
            yield rec.record_num(), -1, xml_event_to_flat(xml), xml


# ====================================================================== generic fallback
_TS_ANY = re.compile(r"(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?|"
                     r"[A-Z][a-z]{2}\s+\d{1,2} \d\d:\d\d:\d\d|\d{2}/[A-Z][a-z]{2}/\d{4}:\d\d:\d\d:\d\d [+-]\d{4}|"
                     r"\b1[5-9]\d{8}(?:\.\d+)?\b)")
_IP_ANY = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_line_any(text: str, ctx: dict) -> dict:
    """Best effort for a single unknown line: syslog -> CEF/LEEF -> kv -> timestamp + IPs."""
    rec = parse_syslog_line(text, ctx)
    if rec:
        return rec
    if "CEF:" in text:
        return parse_cef_text(text[text.index("CEF:"):])
    if "LEEF:" in text:
        return parse_leef_text(text[text.index("LEEF:"):])
    rec = {"message": text[:4000]}
    if text.count("=") >= 2:
        rec.update(parse_kv(text))
    m = _TS_ANY.search(text)
    if m and "ts" not in rec:
        rec["ts"] = m.group(1)
    if "src_ip" not in rec:
        ips = _IP_ANY.findall(text)
        if ips:
            rec["generic_ip1"] = ips[0]
            if len(ips) > 1:
                rec["generic_ip2"] = ips[1]
    ctx["mapper"].apply_patterns(rec, None, text)
    rec.setdefault("event_type", "generic")
    return rec


def parse_generic(lines, ctx):
    for n, off, text in lines:
        if text.strip():
            yield n, off, parse_line_any(text, ctx), text


PARSERS = {
    "jsonl": parse_jsonl, "json_stream": parse_json_stream, "csv": parse_csv, "tsv": parse_csv,
    "w3c": parse_w3c, "zeek": parse_zeek, "syslog": parse_syslog, "cef": parse_cef, "leef": parse_leef,
    "kv": parse_kvlines, "auditd": parse_auditd, "apache": parse_apache, "xml_events": parse_xml_events,
    "generic": parse_generic,
}
# Formats whose records never span lines and need no per-file state: safe to split into byte ranges.
SPLITTABLE = {"jsonl", "csv", "tsv", "zeek", "syslog", "cef", "leef", "kv", "apache", "generic"}


def sniff_csv_header(sample: list[str]) -> tuple[list[str] | None, str]:
    text = "\n".join(sample[:20])
    try:
        dialect = csv.Sniffer().sniff(text, delimiters=",\t;|")
        delim = dialect.delimiter
    except csv.Error:
        delim = "\t" if sample and sample[0].count("\t") > sample[0].count(",") else ","
    first = next(csv.reader(io.StringIO(sample[0]), delimiter=delim))
    try:
        has_header = csv.Sniffer().has_header(text)
    except csv.Error:
        has_header = True
    if any(c.replace(" ", "").replace("_", "").replace("-", "").replace("(", "").replace(")", "").isalpha()
           for c in first) and not any(_IP_ANY.fullmatch(c.strip()) for c in first):
        has_header = True
    return (first if has_header else None), delim
