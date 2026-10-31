"""Flat raw record -> normalized event row, driven by rules/mappings/fields.yaml."""
from __future__ import annotations

import ipaddress
import json
import os
import re
from datetime import datetime, timedelta, timezone

import yaml

from ..schema import FIELD_NAMES, INT_FIELDS

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_FIELDS = os.path.join(ROOT, "rules", "mappings", "fields.yaml")

INVALID = {"", "-", "--", "n/a", "na", "null", "(null)", "none", "nil", "unknown", "::", "-1"}
CANON_PASSTHRU = set(FIELD_NAMES) | {"event_id", "channel", "provider", "event_type", "action_type"}
_EXTRA_SKIP = {"raw", "_raw", "full_log"}
_MON = {m: i for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split(), 1)}


# ====================================================================== timestamps
_TS_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",          # apache
    "%Y-%m-%d %H:%M:%S%z",
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%y %H:%M:%S",             # MS DHCP
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",          # Windows Event Viewer CSV
    "%d/%m/%Y %H:%M:%S",
    "%d-%b-%Y %H:%M:%S",
    "%b %d %Y %H:%M:%S",
    "%a %b %d %H:%M:%S %Y",
    "%Y%m%d%H%M%S",
    "%Y-%m-%d-%H:%M:%S",
]
_SYSLOG_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)(?:\.(\d+))?")
_FRAC_RE = re.compile(r"(\.\d{6})\d+")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_TZ_KEYS = ("tz", "timezone", "tz_offset", "utc_offset")
_TZ_RE = re.compile(r"^(?:UTC|GMT)?\s*([+-])(\d\d):?(\d\d)$", re.I)
_TZ_CACHE: dict[str, timezone | None] = {}


def record_tz(v) -> timezone | None:
    """A record's own UTC offset (FortiGate tz="+0530", "+05:30", "UTC+05:30"), or None."""
    s = str(v).strip().strip('"')
    if s not in _TZ_CACHE:
        m = _TZ_RE.match(s)
        mins = int(m.group(2)) * 60 + int(m.group(3)) if m else None
        _TZ_CACHE[s] = (timezone(timedelta(minutes=mins if m.group(1) == "+" else -mins))
                        if m and mins <= 14 * 60 else None)
    return _TZ_CACHE[s]


def _epoch_num(x: float) -> int:
    if x > 1e17:
        return int(x / 1e6)
    if x > 1e14:
        return int(x / 1e3)
    if x > 1e11:
        return int(x)
    return int(x * 1000)


class TimeParser:
    """Per-file timestamp parser: remembers the format that worked last time."""

    def __init__(self, tz=timezone.utc, default_year: int | None = None, tz_declared: bool = False,
                 year_declared: bool = False):
        self.tz = tz
        self.year = default_year or datetime.now(timezone.utc).year
        self.last_fmt: str | None = None
        self.tz_declared, self.year_declared = tz_declared, year_declared
        self.assumed = False          # did the last parse rely on an assumed timezone or year?
        self.rec_tz: timezone | None = None

    def _aware_ms(self, d: datetime) -> int:
        if d.tzinfo is None:
            if self.rec_tz is not None:          # the record states its own offset: a fact, not an assumption
                d = d.replace(tzinfo=self.rec_tz)
            else:
                d = d.replace(tzinfo=self.tz)
                self.assumed = self.assumed or not self.tz_declared
        return int((d - _EPOCH).total_seconds() * 1000)

    def parse(self, v, rec_tz: timezone | None = None) -> int | None:
        self.assumed = False
        self.rec_tz = rec_tz
        if v is None:
            return None
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return _epoch_num(float(v)) if v > 0 else None
        s = str(v).strip().strip("[]\"")
        if not s:
            return None
        c0 = s[0]
        if c0.isdigit():
            if s.replace(".", "", 1).isdigit():
                try:
                    return _epoch_num(float(s))
                except ValueError:
                    return None
            if self.last_fmt is None and len(s) >= 10 and s[4] == "-":
                try:
                    s2 = s.replace("Z", "+00:00").replace("z", "+00:00")
                    if "." in s2:
                        s2 = _FRAC_RE.sub(r"\1", s2)
                    s2 = s2.replace(" +", "+").replace(" -", "-") if s2.count(":") > 2 else s2
                    return self._aware_ms(datetime.fromisoformat(s2))
                except ValueError:
                    pass
        else:
            m = _SYSLOG_RE.match(s)
            if m:
                mon = _MON.get(m.group(1).lower())
                if mon:
                    frac = m.group(6) or "0"
                    d = datetime(self.year, mon, int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)),
                                 int(frac[:6].ljust(6, "0")))
                    self.assumed = not self.year_declared          # syslog dates carry no year
                    return self._aware_ms(d)
        if self.last_fmt:
            try:
                return self._aware_ms(datetime.strptime(s, self.last_fmt))
            except ValueError:
                pass
        for fmt in _TS_FORMATS:
            try:
                d = datetime.strptime(s, fmt)
            except ValueError:
                continue
            self.last_fmt = fmt
            return self._aware_ms(d)
        return None


# ====================================================================== value normalizers
def domain_of(v) -> str | None:
    """Domain written inside an account string: DOMAIN/user (backslash) -> DOMAIN, user@corp.local -> CORP.LOCAL."""
    s = str(v).strip().strip('"')
    if "\\" in s:
        d = s.rsplit("\\", 1)[0].strip()
        return d.upper() or None
    if "@" in s and not s.upper().startswith("CN="):
        d = s.split("@", 1)[1].strip()
        return d.upper() or None
    return None


def norm_user(v) -> str | None:
    s = str(v).strip().strip('"')
    if not s or s.lower() in INVALID:
        return None
    if s.upper().startswith("CN="):
        s = s[3:].split(",", 1)[0]
    if "\\" in s:
        s = s.rsplit("\\", 1)[1]
    if "@" in s:
        s = s.split("@", 1)[0]
    s = s.lower()
    return s or None


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def norm_ip(v) -> tuple[str | None, str | None]:
    """Returns (ip, hostname_if_not_ip)."""
    s = str(v).strip().strip("[]\"")
    if not s or s.lower() in INVALID:
        return None, None
    if s.startswith("::ffff:"):
        s = s[7:]
    if "," in s:                                       # list of addresses: keep the first
        s = s.split(",", 1)[0].strip()
    if s.count(":") == 1 and "." in s:                 # 1.2.3.4:5555
        s = s.split(":", 1)[0]
    if _is_ip(s):
        return s, None                 # loopback / unspecified kept: analysis decides, ingest never deletes
    return None, s


def norm_host(v) -> str | None:
    s = str(v).strip().strip('"')
    if not s or s.lower() in INVALID or s in ("localhost", "127.0.0.1"):
        return None
    if _is_ip(s):
        return s
    if "\\" in s:
        s = s.rsplit("\\", 1)[1]
    return s.split(".", 1)[0].upper() or None


def norm_int(v) -> int | None:
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return int(v)
    s = str(v).strip()
    if not s or s.lower() in INVALID:
        return None
    try:
        if s[:2].lower() == "0x":
            return int(s, 16)
        return int(float(s))
    except ValueError:
        return None


# ====================================================================== mapper
class Mapper:
    def __init__(self, path: str = DEFAULT_FIELDS):
        with open(path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        self.leaf: dict[str, list[tuple[str, int]]] = {}
        self.paths: list[tuple[str, str, int]] = []
        for canon, aliases in cfg["fields"].items():
            for prio, a in enumerate(aliases):
                self._add(canon, str(a), prio)
        self.overrides = {et: {c: [str(a).lower() for a in al] for c, al in ov.items()}
                          for et, ov in (cfg.get("event_overrides") or {}).items()}
        self.channel_prefix = {k.lower(): v for k, v in (cfg.get("channel_prefix") or {}).items()}
        self.action_types = {str(k).lower(): v for k, v in (cfg.get("action_event_types") or {}).items()}
        self.logon_names = {str(k).lower(): int(v) for k, v in (cfg.get("logon_type_names") or {}).items()}
        self.patterns = []
        for p in cfg.get("message_patterns") or []:
            self.patterns.append((p.get("program"), re.compile(p["regex"]), p.get("event_type"), p.get("action")))
        self.semantics = self._compile_semantics(cfg.get("event_semantics") or [])
        self.suggested = []                       # unapproved suggestions (suggested.yaml), never confirmed types
        sp = os.path.join(os.path.dirname(path), "suggested.yaml")
        if os.path.exists(sp):
            with open(sp, encoding="utf-8") as f:
                sug = yaml.safe_load(f) or {}
            self.suggested = self._compile_semantics(sug.get("event_semantics") or [])
        self._plan: dict[tuple, tuple] = {}
        self._ov_plan: dict[tuple, dict] = {}
        self.domains: set[str] = set()

    @staticmethod
    def _compile_semantics(items: list) -> list:
        out = []
        for it in items:
            conds = []
            for c in it.get("all") or []:
                neg = "not_fields" in c
                fields = [f.lower() for f in (c.get("not_fields") if neg else c.get("fields")) or []]
                conds.append((fields, re.compile(c["matches"], re.I), neg))
            if conds:
                out.append({"name": it.get("name", it.get("event_type")), "event_type": it["event_type"],
                            "action": it.get("action"), "confidence": float(it.get("confidence", 1.0)),
                            "conds": conds})
        return out

    @staticmethod
    def _sem_match(rule: dict, view: dict[str, str]) -> bool:
        for fields, rx, neg in rule["conds"]:
            hit = any(rx.search(view[f]) for f in fields if f in view)
            if hit == neg:
                return False
        return True

    def _add(self, canon: str, alias: str, prio: int) -> None:
        a = alias.lower()
        if "." in a and not a.startswith("@"):
            self.paths.append((a, canon, prio))
        else:
            self.leaf.setdefault(a, []).append((canon, prio))

    # -------------------------------------------------------------- planning
    def _match(self, key: str) -> list[tuple[str, int]]:
        kl = key.lower()
        if kl in CANON_PASSTHRU:
            return [(kl, -1)]
        leaf = kl.rsplit(".", 1)[-1]
        out = list(self.leaf.get(leaf, ()))
        if leaf != kl:
            out += self.leaf.get(kl, [])
        for a, canon, prio in self.paths:
            if kl == a or kl.endswith("." + a):
                out.append((canon, prio))
        return out

    def plan(self, keys: tuple) -> tuple[dict[str, list[str]], list[str]]:
        p = self._plan.get(keys)
        if p is None:
            cand: dict[str, list[tuple[int, str]]] = {}
            unmapped = []
            for k in keys:
                m = self._match(k)
                if not m:
                    if k not in _EXTRA_SKIP:
                        unmapped.append(k)
                for canon, prio in m:
                    cand.setdefault(canon, []).append((prio, k))
            p = ({c: [k for _, k in sorted(v, key=lambda x: x[0])] for c, v in cand.items()}, unmapped)
            if len(self._plan) < 50_000:
                self._plan[keys] = p
        return p

    def _override_plan(self, keys: tuple, et: str) -> dict[str, list[str]]:
        ck = (keys, et)
        p = self._ov_plan.get(ck)
        if p is None:
            ov = self.overrides[et]
            lowmap: dict[str, str] = {}
            for k in keys:
                lowmap.setdefault(k.lower().rsplit(".", 1)[-1], k)
            p = {c: [lowmap[a] for a in al if a in lowmap] for c, al in ov.items()}
            self._ov_plan[ck] = p
        return p

    # -------------------------------------------------------------- message semantics
    def apply_patterns(self, rec: dict, program: str | None, msg: str) -> None:
        """Message patterns (fields.yaml): regex with named groups on free text; marks type_source=pattern."""
        prog = (program or "").lower()
        for want_prog, rx, et, action in self.patterns:
            if want_prog and want_prog not in prog:
                continue
            m = rx.search(msg)
            if m:
                for k, v in m.groupdict().items():
                    if v is not None:
                        rec[k] = v
                if et:
                    rec["event_type"] = et
                    rec["_type_source"] = "pattern"
                if action:
                    rec["action"] = action
                return

    # -------------------------------------------------------------- main
    def map(self, rec: dict, tp: TimeParser, file_host: str | None = None, fmt: str = "") -> tuple[dict, list[str]]:
        src_hint = rec.pop("_type_source", None)
        keys = tuple(rec)
        plan, unmapped = self.plan(keys)
        raw: dict[str, object] = {}
        for canon, ks in plan.items():
            for k in ks:
                v = rec[k]
                if v is None:
                    continue
                if isinstance(v, str) and v.strip().lower() in INVALID:
                    continue
                raw[canon] = v
                break

        # ---- event type
        et = raw.pop("event_type", None)
        type_source = (src_hint or "native") if et else None
        eid = raw.pop("event_id", None)
        chan = str(raw.pop("channel", "") or "")
        prov = str(raw.pop("provider", "") or "")
        act = raw.pop("action_type", None)
        if not et and eid is None and act is not None:
            et = self.action_types.get(str(act).strip().lower().replace(" ", "_"))
            type_source = "native" if et else None
        if not et:
            eidn = norm_int(eid) if eid is not None else None
            if eidn is not None:
                cp = (chan + " " + prov).lower()
                pref = self.channel_prefix.get("default", "win")
                for sub, pfx in self.channel_prefix.items():
                    if sub != "default" and sub in cp:
                        pref = pfx
                        break
                et = f"{pref}:{eidn}"
                type_source = "native"
        if et and et in self.overrides:
            for canon, ks in self._override_plan(keys, et).items():
                if not self.overrides[et][canon]:
                    raw.pop(canon, None)            # explicit empty list: clear the field
                    continue
                for k in ks:
                    v = rec[k]
                    if v is not None and not (isinstance(v, str) and v.strip().lower() in INVALID):
                        raw[canon] = v
                        break

        # ---- normalize
        row: dict[str, object] = {}
        # timestamp: separate Date + Time columns (DHCP, IIS) are combined
        tsv = raw.pop("ts", None)
        if tsv is not None and isinstance(tsv, str) and len(tsv) <= 12 and ":" in tsv and "-" not in tsv:
            date = next((rec[k] for k in keys if k.lower() in ("date", "date_utc", "logdate")), None)
            if date:
                tsv = f"{date} {tsv}"
        rtz = None
        if not tp.tz_declared:                   # a timezone declared in manifest.json still wins
            tzk = next((k for k in keys if k.lower() in _TZ_KEYS), None)
            rtz = record_tz(rec[tzk]) if tzk and rec[tzk] is not None else None
        row["ts"] = tp.parse(tsv, rtz) if tsv is not None else None
        if row["ts"] is not None:
            row["ts_assumed"] = tp.assumed

        user_domain = None
        if "user" in raw:
            orig = raw.pop("user")
            row["user"] = norm_user(orig)
            if row["user"]:
                row["user_original"] = str(orig).strip()[:256]
                user_domain = domain_of(orig)
        if "target_user" in raw:
            row["target_user"] = norm_user(raw.pop("target_user"))
        for f in ("src_ip", "dst_ip", "host_ip"):
            if f in raw:
                ip, name = norm_ip(raw.pop(f))
                row[f] = ip
                if name:
                    alt = {"src_ip": "src_host", "dst_ip": "dst_host", "host_ip": "host"}[f]
                    if alt not in raw and alt not in row:
                        raw[alt] = name
        if "host" in raw:
            hv = str(raw.pop("host"))
            if "." in hv and not _is_ip(hv.strip()):
                self.domains.add(hv.strip().split(".", 1)[1].lower())
            h = norm_host(hv)
            if h and _is_ip(h):
                row.setdefault("host_ip", h)
                h = None
            row["host"] = h
        if not row.get("host") and file_host:
            row["host"] = file_host
        if "src_host" in raw:
            row["src_host"] = norm_host(raw.pop("src_host"))
        if "dst_host" in raw:
            d = str(raw.pop("dst_host")).strip().rstrip(".")
            dl = d.lower()
            if "." not in d or any(dl.endswith("." + x) for x in self.domains):
                row["dst_host"] = norm_host(d)
            else:
                row["dst_host"] = dl
        if "domain" in raw:
            row["domain"] = str(raw.pop("domain")).upper()
        elif user_domain:
            row["domain"] = user_domain
        lt = raw.get("logon_type")
        if isinstance(lt, str) and not lt.strip().lstrip("-").isdigit():
            raw["logon_type"] = self.logon_names.get(lt.strip().lower().replace(" ", "").replace("_", ""))
        if "logon_id" in raw:
            row["logon_id"] = str(raw.pop("logon_id")).lower()
        for f in list(raw):
            v = raw.pop(f)
            if f in INT_FIELDS:
                row[f] = norm_int(v)
            elif f in ("cmdline", "message"):
                row[f] = str(v)[:8000]
            elif f in ("event_id", "channel", "provider", "action_type"):
                continue
            else:
                row[f] = v if isinstance(v, str) else (json.dumps(v) if isinstance(v, (dict, list)) else str(v))
        # semantics: unknown format, recognisable meaning (only when nothing better typed the record)
        if (not et or et == "generic" or et.startswith("syslog:")) and (self.semantics or self.suggested):
            view = {}
            for k, v in rec.items():
                if v is not None and not isinstance(v, (dict, list)):
                    view.setdefault(k.lower().rsplit(".", 1)[-1], str(v))
            for k in ("process", "cmdline", "target", "message", "user", "action", "status"):
                if row.get(k) is not None:
                    view.setdefault(k, str(row[k]))
            for rule in self.semantics:
                if self._sem_match(rule, view):
                    et, type_source = rule["event_type"], f"semantic:{rule['name']}"
                    if rule["action"] and not row.get("action"):
                        row["action"] = rule["action"]
                    break
            else:
                for rule in self.suggested:
                    if self._sem_match(rule, view):
                        row["suggested_event_type"] = rule["event_type"]
                        row["mapping_confidence"] = rule["confidence"]
                        break
        if not et:
            type_source = "inferred"
            if row.get("src_ip") and row.get("dst_ip") and (row.get("dst_port") is not None or row.get("bytes_out")):
                et = "net:flow"
            elif row.get("host_ip") and row.get("host") and not row.get("user") and not row.get("process"):
                et = "net:lease"            # host <-> IP assignment (DHCP lease, inventory, agent heartbeat)
            else:
                et = fmt or "generic"
                type_source = "unknown"
        row["event_type"] = et
        row["type_source"] = "unknown" if et == "generic" else type_source
        return row, unmapped
