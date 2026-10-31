"""Render generator events into real-world log formats and write them, counting lines.

Formats emitted (each exercises a different ingest path):
  windows/security.jsonl   evtx_dump-style JSON (Event.System / Event.EventData), Security + System channels
  windows/sysmon.jsonl     Winlogbeat/ECS-style JSON (winlog.event_data), Sysmon + PowerShell channels
  linux/auth.log           RFC3164 syslog, many hosts
  linux/<host>/audit.log   auditd, multi-line records grouped by serial
  linux/<host>/access.log  Apache combined
  network/firewall.csv     CSV with header
  network/dhcp.csv         Microsoft DHCP server log CSV
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from .world import FQDN

_MON = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


def _dt(ts: int) -> datetime:
    return datetime.fromtimestamp(ts / 1000, timezone.utc)


def iso_z(ts: int) -> str:
    return _dt(ts).strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts % 1000:03d}Z"


def _dumps(o) -> str:
    return json.dumps(o, separators=(",", ":"))


class Sink:
    """Owns every output file; emit() returns the evidence id 'file:line' of the first line written."""

    def __init__(self, root: str):
        self.root = root
        self.files: dict[str, object] = {}
        self.lines: dict[str, int] = {}
        self.bytes = 0
        self.rec = 0
        self.serial = 1000
        self.manifest: dict[str, dict] = {}

    def _fh(self, rel: str, header: str | None = None, host: str | None = None):
        fh = self.files.get(rel)
        if fh is None:
            path = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            fh = open(path, "w", encoding="utf-8", newline="\n", buffering=1 << 20)
            self.files[rel] = fh
            self.lines[rel] = 0
            if header:
                self._write(rel, header)
            if host:
                self.manifest[rel] = {"host": host}
        return fh

    def _write(self, rel: str, text: str) -> str:
        fh = self.files[rel]
        first = self.lines[rel] + 1
        fh.write(text + "\n")
        self.lines[rel] += text.count("\n") + 1
        self.bytes += len(text) + 1
        return f"{rel}:{first}"

    def close(self):
        for fh in self.files.values():
            fh.close()
        with open(os.path.join(self.root, "manifest.json"), "w") as f:
            json.dump({"timezone": "UTC", "files": self.manifest}, f, indent=1)

    # ------------------------------------------------------------ Windows
    def sec(self, ts: int, host: str, eid: int, data: dict, channel: str = "Security") -> str:
        rel = "windows/security.jsonl"
        self._fh(rel)
        self.rec += 1
        prov = "Microsoft-Windows-Security-Auditing" if channel == "Security" else "Service Control Manager"
        ev = {"Event": {"System": {"Provider": {"#attributes": {"Name": prov}}, "EventID": eid,
                                   "EventRecordID": self.rec, "Channel": channel,
                                   "Computer": f"{host}.{FQDN}",
                                   "TimeCreated": {"#attributes": {"SystemTime": iso_z(ts)}}},
                        "EventData": data}}
        return self._write(rel, _dumps(ev))

    def sysmon(self, ts: int, host: str, eid: int, data: dict, user: str | None = None,
               channel: str = "Microsoft-Windows-Sysmon/Operational") -> str:
        rel = "windows/sysmon.jsonl"
        self._fh(rel)
        self.rec += 1
        if channel.startswith("Microsoft-Windows-Sysmon"):
            data = {"UtcTime": iso_z(ts)[:-1].replace("T", " "), **data}
        wl = {"channel": channel, "event_id": eid, "computer_name": f"{host}.{FQDN}",
              "record_id": self.rec, "event_data": data}
        if user:
            wl["user"] = {"name": user, "domain": "CORP"}
        ev = {"@timestamp": iso_z(ts), "host": {"name": f"{host.lower()}.{FQDN}"},
              "event": {"code": str(eid), "provider": channel.split("/")[0]}, "winlog": wl}
        return self._write(rel, _dumps(ev))

    # ------------------------------------------------------------ Linux
    def auth(self, ts: int, host: str, prog: str, pid: int, msg: str) -> str:
        rel = "linux/auth.log"
        self._fh(rel)
        d = _dt(ts)
        return self._write(rel, f"{_MON[d.month - 1]} {d.day:2d} {d:%H:%M:%S} {host} {prog}[{pid}]: {msg}")

    def audit(self, ts: int, host: str, records: list[tuple[str, str]]) -> str:
        rel = f"linux/{host}/audit.log"
        self._fh(rel, host=host)
        self.serial += 1
        stamp = f"{ts // 1000}.{ts % 1000:03d}:{self.serial}"
        text = "\n".join(f"node={host} type={t} msg=audit({stamp}): {body}" for t, body in records)
        return self._write(rel, text)

    def web(self, ts: int, host: str, client: str, method: str, path: str, status: int, size: int,
            ua: str, ref: str = "-") -> str:
        rel = f"linux/{host}/access.log"
        self._fh(rel, host=host)
        d = _dt(ts)
        return self._write(rel, f'{client} - - [{d:%d}/{_MON[d.month - 1]}/{d:%Y:%H:%M:%S} +0000] '
                                f'"{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"')

    # ------------------------------------------------------------ network
    def fw(self, ts: int, src: str, sport: int, dst: str, dport: int, proto: str = "tcp",
           action: str = "allow", bout: int = 0, bin_: int = 0, rule: str = "default") -> str:
        rel = "network/firewall.csv"
        self._fh(rel, "timestamp,src_ip,src_port,dst_ip,dst_port,proto,action,bytes_sent,bytes_received,rule",
                 host="FW-01")
        d = _dt(ts)
        return self._write(rel, f"{d:%Y-%m-%d %H:%M:%S},{src},{sport},{dst},{dport},{proto},{action},"
                                f"{bout},{bin_},{rule}")

    def dhcp(self, ts: int, code: int, desc: str, ip: str, host: str, mac: str) -> str:
        rel = "network/dhcp.csv"
        self._fh(rel, "ID,Date,Time,Description,IP Address,Host Name,MAC Address", host="DC-01")
        d = _dt(ts)
        return self._write(rel, f"{code},{d:%m/%d/%y},{d:%H:%M:%S},{desc},{ip},{host}.{FQDN},{mac}")
