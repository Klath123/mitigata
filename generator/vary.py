"""Variation mode: the same attacks, but with every name an attacker or a company could choose changed.

A detection that only matched our own tool names, paths, host names or timings fails here. Applied as one
regex pass over every written line (all formats), so evidence ids and ground truth stay exact.
"""
from __future__ import annotations

import random
import re

from .world import SERVERS, World

# attacker-chosen names that appear in the scenarios (and in decoys, which keeps them indistinguishable)
TOOLS = ["PsExec64.exe", "PsExec.exe", "PSEXESVC.exe", "PSEXESVC", "pd64.exe", "procdump64.exe", "procdump.exe",
         "svchst.exe", "ab12f.exe", "7za.exe", "rar.exe", "kyc.rar", "fin.7z", "ls.dmp", "d.dmp", "upd.ps1",
         "enc.ps1", "u.ps1", "s.ps1", "shell.php", "Invoice_Oct.docm", "cdn-update-sync.com", "mimikatz.exe",
         "mimikatz"]
# user-writable staging folders: an attacker picks any of them
STAGING = ["\\Windows\\Temp\\", "\\ProgramData\\", "\\Users\\Public\\"]
ALT_STAGING = ["\\PerfLogs\\", "\\Users\\Public\\Libraries\\", "\\ProgramData\\Microsoft\\Crypto\\",
               "\\Windows\\Tasks\\", "\\Recovery\\"]
SERVICE_ACCOUNTS = ["svc_admin", "svc_backup", "svc_report", "svc_sync", "svc_web", "helpdesk_sync"]
SOURCES = {  # --drop name -> predicate on the written file path
    "sysmon": lambda rel: rel == "windows/sysmon.jsonl",
    "security": lambda rel: rel == "windows/security.jsonl",
    "audit": lambda rel: rel.endswith("/audit.log"),
    "auth": lambda rel: rel == "linux/auth.log",
    "web": lambda rel: rel.endswith("/access.log"),
    "firewall": lambda rel: rel == "network/firewall.csv",
    "dhcp": lambda rel: rel == "network/dhcp.csv",
}


def _word(r: random.Random, n: int) -> str:
    return "".join(r.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(n))


class Variation:
    def __init__(self, w: World, seed: int, drop: list[str] = (), jitter: bool = True):
        r = random.Random(seed * 7919 + 17)
        self.seed, self.jitter_rng, self.jitter = seed, random.Random(seed), jitter
        bad = [d for d in drop if d not in SOURCES]
        if bad:
            raise ValueError(f"unknown --drop source {bad}; choose from {sorted(SOURCES)}")
        self.drop = [SOURCES[d] for d in drop]
        names: dict[str, str] = {}
        for t in TOOLS:
            stem, dot, ext = t.rpartition(".")
            names[t.lower()] = (_word(r, r.randint(4, 9)) + dot + ext) if dot else _word(r, 8).upper()
        # hosts: neutral names, so roles must come from behaviour, not from "DC" / "FS" in the name
        hosts = sorted(set(w.laptops) | set(SERVERS))
        for h in hosts:
            names[h.lower()] = f"{'SRV' if h in SERVERS else 'WKS'}-{r.randint(1000, 9999)}"
        for u in [x.name for x in w.users] + list(w.admins) + SERVICE_ACCOUNTS:
            names[u.lower()] = _word(r, 2) + "." + _word(r, r.randint(4, 7))
        self.names = names
        self._rx = re.compile(r"(?<![\w.\-])(?:" + "|".join(re.escape(k) for k in sorted(names, key=len, reverse=True))
                              + r")(?![\w\-])", re.I)
        alt = dict(zip((p.lower() for p in STAGING), r.sample(ALT_STAGING, len(STAGING))))
        # one pass each for plain paths and JSON-escaped paths, so replacements never chain
        self._paths = {}
        for a, b in alt.items():
            self._paths[a] = b
            self._paths[a.replace("\\", "\\\\")] = b.replace("\\", "\\\\")
        self._prx = re.compile("|".join(re.escape(k) for k in sorted(self._paths, key=len, reverse=True)), re.I)

    def _case(self, m: re.Match) -> str:
        s = m.group(0)
        new = self.names[s.lower()]
        return new.lower() if s.islower() else new

    def line(self, s: str) -> str:
        s = self._rx.sub(self._case, s)
        return self._prx.sub(lambda m: self._paths[m.group(0).lower()], s)

    def dropped(self, rel: str) -> bool:
        return any(p(rel) for p in self.drop)

    def stretch(self) -> float:
        """Per-attack time factor: the attacker may be twice as fast or three times slower."""
        return self.jitter_rng.uniform(0.5, 3.0) if self.jitter else 1.0


if __name__ == "__main__":                                   # self-check
    from .world import build_world
    v = Variation(build_world(1), 3, drop=["sysmon"])
    s = 'C:\\Windows\\Temp\\ab12f.exe on DC-01.corp.local by adm_ravi via PSEXESVC; dc-01 svc_admin2 PsExec64.exe'
    out = v.line(s)
    assert "ab12f" not in out and "DC-01" not in out and "dc-01" not in out and "PSEXESVC" not in out, out
    assert "adm_ravi" not in out and "svc_admin2" in out and "\\Windows\\Temp\\" not in out, out
    j = '{"Image":"C:\\\\Windows\\\\Temp\\\\ab12f.exe"}'
    assert "\\\\Windows\\\\Temp\\\\" not in v.line(j), v.line(j)
    assert v.dropped("windows/sysmon.jsonl") and not v.dropped("windows/security.jsonl")
    print("ok", out)
