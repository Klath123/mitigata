"""ATT&CK technique names and tactics.

If MITRE's enterprise-attack.json (STIX 2.1) is present at rules/attack/enterprise-attack.json or
$ATTACK_STIX, names/tactics come from it; otherwise a built-in table covering every technique our rules emit.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BUILTIN = {
    "T1003": ("OS Credential Dumping", ["Credential Access"]),
    "T1003.001": ("LSASS Memory", ["Credential Access"]),
    "T1005": ("Data from Local System", ["Collection"]),
    "T1016": ("System Network Configuration Discovery", ["Discovery"]),
    "T1018": ("Remote System Discovery", ["Discovery"]),
    "T1021": ("Remote Services", ["Lateral Movement"]),
    "T1021.001": ("Remote Desktop Protocol", ["Lateral Movement"]),
    "T1021.002": ("SMB/Windows Admin Shares", ["Lateral Movement"]),
    "T1021.004": ("SSH", ["Lateral Movement"]),
    "T1021.006": ("Windows Remote Management", ["Lateral Movement"]),
    "T1033": ("System Owner/User Discovery", ["Discovery"]),
    "T1041": ("Exfiltration Over C2 Channel", ["Exfiltration"]),
    "T1047": ("Windows Management Instrumentation", ["Execution"]),
    "T1048": ("Exfiltration Over Alternative Protocol", ["Exfiltration"]),
    "T1049": ("System Network Connections Discovery", ["Discovery"]),
    "T1053": ("Scheduled Task/Job", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1053.003": ("Cron", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1053.005": ("Scheduled Task", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1057": ("Process Discovery", ["Discovery"]),
    "T1059": ("Command and Scripting Interpreter", ["Execution"]),
    "T1059.001": ("PowerShell", ["Execution"]),
    "T1059.003": ("Windows Command Shell", ["Execution"]),
    "T1059.004": ("Unix Shell", ["Execution"]),
    "T1070": ("Indicator Removal", ["Defense Evasion"]),
    "T1070.001": ("Clear Windows Event Logs", ["Defense Evasion"]),
    "T1071": ("Application Layer Protocol", ["Command and Control"]),
    "T1071.001": ("Web Protocols", ["Command and Control"]),
    "T1078": ("Valid Accounts", ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"]),
    "T1078.002": ("Domain Accounts", ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"]),
    "T1078.003": ("Local Accounts", ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"]),
    "T1082": ("System Information Discovery", ["Discovery"]),
    "T1083": ("File and Directory Discovery", ["Discovery"]),
    "T1087": ("Account Discovery", ["Discovery"]),
    "T1087.001": ("Local Account", ["Discovery"]),
    "T1087.002": ("Domain Account", ["Discovery"]),
    "T1095": ("Non-Application Layer Protocol", ["Command and Control"]),
    "T1098": ("Account Manipulation", ["Persistence", "Privilege Escalation"]),
    "T1098.004": ("SSH Authorized Keys", ["Persistence", "Privilege Escalation"]),
    "T1105": ("Ingress Tool Transfer", ["Command and Control"]),
    "T1110": ("Brute Force", ["Credential Access"]),
    "T1110.001": ("Password Guessing", ["Credential Access"]),
    "T1110.003": ("Password Spraying", ["Credential Access"]),
    "T1133": ("External Remote Services", ["Initial Access", "Persistence"]),
    "T1135": ("Network Share Discovery", ["Discovery"]),
    "T1136": ("Create Account", ["Persistence"]),
    "T1136.001": ("Local Account", ["Persistence"]),
    "T1136.002": ("Domain Account", ["Persistence"]),
    "T1190": ("Exploit Public-Facing Application", ["Initial Access"]),
    "T1204": ("User Execution", ["Execution"]),
    "T1204.002": ("Malicious File", ["Execution"]),
    "T1482": ("Domain Trust Discovery", ["Discovery"]),
    "T1486": ("Data Encrypted for Impact", ["Impact"]),
    "T1490": ("Inhibit System Recovery", ["Impact"]),
    "T1505": ("Server Software Component", ["Persistence"]),
    "T1505.003": ("Web Shell", ["Persistence"]),
    "T1543": ("Create or Modify System Process", ["Persistence", "Privilege Escalation"]),
    "T1543.002": ("Systemd Service", ["Persistence", "Privilege Escalation"]),
    "T1543.003": ("Windows Service", ["Persistence", "Privilege Escalation"]),
    "T1547": ("Boot or Logon Autostart Execution", ["Persistence", "Privilege Escalation"]),
    "T1547.001": ("Registry Run Keys / Startup Folder", ["Persistence", "Privilege Escalation"]),
    "T1552": ("Unsecured Credentials", ["Credential Access"]),
    "T1552.001": ("Credentials In Files", ["Credential Access"]),
    "T1560": ("Archive Collected Data", ["Collection"]),
    "T1560.001": ("Archive via Utility", ["Collection"]),
    "T1566": ("Phishing", ["Initial Access"]),
    "T1566.001": ("Spearphishing Attachment", ["Initial Access"]),
    "T1567": ("Exfiltration Over Web Service", ["Exfiltration"]),
    "T1569": ("System Services", ["Execution"]),
    "T1569.002": ("Service Execution", ["Execution"]),
}


@lru_cache(maxsize=1)
def table() -> dict[str, tuple[str, list[str]]]:
    path = os.environ.get("ATTACK_STIX") or os.path.join(ROOT, "rules", "attack", "enterprise-attack.json")
    if not os.path.exists(path):
        return BUILTIN
    try:
        with open(path, encoding="utf-8") as f:
            bundle = json.load(f)
        out = dict(BUILTIN)
        for o in bundle.get("objects", []):
            if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
                continue
            ext = next((r["external_id"] for r in o.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), None)
            if ext:
                tactics = [p["phase_name"].replace("-", " ").title().replace("And", "and")
                           for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
                out[ext] = (o.get("name", ext), tactics)
        return out
    except Exception:
        return BUILTIN


def name(tid: str | None) -> str | None:
    if not tid:
        return None
    t = table().get(tid)
    return t[0] if t else None


def tactics(tid: str | None) -> list[str]:
    if not tid:
        return []
    t = table().get(tid) or table().get(tid.split(".")[0])
    return list(t[1]) if t else []
