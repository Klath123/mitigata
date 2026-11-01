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
    "T1562": ("Impair Defenses", ["Defense Evasion"]),
    "T1562.001": ("Disable or Modify Tools", ["Defense Evasion"]),
    "T1569": ("System Services", ["Execution"]),
    "T1569.002": ("Service Execution", ["Execution"]),
}


# ATT&CK v18+ split Defense Evasion into Stealth and Defense Impairment; the kill chain (schema.TACTICS) and every
# rule, dataset and tool label older than that use Defense Evasion, so both map back onto it
RENAMED = {"Stealth": "Defense Evasion", "Defense Impairment": "Defense Evasion"}


@lru_cache(maxsize=1)
def table() -> dict[str, tuple[str, list[str]]]:
    path = os.environ.get("ATTACK_STIX") or os.path.join(ROOT, "rules", "attack", "enterprise-attack.json")
    if not os.path.exists(path):
        return BUILTIN
    try:
        with open(path, encoding="utf-8") as f:
            bundle = json.load(f)
        out = dict(BUILTIN)
        objs = [o for o in bundle.get("objects", []) if o.get("type") == "attack-pattern" and not o.get("revoked")]
        # live techniques win over deprecated ones; deprecated ones still label old rules and old datasets
        for o in sorted(objs, key=lambda o: not o.get("x_mitre_deprecated")):
            ext = next((r["external_id"] for r in o.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), None)
            if ext:
                tactics = list(dict.fromkeys(
                    RENAMED.get(t, t) for t in (p["phase_name"].replace("-", " ").title().replace("And", "and")
                                                for p in o.get("kill_chain_phases", [])
                                                if p.get("kill_chain_name") == "mitre-attack")))
                if tactics or ext not in out:
                    out[ext] = (o.get("name", ext), tactics)
        return out
    except Exception:
        return BUILTIN


# ATT&CK v18 retired the Impair Defenses family into Defense Impairment; used when the bundle is not installed
REVOKED_FALLBACK = {"T1562": "T1685", "T1562.001": "T1685", "T1562.002": "T1685.001", "T1562.004": "T1686",
                    "T1562.007": "T1686.001", "T1562.008": "T1685.002", "T1562.012": "T1685.004",
                    "T1562.013": "T1686.002", "T1070.001": "T1685.005", "T1070.002": "T1685.006"}


@lru_cache(maxsize=1)
def revoked() -> dict[str, str]:
    """Retired technique id -> the id MITRE replaced it with (the bundle's revoked-by links, chains followed)."""
    path = os.environ.get("ATTACK_STIX") or os.path.join(ROOT, "rules", "attack", "enterprise-attack.json")
    out = dict(REVOKED_FALLBACK)
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                objs = json.load(f).get("objects", [])
            ext = {o["id"]: next((r["external_id"] for r in o.get("external_references", [])
                                  if r.get("source_name") == "mitre-attack"), None)
                   for o in objs if o.get("type") == "attack-pattern"}
            for o in objs:
                if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
                    a, b = ext.get(o["source_ref"]), ext.get(o["target_ref"])
                    if a and b and a != b:
                        out[a] = b
        except Exception:
            pass
    for k in list(out):                   # follow chains: a -> b -> c becomes a -> c
        seen = {k}
        while out[k] in out and out[k] not in seen:
            seen.add(out[k])
            out[k] = out[out[k]]
    return out


def current(technique: str | None, sub_technique: str | None = None) -> tuple[str | None, str | None]:
    """(technique, sub-technique) with retired ids replaced; keeps the sub-technique under its own parent."""
    rv = revoked()
    sub = rv.get(sub_technique, sub_technique) if sub_technique else None
    tech = rv.get(technique, technique) if technique else None
    if sub:
        if "." in sub:
            tech = sub.split(".")[0]
        else:                             # the sub-technique was promoted to a technique of its own
            tech, sub = sub, None
    return tech, sub


def name(tid: str | None) -> str | None:
    if not tid:
        return None
    t = table().get(tid)
    return t[0] if t else None


def tactics(tid: str | None) -> list[str]:
    if not tid:
        return []
    for k in (tid, tid.split(".")[0]):
        t = table().get(k)
        if t and t[1]:
            return list(t[1])
    return []
