"""Link weights (spec starting values) and noisy-OR combination."""
from __future__ import annotations

WEIGHTS = {
    "spawned": 1.0,             # Sysmon ParentProcessGuid = ProcessGuid
    "accessed": 0.95,           # Sysmon 10 SourceProcessGuid -> TargetProcessGuid
    "same_process": 0.95,       # two hits on the same process GUID
    "session": 0.9,             # same LogonId on the same host
    "logon_hop": 0.8,           # logon on B whose source IP was A's at that time
    "service_after_logon": 0.75,  # service/system activity right after a remote admin logon on that host
    "same_external_ip": 0.8,    # same internet IP in both hits
    "shared_ioc": 0.7,          # flagged hits sharing a specific artifact (C2 IP/domain, payload, malware name)
    "created_account_used": 0.8,  # account created/added in one hit acts in a later one
    "sent_bytes": 0.7,          # flow from the host to an IP the incident's process talked to
    "same_account": 0.6,        # same (non-system) account within 60 min, both meaningful hits
    "compromised_host": 0.5,    # system activity on a host the incident entered shortly before
    "reused_credential": 0.6,   # account exposed on a credential-theft host logs on elsewhere
    "same_account_weak": 0.35,  # same account, but one side is a low-severity hit
    "time_proximity": 0.3,      # same host, within 5 min, no other tie
}
SOLID = 0.7
POSSIBLE = 0.4


def noisy_or(weights) -> float:
    p = 1.0
    for w in weights:
        p *= 1.0 - w
    return 1.0 - p
