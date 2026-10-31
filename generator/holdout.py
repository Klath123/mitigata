"""Holdout scenarios: written from public intrusion-report patterns, NOT from rules/. Never tune rules on them.

D : "loader to Kerberoast"  LNK -> rundll32 DLL -> HTTPS beacon -> AdFind discovery -> Kerberoasting (RC4 4769)
    -> RDP to SQL-02 with the cracked service account -> DLL side-loading + task persistence -> slow DNS exfil
E : "backup server, Security log only"  valid account from the internet -> cmd discovery -> local admin account
    -> scheduled task from a writable folder -> share copy + service on SQL-01 -> backup catalog wiped -> log cleared
Semi-blind: the author has read rules/, so the truly blind numbers come from the public corpora (eval/blind.py).
"""
from __future__ import annotations

import base64

from . import acts as A
from .acts import Ev
from .attacks import CMD, MIN, SYS32, Attack
from .world import DOMAIN, World

HOUR = 60 * MIN


def scenario_d(w: World, aid: int, t0: int) -> Attack:
    r = w.rng
    at = Attack(w, aid, "D")
    v = r.choice(w.users)
    L, u, S = v.laptop, v.name, "SQL-02"
    svc = "svc_report"
    lip, sip, dc = w.lease[L], w.server_ip[S], "DC-01"
    C, xdom = at.ext_ip(), "cdn-telemetry-sync.net"
    lid = w.logon_id()
    dll = f"C:\\Users\\{u}\\AppData\\Local\\Temp\\note.dll"
    e1, rg = A.proc(w, t0, L, u, SYS32 + "rundll32.exe", f"rundll32.exe {dll},DllRegisterServer",
                    "C:\\Windows\\explorer.exe", w.explorer_guid[L], lid,
                    parent_cmd=f"C:\\Windows\\explorer.exe /select,C:\\Users\\{u}\\Downloads\\Q3_report.lnk")
    at.step("T1218", "T1218.011", "Defense Evasion", L, u, "Shortcut runs a DLL through rundll32", e1)
    beacon = []
    ts = t0 + 30_000
    for k in range(12):                                     # beacon every ~5 min (+-10% jitter) for an hour
        ts += r.randint(270_000, 330_000)
        beacon += A.netconn(w, ts, L, u, SYS32 + "rundll32.exe", rg, lip, C, 443)
        beacon += A.flow(w, ts, lip, C, 443, r.randint(800, 3000), r.randint(2000, 9000))
    at.step("T1071", "T1071.001", "Command and Control", L, u, f"rundll32 beacons to {C}:443", beacon)
    t = t0 + 20 * MIN
    e1, _ = A.proc(w, t, L, u, f"C:\\Users\\{u}\\AppData\\Local\\Temp\\af.exe",
                   'af.exe -f "(objectcategory=person)" -csv name samaccountname serviceprincipalname',
                   SYS32 + "rundll32.exe", rg, lid)
    at.step("T1087", "T1087.002", "Discovery", L, u, "AdFind lists domain accounts and their SPNs", e1)
    t = t0 + 24 * MIN
    spns = ["MSSQLSvc/SQL-01:1433", "MSSQLSvc/SQL-02:1433", "HTTP/intranet", "cifs/BK-01", "HTTP/reports",
            "MSSQLSvc/APP-01:1433", "ldap/DC-01", "HTTP/sso", "cifs/FS-03", "HOST/BK-01"]
    roast = []
    for k, spn in enumerate(spns):
        roast += [Ev(t + k * 1200, "sec", (dc, 4769, {"TargetUserName": f"{u}@{DOMAIN}", "ServiceName": spn,
                                                      "IpAddress": f"::ffff:{lip}", "TicketEncryptionType": "0x17",
                                                      "TicketOptions": "0x40810000", "Status": "0x0"}))]
    at.step("T1558", "T1558.003", "Credential Access", dc, u, "Kerberoasting: RC4 tickets for 10 SPNs in 12 s", roast)
    t = t0 + 3 * HOUR                                       # offline cracking takes a while
    slid = w.logon_id()
    at.step("T1021", "T1021.001", "Lateral Movement", S, svc, f"RDP {L} -> {S} with the cracked {svc} password",
            A.flow(w, t - 500, lip, sip, 3389, 900_000, 4_000_000)
            + A.logon(w, t, S, svc, 10, lip, slid, admin=True, workstation=L, pkg="Negotiate"))
    t += 4 * MIN
    exe, side = "C:\\ProgramData\\VMware\\vmtoolsd.exe", "C:\\ProgramData\\VMware\\vmtools.dll"
    e1, cg = A.proc(w, t, S, svc, CMD, f"cmd.exe /c copy \\\\{L}\\c$\\Users\\{u}\\AppData\\Local\\Temp\\note.dll {side}",
                    "C:\\Windows\\explorer.exe", w.explorer_guid[S], slid)
    e2, vg = A.proc(w, t + 60_000, S, svc, exe, f'"{exe}"', CMD, cg, slid)
    load = [Ev(t + 61_000, "sysmon", (S, 7, {"ProcessGuid": vg, "Image": exe, "ImageLoaded": side,
                                            "Signed": "false", "SignatureStatus": "Unavailable",
                                            "User": f"{DOMAIN}\\{svc}"}))]
    at.step("T1574", "T1574.002", "Persistence", S, svc, "Signed binary copied next to a planted DLL (side-loading)",
            e1 + A.file_create(t + 2000, S, svc, CMD, cg, side) + e2 + load)
    at.step("T1053", "T1053.005", "Persistence", S, svc, "Scheduled task restarts the side-loaded binary",
            A.sched_task(t + 90_000, S, svc, "\\VMware Tools Updater", exe, "", slid))
    exf = []
    t += 10 * MIN
    for k in range(240):                                    # ~2 days, one query every ~12 min
        ts = t + k * r.randint(9 * MIN, 15 * MIN)
        chunk = base64.b32encode(r.getrandbits(160).to_bytes(20, "big")).decode().rstrip("=").lower()
        exf += A.dns(ts, S, svc, exe, vg, f"{chunk}.{k:04x}.{xdom}", C)
    at.step("T1048", "T1048.003", "Exfiltration", S, svc, f"Data leaked slowly in DNS queries to {xdom}", exf)
    return at


def _p4688(ts, host, user, lid, image, cmd, parent):
    return [Ev(ts, "sec", (host, 4688, {"SubjectUserName": user, "SubjectDomainName": DOMAIN, "SubjectLogonId": lid,
                                        "NewProcessId": hex(4000 + ts % 60000), "NewProcessName": image,
                                        "CommandLine": cmd, "ParentProcessName": parent,
                                        "TokenElevationType": "%%1937"}))]


def scenario_e(w: World, aid: int, t0: int) -> Attack:
    r = w.rng
    at = Attack(w, aid, "E")
    B, Q, u = "BK-01", "SQL-01", "svc_backup"
    bip, qip = w.server_ip[B], w.server_ip[Q]
    X = at.ext_ip()
    lid = w.logon_id()
    at.step("T1078", "T1078.002", "Initial Access", B, u, f"Valid {u} credentials used from the internet ({X})",
            A.flow(w, t0 - 400, X, bip, 445, 3_000, 9_000)
            + A.logon(w, t0, B, u, 3, X, lid, admin=True, workstation="DESKTOP-7Q2M", pkg="NTLM"))
    t = t0 + 2 * MIN
    disc = []
    for k, c in enumerate(["whoami /all", 'net group "Domain Admins" /domain', "net view \\\\SQL-01",
                           "quser", "ipconfig /all"]):
        disc += _p4688(t + k * 9000, B, u, lid, CMD, f"cmd.exe /c {c}", SYS32 + "services.exe")
    at.step("T1033", None, "Discovery", B, u, "Hands-on-keyboard discovery through cmd", disc)
    t = t0 + 6 * MIN
    at.step("T1136", "T1136.001", "Persistence", B, u, "Local account 'support' created and made admin",
            _p4688(t, B, u, lid, SYS32 + "net.exe", "net user support P@ssw0rd2026! /add", CMD)
            + A.user_created(t + 500, B, u, "support", lid)
            + A.group_add(t + 900, B, u, "support", "Administrators", lid))
    t = t0 + 8 * MIN
    at.step("T1053", "T1053.005", "Persistence", B, u, "Scheduled task runs a script from C:\\Windows\\Tasks",
            A.sched_task(t, B, u, "\\Microsoft\\Windows\\Sync\\Daily", "C:\\Windows\\Tasks\\sync.bat", "", lid))
    t = t0 + 15 * MIN
    qlid = w.logon_id()
    copy = [Ev(t + 2000, "sec", (Q, 5145, {"SubjectUserName": u, "SubjectDomainName": DOMAIN, "SubjectLogonId": qlid,
                                          "IpAddress": bip, "ShareName": "\\\\*\\ADMIN$",
                                          "RelativeTargetName": "wsync.exe", "AccessMask": "0x2"}))]
    at.step("T1021", "T1021.002", "Lateral Movement", Q, u, f"{B} copies wsync.exe to {Q} over ADMIN$",
            A.explicit_creds(t - 1000, B, u, u, Q) + A.flow(w, t - 500, bip, qip, 445, 1_400_000, 40_000)
            + A.logon(w, t, Q, u, 3, bip, qlid, admin=True, workstation=B) + copy)
    t += 60_000
    at.step("T1543", "T1543.003", "Persistence", Q, u, "Service 'WinSyncSvc' runs the copied binary",
            A.service(t, Q, "WinSyncSvc", "C:\\Windows\\wsync.exe")
            + _p4688(t + 3000, Q, "SYSTEM", "0x3e7", "C:\\Windows\\wsync.exe", "C:\\Windows\\wsync.exe",
                     SYS32 + "services.exe"))
    t = t0 + 40 * MIN
    at.step("T1490", None, "Impact", Q, u, "Backup catalog deleted and boot recovery disabled",
            _p4688(t, Q, "SYSTEM", "0x3e7", SYS32 + "wbadmin.exe", "wbadmin delete catalog -quiet",
                   "C:\\Windows\\wsync.exe")
            + _p4688(t + 4000, Q, "SYSTEM", "0x3e7", SYS32 + "bcdedit.exe",
                     "bcdedit /set {default} recoveryenabled No", "C:\\Windows\\wsync.exe"))
    t += 2 * MIN
    at.step("T1070", "T1070.001", "Defense Evasion", Q, u, "Security log cleared",
            [Ev(t, "sec", (Q, 1102, {"SubjectUserName": u, "SubjectDomainName": DOMAIN, "SubjectLogonId": qlid}))])
    return at


HOLDOUT = {"D": scenario_d, "E": scenario_e}
