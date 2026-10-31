"""Event builders shared by noise and attacks.

Each builder returns a list of Ev; nothing is written until the generator merges every Ev
in time order and calls Ev.run(sink). An Ev with a `tag` records its evidence id in the
ground truth for that attack step.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .world import DOMAIN, SERVERS, World


@dataclass(order=True)
class Ev:
    ts: int
    meth: str = field(compare=False)
    args: tuple = field(compare=False)
    kw: dict = field(compare=False, default_factory=dict)
    tag: object = field(compare=False, default=None)

    def run(self, sink) -> str:
        return getattr(sink, self.meth)(self.ts, *self.args, **self.kw)


def tagged(evs: list[Ev], tag) -> list[Ev]:
    for e in evs:
        e.tag = tag
    return evs


def is_server(host: str) -> bool:
    return host in SERVERS


# ---------------------------------------------------------------- logons
def logon(w: World, ts: int, host: str, user: str, ltype: int, src_ip: str = "-", lid: str | None = None,
          admin: bool = False, workstation: str = "-", pkg: str = "NTLM") -> list[Ev]:
    lid = lid or w.logon_id()
    evs = [Ev(ts, "sec", (host, 4624, {
        "SubjectUserName": "-", "TargetUserName": user, "TargetDomainName": DOMAIN,
        "TargetLogonId": lid, "LogonType": ltype, "LogonProcessName": "NtLmSsp" if ltype == 3 else "User32",
        "AuthenticationPackageName": pkg, "WorkstationName": workstation, "IpAddress": src_ip,
        "IpPort": str(w.rng.randint(49152, 65535)) if src_ip != "-" else "-"}))]
    if admin:
        evs.append(Ev(ts + 1, "sec", (host, 4672, {
            "SubjectUserName": user, "SubjectDomainName": DOMAIN, "SubjectLogonId": lid,
            "PrivilegeList": "SeBackupPrivilege SeRestorePrivilege SeDebugPrivilege SeImpersonatePrivilege"})))
    return evs


def logon_fail(w: World, ts: int, host: str, user: str, ltype: int, src_ip: str = "-",
               workstation: str = "-") -> list[Ev]:
    return [Ev(ts, "sec", (host, 4625, {
        "SubjectUserName": "-", "TargetUserName": user, "TargetDomainName": DOMAIN, "LogonType": ltype,
        "Status": "0xc000006d", "SubStatus": "0xc000006a", "FailureReason": "%%2313",
        "WorkstationName": workstation, "IpAddress": src_ip, "IpPort": str(w.rng.randint(49152, 65535))}))]


def logoff(ts: int, host: str, user: str, lid: str) -> list[Ev]:
    return [Ev(ts, "sec", (host, 4634, {"TargetUserName": user, "TargetDomainName": DOMAIN,
                                         "TargetLogonId": lid}))]


def explicit_creds(ts: int, host: str, user: str, target_user: str, target_server: str) -> list[Ev]:
    return [Ev(ts, "sec", (host, 4648, {"SubjectUserName": user, "SubjectDomainName": DOMAIN,
                                         "TargetUserName": target_user, "TargetDomainName": DOMAIN,
                                         "TargetServerName": target_server}))]


def kerberos(ts: int, dc: str, user: str, service: str, src_ip: str) -> list[Ev]:
    return [Ev(ts, "sec", (dc, 4769, {"TargetUserName": f"{user}@{DOMAIN}", "ServiceName": service,
                                       "IpAddress": f"::ffff:{src_ip}", "TicketEncryptionType": "0x12",
                                       "Status": "0x0"}))]


def share(ts: int, host: str, user: str, src_ip: str, share_name: str, lid: str) -> list[Ev]:
    return [Ev(ts, "sec", (host, 5140, {"SubjectUserName": user, "SubjectDomainName": DOMAIN,
                                         "SubjectLogonId": lid, "IpAddress": src_ip,
                                         "ShareName": f"\\\\*\\{share_name}", "AccessMask": "0x1"}))]


# ---------------------------------------------------------------- processes
def proc(w: World, ts: int, host: str, user: str, image: str, cmd: str, parent_image: str,
         pguid: str, lid: str = "0x3e7", guid: str | None = None, parent_cmd: str = "") -> tuple[list[Ev], str]:
    """Process start: Sysmon 1 everywhere, plus Security 4688 on servers. Returns (events, guid)."""
    guid = guid or w.guid()
    pid = w.rng.randint(1000, 30000)
    evs = [Ev(ts, "sysmon", (host, 1, {
        "ProcessGuid": guid, "ProcessId": pid, "Image": image, "CommandLine": cmd,
        "CurrentDirectory": "C:\\Windows\\system32\\", "User": f"{DOMAIN}\\{user}", "LogonId": lid,
        "IntegrityLevel": "High" if user in ("SYSTEM",) else "Medium",
        "Hashes": f"SHA256={w.rng.getrandbits(256):064X}",
        "ParentProcessGuid": pguid, "ParentProcessId": w.rng.randint(400, 30000),
        "ParentImage": parent_image, "ParentCommandLine": parent_cmd or parent_image}))]
    if is_server(host):
        evs.append(Ev(ts, "sec", (host, 4688, {
            "SubjectUserName": user, "SubjectDomainName": DOMAIN, "SubjectLogonId": lid,
            "NewProcessId": hex(pid), "NewProcessName": image, "CommandLine": cmd,
            "ParentProcessName": parent_image, "TokenElevationType": "%%1936"})))
    return evs, guid


def netconn(w: World, ts: int, host: str, user: str, image: str, guid: str, src_ip: str, dst_ip: str,
            dport: int, dst_host: str = "") -> list[Ev]:
    return [Ev(ts, "sysmon", (host, 3, {
        "ProcessGuid": guid, "Image": image, "User": f"{DOMAIN}\\{user}", "Protocol": "tcp", "Initiated": "true",
        "SourceIp": src_ip, "SourceHostname": host, "SourcePort": w.rng.randint(49152, 65535),
        "DestinationIp": dst_ip, "DestinationHostname": dst_host, "DestinationPort": dport}))]


def dns(ts: int, host: str, user: str, image: str, guid: str, query: str, answer: str) -> list[Ev]:
    return [Ev(ts, "sysmon", (host, 22, {"ProcessGuid": guid, "Image": image, "User": f"{DOMAIN}\\{user}",
                                          "QueryName": query, "QueryStatus": "0",
                                          "QueryResults": f"::ffff:{answer};"}))]


def file_create(ts: int, host: str, user: str, image: str, guid: str, path: str) -> list[Ev]:
    return [Ev(ts, "sysmon", (host, 11, {"ProcessGuid": guid, "Image": image, "User": f"{DOMAIN}\\{user}",
                                          "TargetFilename": path}))]


def file_rename(ts: int, host: str, user: str, image: str, guid: str, old: str, new: str) -> list[Ev]:
    # Sysmon has no rename event; ransomware shows up as file create of the new name
    return [Ev(ts, "sysmon", (host, 11, {"ProcessGuid": guid, "Image": image, "User": f"{DOMAIN}\\{user}",
                                          "TargetFilename": new, "SourceFilename": old}))]


def reg_set(ts: int, host: str, user: str, image: str, guid: str, key: str, value: str) -> list[Ev]:
    return [Ev(ts, "sysmon", (host, 13, {"EventType": "SetValue", "ProcessGuid": guid, "Image": image,
                                          "User": f"{DOMAIN}\\{user}", "TargetObject": key, "Details": value}))]


def proc_access(ts: int, host: str, user: str, src_image: str, src_guid: str, tgt_image: str,
                tgt_guid: str, access: str = "0x1010") -> list[Ev]:
    return [Ev(ts, "sysmon", (host, 10, {"SourceProcessGuid": src_guid, "SourceImage": src_image,
                                          "SourceUser": f"{DOMAIN}\\{user}",
                                          "TargetProcessGuid": tgt_guid, "TargetImage": tgt_image,
                                          "GrantedAccess": access,
                                          "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|UNKNOWN"}))]


def ps_script(w: World, ts: int, host: str, user: str, text: str) -> list[Ev]:
    return [Ev(ts, "sysmon", (host, 4104, {"MessageNumber": 1, "MessageTotal": 1, "ScriptBlockText": text,
                                            "ScriptBlockId": w.guid()[1:-1], "Path": ""}),
               {"user": user, "channel": "Microsoft-Windows-PowerShell/Operational"})]


def service(ts: int, host: str, name: str, image: str, account: str = "LocalSystem") -> list[Ev]:
    return [Ev(ts, "sec", (host, 7045, {"ServiceName": name, "ImagePath": image,
                                         "ServiceType": "user mode service", "StartType": "demand start",
                                         "AccountName": account}), {"channel": "System"})]


def sched_task(ts: int, host: str, user: str, name: str, command: str, args: str, lid: str) -> list[Ev]:
    content = (f"<Task><Actions><Exec><Command>{command}</Command><Arguments>{args}</Arguments>"
               f"</Exec></Actions></Task>")
    return [Ev(ts, "sec", (host, 4698, {"SubjectUserName": user, "SubjectDomainName": DOMAIN,
                                         "SubjectLogonId": lid, "TaskName": name, "TaskContent": content}))]


def user_created(ts: int, host: str, by: str, new: str, lid: str) -> list[Ev]:
    return [Ev(ts, "sec", (host, 4720, {"SubjectUserName": by, "SubjectDomainName": DOMAIN,
                                         "SubjectLogonId": lid, "TargetUserName": new,
                                         "TargetDomainName": DOMAIN, "SamAccountName": new}))]


def group_add(ts: int, host: str, by: str, member: str, group: str, lid: str) -> list[Ev]:
    eid = 4732 if group in ("Administrators", "Backup Operators") else 4728
    return [Ev(ts, "sec", (host, eid, {"SubjectUserName": by, "SubjectDomainName": DOMAIN,
                                        "SubjectLogonId": lid, "TargetUserName": group,
                                        "TargetDomainName": DOMAIN,
                                        "MemberName": f"CN={member},CN=Users,DC=corp,DC=local"}))]


# ---------------------------------------------------------------- network / linux
def flow(w: World, ts: int, src: str, dst: str, dport: int, bout: int, bin_: int, action: str = "allow",
         rule: str = "default") -> list[Ev]:
    return [Ev(ts, "fw", (src, w.rng.randint(49152, 65535), dst, dport, "tcp", action, bout, bin_, rule))]


def auth(w: World, ts: int, host: str, prog: str, msg: str) -> list[Ev]:
    return [Ev(ts, "auth", (host, prog, w.rng.randint(1000, 60000), msg))]


def audit_exec(w: World, ts: int, host: str, uid: int, exe: str, argv: list[str], pid: int, ppid: int,
               auid: int = 4294967295) -> list[Ev]:
    args = " ".join(f'a{i}="{a}"' for i, a in enumerate(argv))
    comm = exe.rsplit("/", 1)[-1]
    return [Ev(ts, "audit", (host, [
        ("SYSCALL", f'arch=c000003e syscall=59 success=yes exit=0 ppid={ppid} pid={pid} auid={auid} '
                    f'uid={uid} gid={uid} euid={uid} tty=(none) ses=4294967295 comm="{comm}" exe="{exe}" key="exec"'),
        ("EXECVE", f"argc={len(argv)} {args}"),
        ("CWD", 'cwd="/var/www/html"')]))]


def audit_file(w: World, ts: int, host: str, uid: int, exe: str, path: str, pid: int, ppid: int,
               write: bool) -> list[Ev]:
    sc, key = (257, "write") if write else (257, "read")
    flags = "O_WRONLY|O_CREAT" if write else "O_RDONLY"
    comm = exe.rsplit("/", 1)[-1]
    return [Ev(ts, "audit", (host, [
        ("SYSCALL", f'arch=c000003e syscall={sc} success=yes exit=3 ppid={ppid} pid={pid} auid=4294967295 '
                    f'uid={uid} gid={uid} euid={uid} tty=(none) comm="{comm}" exe="{exe}" key="{key}" '
                    f'flags="{flags}"'),
        ("PATH", f'item=0 name="{path}" nametype={"CREATE" if write else "NORMAL"}')]))]


def audit_connect(w: World, ts: int, host: str, uid: int, exe: str, dst_ip: str, dport: int, pid: int,
                  ppid: int) -> list[Ev]:
    a, b, c, d = (int(x) for x in dst_ip.split("."))
    saddr = f"0200{dport:04X}{a:02X}{b:02X}{c:02X}{d:02X}0000000000000000"
    comm = exe.rsplit("/", 1)[-1]
    return [Ev(ts, "audit", (host, [
        ("SYSCALL", f'arch=c000003e syscall=42 success=yes exit=0 ppid={ppid} pid={pid} auid=4294967295 '
                    f'uid={uid} gid={uid} euid={uid} tty=(none) comm="{comm}" exe="{exe}" key="connect"'),
        ("SOCKADDR", f"saddr={saddr}")]))]
