"""Normal company activity, minute by minute, plus deliberate lookalikes (decoys).

Bulk activities scale with `scale` (to hit a target dataset size); behaviours of
specific people/systems (backups, admins, decoys) do not.
"""
from __future__ import annotations

import math
import zlib

from . import acts as A
from .acts import Ev
from .world import CLOUD_UPLOAD, COMMON_EXT, DEPT_SHARE, NORMAL_GROUPS, SERVERS, World

MIN = 60_000
HOUR = 60 * MIN

BENIGN_PAIRS = [
    ("C:\\Windows\\explorer.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", '"chrome.exe"', 30),
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
     "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", '"chrome.exe" --type=renderer', 40),
    ("C:\\Windows\\explorer.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
     '"OUTLOOK.EXE"', 6),
    ("C:\\Windows\\explorer.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
     '"WINWORD.EXE" /n "C:\\Users\\{u}\\Documents\\report.docx"', 8),
    ("C:\\Windows\\explorer.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
     '"EXCEL.EXE" "C:\\Users\\{u}\\Documents\\budget.xlsx"', 8),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "C:\\Windows\\splwow64.exe",
     "C:\\Windows\\splwow64.exe 12288", 2),
    ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\backgroundTaskHost.exe",
     '"backgroundTaskHost.exe" -ServerName:App.AppXmtcan0h2tfbfy7k9kmpeckvwkw8yy0x.mca', 10),
    ("C:\\Windows\\explorer.exe", "C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
     '"Teams.exe" --system-initiated', 6),
    ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\taskhostw.exe", "taskhostw.exe", 8),
    ("C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\notepad.exe",
     '"notepad.exe" C:\\Users\\{u}\\Desktop\\notes.txt', 3),
    ("C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\cmd.exe", '"cmd.exe"', 1),
    ("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\ipconfig.exe", "ipconfig /all", 1),
    ("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\ping.exe", "ping 10.0.1.22", 1),
    ("C:\\Windows\\explorer.exe", "C:\\Program Files\\7-Zip\\7z.exe",
     '"7z.exe" a C:\\Users\\{u}\\Documents\\photos.zip C:\\Users\\{u}\\Pictures', 0.3),
]
_PAIR_W = [p[3] for p in BENIGN_PAIRS]
SERVER_PROCS = [
    ("C:\\Windows\\System32\\services.exe", "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs -p"),
    ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", "wmiprvse.exe -Embedding"),
    ("C:\\Windows\\System32\\services.exe", "C:\\Windows\\System32\\msiexec.exe", "msiexec.exe /V"),
    ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\conhost.exe", "conhost.exe 0xffffffff -ForceV1"),
    ("C:\\Windows\\System32\\services.exe", "C:\\Program Files\\Microsoft SQL Server\\sqlservr.exe",
     "sqlservr.exe -sMSSQLSERVER"),
]
SPNS = ["cifs/FS-01", "cifs/FS-02", "cifs/FS-03", "MSSQLSvc/SQL-01:1433", "MSSQLSvc/SQL-02:1433",
        "HTTP/WEB-01", "ldap/DC-01", "krbtgt"]
URLS = ["/", "/login", "/products", "/static/app.js", "/static/style.css", "/api/quotes?sym=INFY",
        "/api/portfolio", "/images/logo.png", "/help", "/contact"]
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
       "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Version/17.5 Safari/605.1.15"]
LINUX_SVC = {"www-data": 33, "root": 0}


def poisson(rng, lam: float) -> int:
    if lam <= 0:
        return 0
    if lam > 30:
        return max(0, int(rng.gauss(lam, math.sqrt(lam)) + 0.5))
    L, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= L:
            return k
        k += 1


def rhythm(hour: int, weekday: int) -> float:
    if weekday >= 5:
        return 0.12
    if 9 <= hour < 18:
        return 1.0
    if hour in (8, 18):
        return 0.6
    if hour in (7, 19, 20):
        return 0.25
    return 0.05


class Noise:
    def __init__(self, w: World, start_ms: int, days: int, scale: float, fixed: bool = True):
        self.w, self.start, self.days, self.scale, self.fixed = w, start_ms, days, scale, fixed
        self.rng = w.rng
        self.lap = sorted(w.laptops)
        self.day_plan: dict[int, list] = {}
        self.cmd_guid: dict[str, str] = {}
        self.web_ppid = 812

    # ------------------------------------------------------------ helpers
    def _t(self, base: int) -> int:
        return base + self.rng.randrange(MIN)

    def _plan_day(self, day: int) -> None:
        """Schedule per-day discrete behaviours as {minute_of_day: [callable]}."""
        r = self.rng
        plan: dict[int, list] = {}

        def at(minute: int, fn):
            plan.setdefault(minute, []).append(fn)

        weekday = (day + 0) % 7       # dataset starts on a Monday
        if self.fixed:
            at(0 if day == 0 else 360, self._dhcp_day)
            if weekday < 5:
                for lp in self.lap:
                    at(r.randint(470, 580), lambda t, lp=lp: self._morning_logon(t, lp))
            for m in range(0, 1440, 10):
                at(m, self._stale_service)
            at(r.randint(60, 90), self._backups)
            for _ in range(r.randint(2, 4)):
                at(r.randint(540, 1020), self._psexec_decoy)
            for _ in range(r.randint(2, 5)):
                at(r.randint(540, 1020), self._admin_discovery)
            for host in ("FS-02", "FS-03"):
                at(r.randint(600, 700), lambda t, h=host: self._svc_backup_interactive(t, h))
            for _ in range(4):
                at(r.randint(540, 1020), self._admin_rdp)
            for _ in range(r.randint(2, 4)):
                at(r.randint(600, 1000), self._legit_upload)
            for m in range(r.randint(0, 120), 1440, r.randint(90, 180)):
                at(m, self._rdp_scanner)
            for m in range(r.randint(0, 60), 1440, r.randint(60, 150)):
                at(m, self._ssh_scanner)
            for _ in range(r.randint(1, 3)):
                at(r.randint(0, 1439), self._google_task)
            if weekday == 1:
                at(r.randint(600, 900), self._onboarding)
            if day == 1:
                at(r.randint(600, 900), self._backup_operator_change)
            for m in range(0, 1440, 60):
                at(m, self._linux_cron)
        self.day_plan = plan

    # ------------------------------------------------------------ main entry
    def tick(self, t: int) -> list[Ev]:
        off = t - self.start
        day, mod = divmod(off // MIN, 1440)
        if mod == 0:
            self._plan_day(day)
        hour = mod // 60
        weight = rhythm(hour, day % 7)
        out: list[Ev] = []
        for fn in self.day_plan.get(mod, ()):
            out.extend(fn(t))
        if self.fixed:
            out.extend(self._inventory(t, mod))
        s = self.scale
        if s > 0:
            r = self.rng
            for _ in range(poisson(r, 120 * weight * s)):
                out.extend(self._laptop_proc(t))
            for _ in range(poisson(r, 110 * weight * s)):
                out.extend(self._browse(t))
            for _ in range(poisson(r, 25 * weight * s)):
                out.extend(self._fileshare(t))
            for _ in range(poisson(r, 70 * max(weight, 0.2) * s)):
                out.extend(self._kerberos(t))
            for _ in range(poisson(r, 12 * s)):
                out.extend(self._server_proc(t))
            for _ in range(poisson(r, 45 * max(weight, 0.3) * s)):
                out.extend(self._web(t))
            for _ in range(poisson(r, 6 * max(weight, 0.3) * s)):
                out.extend(self._audit_noise(t))
        return out

    # ------------------------------------------------------------ bulk
    def _active_user(self):
        lp = self.rng.choice(self.lap)
        return lp, self.w.laptops[lp].name

    def _laptop_proc(self, t):
        w, r = self.w, self.rng
        lp, u = self._active_user()
        par, img, cmd, _ = r.choices(BENIGN_PAIRS, weights=_PAIR_W)[0]
        img = img.replace("{u}", u)
        cmd = cmd.replace("{u}", u)
        pguid = w.explorer_guid[lp] if par.endswith("explorer.exe") else w.guid()
        evs, _ = A.proc(w, self._t(t), lp, u, img, cmd, par, pguid, lid="0x" + format(zlib.crc32(lp.encode()) & 0xFFFFF, "x"))
        return evs

    def _browse(self, t):
        w, r = self.w, self.rng
        lp, u = self._active_user()
        dst = r.choice(COMMON_EXT)
        ts = self._t(t)
        evs = A.flow(w, ts, w.lease[lp], dst, 443, r.randint(800, 40_000), r.randint(2_000, 900_000))
        if r.random() < 0.25:
            g = w.guid()
            chrome = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
            evs += A.dns(ts - 40, lp, u, chrome, g, r.choice(["www.google.com", "outlook.office365.com",
                                                              "teams.microsoft.com", "www.nseindia.com"]), dst)
            evs += A.netconn(w, ts, lp, u, chrome, g, w.lease[lp], dst, 443)
        return evs

    def _fileshare(self, t):
        w, r = self.w, self.rng
        lp, u = self._active_user()
        user = w.laptops[lp]
        fs, sh = DEPT_SHARE.get(user.dept, ("FS-01", "Public"))
        ts, ip, lid = self._t(t), w.lease[lp], w.logon_id()
        return (A.kerberos(ts - 200, "DC-01", u, f"cifs/{fs}", ip)
                + A.logon(w, ts, fs, u, 3, ip, lid, workstation=lp, pkg="Kerberos")
                + A.share(ts + 30, fs, u, ip, sh, lid)
                + A.flow(w, ts, ip, w.server_ip[fs], 445, r.randint(2_000, 400_000), r.randint(10_000, 5_000_000)))

    def _kerberos(self, t):
        lp, u = self._active_user()
        return A.kerberos(self._t(t), "DC-01", u, self.rng.choice(SPNS), self.w.lease[lp])

    def _server_proc(self, t):
        w, r = self.w, self.rng
        host = r.choice([h for h, v in SERVERS.items() if v[2] == "win"])
        par, img, cmd = r.choice(SERVER_PROCS)
        evs, _ = A.proc(w, self._t(t), host, "SYSTEM", img, cmd, par, w.explorer_guid[host])
        return evs

    def _web(self, t):
        w, r = self.w, self.rng
        client = f"{r.randint(1, 223)}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"
        ts = self._t(t)
        if r.random() < 0.05:
            return [Ev(ts, "web", ("WEB-01", client, "POST", "/upload.php", 200, r.randint(200, 900),
                                   r.choice(UAS)))]
        return [Ev(ts, "web", ("WEB-01", client, "GET", r.choice(URLS), r.choice([200, 200, 200, 304, 404]),
                               r.randint(300, 90_000), r.choice(UAS)))]

    def _audit_noise(self, t):
        w, r = self.w, self.rng
        ts, pid = self._t(t), r.randint(2000, 60000)
        k = r.random()
        if k < 0.5:   # upload processing: php-fpm -> convert
            return A.audit_exec(w, ts, "WEB-01", 33, "/usr/bin/convert",
                                ["convert", f"/var/www/html/uploads/img{pid}.png", "-resize", "800x600",
                                 f"/var/www/html/uploads/t_img{pid}.png"], pid, self.web_ppid)
        if k < 0.8:   # the app itself reads its config: normal
            return A.audit_file(w, ts, "WEB-01", 33, "/usr/sbin/php-fpm8.1", "/var/www/html/config/app.ini",
                                self.web_ppid, 1, write=False)
        return A.audit_file(w, ts, "WEB-01", 33, "/usr/sbin/php-fpm8.1",
                            f"/var/www/html/uploads/img{pid}.png", self.web_ppid, 1, write=True)

    # ------------------------------------------------------------ fixed behaviours
    def _inventory(self, t, mod):
        """Signed inventory script, hourly on every laptop (same binary as attacks, different parent)."""
        w = self.w
        out = []
        minute = mod % 60
        for lp in self.lap:
            if (zlib.crc32(lp.encode()) % 60) != minute:
                continue
            ts = self._t(t)
            evs, g = A.proc(w, ts, lp, "SYSTEM", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                            "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\IT\\inventory.ps1",
                            "C:\\Windows\\System32\\svchost.exe", w.guid())
            out += evs
            out += A.ps_script(w, ts + 300, lp, "SYSTEM",
                               "Get-CimInstance Win32_OperatingSystem | Select Caption,Version; "
                               "Get-CimInstance Win32_LogicalDisk | Select DeviceID,FreeSpace")
        return out

    def _dhcp_day(self, t):
        w = self.w
        out = []
        if t == self.start:
            items, code, desc = sorted(w.lease.items()), 10, "Assign"
        else:
            items, code, desc = w.renew_leases(), 10, "Assign"
            # hosts that kept their IP renew
            moved = {lp for lp, _ in items}
            out += [Ev(self._t(t), "dhcp", (11, "Renew", ip, lp, w.mac[lp]))
                    for lp, ip in sorted(w.lease.items()) if lp not in moved]
        out += [Ev(t + i * 500, "dhcp", (code, desc, ip, lp, w.mac[lp])) for i, (lp, ip) in enumerate(items)]
        return out

    def _morning_logon(self, t, lp):
        w, r = self.w, self.rng
        u = w.laptops[lp].name
        ts = self._t(t)
        out = []
        if r.random() < 0.06:                                  # mistyped password, then success
            for k in range(r.randint(1, 3)):
                out += A.logon_fail(w, ts - 20_000 + k * 4000, lp, u, 2, "127.0.0.1", lp)
        out += A.logon(w, ts, lp, u, 2, "127.0.0.1", workstation=lp, pkg="Negotiate")
        return out

    def _stale_service(self, t):
        """svc_report on APP-01 keeps failing against SQL-01 with an expired password: never succeeds."""
        w = self.w
        return A.logon_fail(w, self._t(t), "SQL-01", "svc_report", 3, w.server_ip["APP-01"], "APP-01")

    def _backups(self, t):
        w, r = self.w, self.rng
        out = []
        ts = t
        bk = w.server_ip["BK-01"]
        for host in ("FS-01", "FS-02", "FS-03", "SQL-01", "SQL-02"):
            ts += r.randint(5, 20) * MIN
            lid = w.logon_id()
            out += A.logon(w, ts, host, "svc_backup", 3, bk, lid, admin=True, workstation="BK-01")
            evs, _ = A.proc(w, ts + 2000, host, "svc_backup", "C:\\Windows\\System32\\vssadmin.exe",
                            "vssadmin.exe list shadows", "C:\\Windows\\System32\\cmd.exe", w.guid(), lid)
            out += evs
            out += A.flow(w, ts + 5000, bk, w.server_ip[host], 445, r.randint(10**6, 10**7),
                          r.randint(5 * 10**8, 4 * 10**9))
        return out

    def _svc_backup_interactive(self, t, host):
        """An admin RDPs to a file server as svc_backup: its credentials now sit in that server's LSASS."""
        w = self.w
        return A.logon(w, self._t(t), host, "svc_backup", 10, w.lease["IT-01"], admin=True, workstation="IT-01")

    def _admin_rdp(self, t):
        w, r = self.w, self.rng
        adm = r.choice(["adm_ravi", "adm_meera"])
        src = "IT-02" if adm == "adm_ravi" else "IT-03"
        host = r.choice(["FS-01", "FS-02", "FS-03", "SQL-01", "DC-01", "BK-01"])
        ts = self._t(t)
        return (A.logon(w, ts, host, adm, 10, w.lease[src], admin=True, workstation=src)
                + A.flow(w, ts, w.lease[src], w.server_ip[host], 3389, r.randint(10**5, 10**7), r.randint(10**6, 10**8)))

    def _psexec_decoy(self, t):
        """it_admin patches a file server with PsExec: same tool as the attack, no link to it."""
        w, r = self.w, self.rng
        ts = self._t(t)
        tgt = r.choice(["FS-01", "FS-02", "FS-03"])
        src_ip = w.lease["IT-01"]
        lid = w.logon_id()
        out, _ = A.proc(w, ts, "IT-01", "it_admin", "C:\\Tools\\PsExec64.exe",
                        f"PsExec64.exe \\\\{tgt} -s cmd /c \"wuauclt /detectnow\"",
                        "C:\\Windows\\System32\\cmd.exe", w.guid())
        out += A.flow(w, ts + 500, src_ip, w.server_ip[tgt], 445, 300_000, 20_000)
        out += A.logon(w, ts + 900, tgt, "it_admin", 3, src_ip, lid, admin=True, workstation="IT-01")
        out += A.service(ts + 1500, tgt, "PSEXESVC", "%SystemRoot%\\PSEXESVC.exe")
        evs, g = A.proc(w, ts + 2000, tgt, "SYSTEM", "C:\\Windows\\PSEXESVC.exe", "C:\\Windows\\PSEXESVC.exe",
                        "C:\\Windows\\System32\\services.exe", w.explorer_guid[tgt], lid)
        out += evs
        evs, _ = A.proc(w, ts + 2500, tgt, "SYSTEM", "C:\\Windows\\System32\\cmd.exe",
                        'cmd /c "wuauclt /detectnow"', "C:\\Windows\\PSEXESVC.exe", g, lid)
        return A.tagged(out + evs, ("decoy", "it_admin_psexec"))

    def _admin_discovery(self, t):
        w, r = self.w, self.rng
        cmd = r.choice(['net user priya /domain', 'nltest /dclist:corp.local', 'net group "Eng-Staff" /domain',
                        'ipconfig /all'])
        img = "C:\\Windows\\System32\\" + ("nltest.exe" if cmd.startswith("nltest") else
                                           "ipconfig.exe" if cmd.startswith("ipconfig") else "net.exe")
        evs, _ = A.proc(w, self._t(t), "IT-01", "it_admin", img, cmd, "C:\\Windows\\System32\\cmd.exe", w.guid())
        return A.tagged(evs, ("decoy", "admin_discovery"))

    def _legit_upload(self, t):
        w, r = self.w, self.rng
        lp, u = self._active_user()
        return A.flow(w, self._t(t), w.lease[lp], r.choice(CLOUD_UPLOAD), 443, r.randint(10**8, 8 * 10**8),
                      r.randint(10**5, 10**6))

    def _rdp_scanner(self, t):
        """Internet noise against the RDP gateway: bursts of failures, never a success."""
        w, r = self.w, self.rng
        src = r.choice(w.scanners)
        ts = self._t(t)
        out = A.flow(w, ts, src, w.server_ip["SSO-01"], 3389, 2_000, 4_000)
        for k in range(r.randint(8, 30)):
            out += A.logon_fail(w, ts + k * r.randint(1500, 6000), "SSO-01",
                                r.choice(["administrator", "admin", "test", "user", "scanner"]), 3, src, "-")
        return A.tagged(out, ("decoy", "rdp_scanner"))

    def _ssh_scanner(self, t):
        w, r = self.w, self.rng
        src = r.choice(w.scanners)
        ts = self._t(t)
        out = []
        for k in range(r.randint(5, 25)):
            user = r.choice(["root", "admin", "ubuntu", "oracle", "test"])
            out += A.auth(w, ts + k * 2500, "WEB-01", "sshd",
                          f"Failed password for {'invalid user ' if user != 'root' else ''}{user} from {src} "
                          f"port {r.randint(30000, 65000)} ssh2")
        return out

    def _linux_cron(self, t):
        w, r = self.w, self.rng
        out = []
        for host in ("WEB-01", "APP-01"):
            ts = self._t(t)
            out += A.auth(w, ts, host, "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
            out += A.auth(w, ts + 1500, host, "CRON", "pam_unix(cron:session): session closed for user root")
        if r.random() < 0.3:
            ts = self._t(t)
            adm = r.choice(["adm_ravi", "adm_meera"])
            src = w.lease["IT-02" if adm == "adm_ravi" else "IT-03"]
            host = r.choice(["WEB-01", "APP-01"])
            out += A.auth(w, ts, host, "sshd", f"Accepted publickey for {adm} from {src} port "
                                               f"{r.randint(30000, 65000)} ssh2: RSA SHA256:abc")
            out += A.auth(w, ts + 9000, host, "sudo", f"{adm} : TTY=pts/0 ; PWD=/home/{adm} ; USER=root ; "
                                                     f"COMMAND=/usr/bin/systemctl restart nginx")
        return out

    def _google_task(self, t):
        lp, _ = self._active_user()
        return A.sched_task(self._t(t), lp, "SYSTEM", "\\GoogleUpdateTaskMachineUA",
                            "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe", "/ua /installsource scheduler",
                            "0x3e7")

    def _onboarding(self, t):
        w, r = self.w, self.rng
        ts, lid = self._t(t), w.logon_id()
        new = f"newhire{r.randint(100, 999)}"
        return (A.user_created(ts, "DC-01", "it_admin", new, lid)
                + A.group_add(ts + 20_000, "DC-01", "it_admin", new, r.choice(NORMAL_GROUPS), lid))

    def _backup_operator_change(self, t):
        """Legit but privileged: adm_ravi adds svc_backup to Backup Operators (a T1098 lookalike)."""
        w = self.w
        return A.tagged(A.group_add(self._t(t), "DC-01", "adm_ravi", "svc_backup", "Backup Operators", w.logon_id()),
                        ("decoy", "backup_operator_change"))
