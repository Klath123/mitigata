"""Synthetic company: users, hosts, IPs (with DHCP leases that move), accounts."""
from __future__ import annotations

import random
from dataclasses import dataclass, field

DOMAIN = "CORP"
FQDN = "corp.local"

FIRST = ("asha priya rahul vikram neha arjun kavya rohan meera anil sneha karan divya "
         "suresh pooja amit nisha rajesh lata manoj sana farhan ishaan tara dev ritu "
         "gopal leela yash zoya kabir mira nikhil anjali harsh payal varun sunita omkar "
         "rekha tushar bhavna irfan jaya kunal madhu naveen preeti qadir reena sahil "
         "tanvi uday vani wasim yamini zubin aditi bharat chitra dhruv esha gaurav").split()
DEPTS = ["HR", "FIN", "ENG", "SALES", "OPS", "LEGAL"]
DEPT_SHARE = {"HR": ("FS-01", "HR"), "FIN": ("FS-02", "Finance"), "ENG": ("FS-01", "Engineering"),
              "SALES": ("FS-03", "Sales"), "OPS": ("FS-03", "Ops"), "LEGAL": ("FS-02", "Legal")}

SERVERS = {  # name: (ip, role, os)
    "DC-01": ("10.0.1.10", "dc", "win"),
    "FS-01": ("10.0.1.21", "fileserver", "win"),
    "FS-02": ("10.0.1.22", "fileserver", "win"),
    "FS-03": ("10.0.1.23", "fileserver", "win"),
    "BK-01": ("10.0.1.30", "backup", "win"),
    "SQL-01": ("10.0.1.41", "database", "win"),
    "SQL-02": ("10.0.1.42", "database", "win"),
    "SSO-01": ("10.0.2.60", "gateway", "win"),
    "WEB-01": ("10.0.2.50", "web", "linux"),
    "APP-01": ("10.0.1.70", "app", "linux"),
}
FIREWALL = "FW-01"
PRIV_GROUPS = ["Domain Admins", "Enterprise Admins", "Administrators", "Backup Operators"]
NORMAL_GROUPS = ["HR-Staff", "Finance-Staff", "Eng-Staff", "Sales-Staff", "VPN-Users"]

# benign external destinations (CDN, M365, Google...) — repeated daily so never "new"
COMMON_EXT = [f"{a}.{b}.{c}.{d}" for a, b, c, d in [
    (13, 107, 42, 14), (20, 190, 128, 3), (40, 126, 32, 74), (52, 96, 88, 1), (104, 16, 85, 20),
    (142, 250, 183, 14), (142, 250, 77, 99), (151, 101, 1, 69), (172, 217, 160, 110),
    (23, 52, 14, 9), (35, 186, 224, 25), (34, 107, 221, 82), (185, 199, 108, 153),
    (199, 232, 46, 5), (54, 230, 159, 21), (99, 84, 160, 12), (162, 159, 136, 232)]]
CLOUD_UPLOAD = ["142.250.183.14", "13.107.42.14"]       # drive/onedrive: big uploads are normal here


@dataclass
class User:
    name: str
    dept: str
    laptop: str
    sid: str


@dataclass
class World:
    rng: random.Random
    users: list[User] = field(default_factory=list)
    laptops: dict[str, User] = field(default_factory=dict)       # laptop -> owner
    server_ip: dict[str, str] = field(default_factory=dict)
    admins: list[str] = field(default_factory=list)
    lease: dict[str, str] = field(default_factory=dict)          # laptop -> current ip
    lease_rev: dict[str, str] = field(default_factory=dict)      # ip -> laptop
    mac: dict[str, str] = field(default_factory=dict)
    pool: list[str] = field(default_factory=list)
    explorer_guid: dict[str, str] = field(default_factory=dict)  # host -> guid of explorer.exe
    scanners: list[str] = field(default_factory=list)

    # ------------------------------------------------------------ helpers
    def guid(self) -> str:
        h = f"{self.rng.getrandbits(128):032x}"
        return "{%s-%s-%s-%s-%s}" % (h[:8], h[8:12], h[12:16], h[16:20], h[20:])

    def logon_id(self) -> str:
        return hex(self.rng.randint(0x10000, 0xFFFFFFF))

    def ip_of(self, host: str) -> str:
        return self.server_ip.get(host) or self.lease[host]

    def renew_leases(self) -> list[tuple[str, str]]:
        """Re-shuffle ~30% of laptop IPs (a new day); returns (laptop, ip) assignments."""
        moved = self.rng.sample(sorted(self.laptops), k=max(1, len(self.laptops) * 3 // 10))
        free = [ip for ip in self.pool if ip not in self.lease_rev]
        for lp in moved:                      # release first so IPs get reused by other hosts
            old = self.lease.pop(lp)
            del self.lease_rev[old]
            free.append(old)
        self.rng.shuffle(free)
        out = []
        for lp in moved:
            ip = free.pop()
            self.lease[lp] = ip
            self.lease_rev[ip] = lp
            out.append((lp, ip))
        return out


def build_world(seed: int, n_users: int = 300) -> World:
    rng = random.Random(seed)
    w = World(rng=rng)
    w.server_ip = {h: v[0] for h, v in SERVERS.items()}
    names: list[str] = []
    i = 0
    while len(names) < n_users:
        base = FIRST[i % len(FIRST)]
        names.append(base if i < len(FIRST) else f"{base}{i // len(FIRST)}")
        i += 1
    counters = {d: 0 for d in DEPTS}
    for n in names:
        d = rng.choice(DEPTS)
        counters[d] += 1
        lp = f"{d}-{counters[d]:02d}"
        u = User(n, d, lp, f"S-1-5-21-1004336348-1177238915-682003330-{1100 + len(w.users)}")
        w.users.append(u)
        w.laptops[lp] = u
    # IT laptops + admins
    for k, adm in enumerate(["it_admin", "adm_ravi", "adm_meera"], 1):
        lp = f"IT-{k:02d}"
        u = User(adm, "IT", lp, f"S-1-5-21-1004336348-1177238915-682003330-{500 + k}")
        w.laptops[lp] = u
        w.admins.append(adm)
    w.pool = [f"10.0.{a}.{b}" for a in range(10, 14) for b in range(10, 250)]
    rng.shuffle(w.pool)
    for k, lp in enumerate(sorted(w.laptops)):
        ip = w.pool[k]
        w.lease[lp] = ip
        w.lease_rev[ip] = lp
        w.mac[lp] = "%012X" % rng.getrandbits(48)
    for h in list(w.laptops) + list(SERVERS):
        w.explorer_guid[h] = w.guid()
    w.scanners = [f"{rng.randint(45, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
                  for _ in range(40)]
    return w


def is_internal(ip: str) -> bool:
    return ip.startswith(("10.", "192.168.", "172.16."))
