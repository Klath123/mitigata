def sub(p, pairs):
    s = open(p, encoding='utf-8').read()
    for a, b in pairs:
        assert a in s, (p, a[:70])
        s = s.replace(a, b)
    open(p, 'w', encoding='utf-8', newline='\n').write(s)

sub('engine/hunt/rules.py', [
('''HIT_COLS = ["src_file", "line", "ts", "host", "user", "src_ip",''',
 '''HIT_COLS = ["src_file", "line", "ts", "host", "user", "domain", "src_ip",'''),
('''  severity DOUBLE, hit_key VARCHAR, src_file VARCHAR, line BIGINT, ts BIGINT, host VARCHAR, "user" VARCHAR,''',
 '''  severity DOUBLE, hit_key VARCHAR, src_file VARCHAR, line BIGINT, ts BIGINT, host VARCHAR, "user" VARCHAR,
  domain VARCHAR,'''),
])

sub('engine/graph/build.py', [
('''@dataclass
class Node:''',
 '''def norm_domain(d: str | None) -> str | None:
    """CORP, corp.local, CORP.LOCAL -> CORP (NetBIOS and DNS forms of one domain compare equal)."""
    if not d:
        return None
    d = str(d).strip().upper()
    if not d or d in ("-", "NT AUTHORITY", "NT SERVICE", "WORKGROUP", "BUILTIN"):
        return None
    return d.split(".", 1)[0]


def account_key(user: str | None, domain: str | None, domains_of: dict[str, set[str]]) -> str | None:
    """Identity used for linking.
    domain known                          -> user@DOMAIN
    domain missing, name has one domain   -> that identity (e.g. a Linux log of a domain account)
    domain missing, name never had one    -> user
    domain missing, name has several      -> None: ambiguous, never linked by account
    """
    if not user or is_system_account(user):
        return None
    d = norm_domain(domain)
    if d:
        return f"{user}@{d}"
    known = domains_of.get(user) or set()
    if len(known) == 1:
        return f"{user}@{next(iter(known))}"
    return user if not known else None


@dataclass
class Node:'''),
('''        self.attribution: dict[str, str] = {}     # node -> reason it belongs to a non-flagged session''',
 '''        self.attribution: dict[str, str] = {}     # node -> reason it belongs to a non-flagged session
        self.domains_of: dict[str, set[str]] = defaultdict(set)   # account name -> domains it appears with
        for u, d in con.execute("""SELECT DISTINCT "user", domain FROM events
                                   WHERE "user" IS NOT NULL AND domain IS NOT NULL""").fetchall():
            nd = norm_domain(d)
            if nd:
                self.domains_of[u].add(nd)'''),
('''                if r.get("event_type") in ("win:4720", "win:4728", "win:4732", "win:4756", "account:create") \
                        and r.get("target_user"):
                    created_idx[r["target_user"]].append(k)
            for u in n.users:
                user_idx[u].append(k)''',
 '''                if r.get("event_type") in ("win:4720", "win:4728", "win:4732", "win:4756", "account:create") \
                        and r.get("target_user"):
                    ck = account_key(r["target_user"], r.get("domain"), self.domains_of)
                    if ck:
                        created_idx[ck].append(k)
            for ak in {account_key(r.get("user"), r.get("domain"), self.domains_of) for r in n.rows} - {None}:
                user_idx[ak].append(k)'''),
])
print("ok")
