import duckdb

from engine.hunt.sigma import _cidr


def _match(ip, net):
    con = duckdb.connect()
    return con.execute(f"SELECT {_cidr('x', net)} FROM (SELECT ?::VARCHAR AS x)", [ip]).fetchone()[0] is True


def test_cidr_ipv4_is_real_network_membership():
    # the old prefix version turned 10.0.0.0/8 into LIKE '10.0.0%' and called 10.0.11.198 public
    assert _match("10.0.11.198", "10.0.0.0/8")
    assert _match("172.31.255.1", "172.16.0.0/12")
    assert not _match("172.32.0.1", "172.16.0.0/12")
    assert _match("192.168.200.3", "192.168.0.0/16")
    assert not _match("100.0.0.1", "10.0.0.0/8")
    assert not _match("110.1.1.1", "10.0.0.0/8")
    assert _match("127.0.0.1", "127.0.0.0/8")
    assert not _match("-", "10.0.0.0/8")
    assert not _match(None, "10.0.0.0/8")


def test_windows_rules_never_see_linux_processes():
    from engine.hunt.sigma import logsource_filter
    con = duckdb.connect()
    con.execute("CREATE TABLE ev (event_type VARCHAR, process VARCHAR)")
    con.executemany("INSERT INTO ev VALUES (?, ?)", [("sysmon:1", r"C:\Windows\x.exe"), ("audit:execve", "/usr/bin/id"),
                                                     ("sysmon:1", "/usr/bin/curl"), ("win:4688", r"C:\a.exe")])

    def seen(prod):
        f = logsource_filter({"logsource": {"product": prod, "category": "process_creation"}})
        return {p for (p,) in con.execute(f"SELECT process FROM ev e WHERE {f}").fetchall()}
    assert seen("windows") == {r"C:\Windows\x.exe", r"C:\a.exe"}
    assert seen("linux") == {"/usr/bin/id", "/usr/bin/curl"}


def test_cidr_ipv6():
    assert _match("fe80::1", "fe80::/10")
    assert _match("febf::1", "fe80::/10")
    assert not _match("fec0::1", "fe80::/10")
    assert _match("fd12:3456::1", "fc00::/7")
    assert _match("::1", "::1/128")
    assert _match("2001:db8::5", "2001:db8::/32")
    assert not _match("2001:db9::5", "2001:db8::/32")
    assert not _match("10.0.0.1", "fe80::/10")
