"""First-seen against the knowledge base: a known account signing in from a never-used internet address."""
import duckdb

from engine import kb

H = 3_600_000


def _batch(con, signins):
    con.execute("CREATE OR REPLACE MACRO is_internal(ip) AS ip LIKE '10.%'")
    con.execute("""CREATE OR REPLACE TABLE events (src_file VARCHAR, line BIGINT, ts BIGINT, host VARCHAR,
        "user" VARCHAR, domain VARCHAR, src_ip VARCHAR, dst_ip VARCHAR, dst_port INTEGER, src_host VARCHAR,
        dst_host VARCHAR, logon_type INTEGER, logon_id VARCHAR, event_type VARCHAR, message VARCHAR, action VARCHAR,
        raw VARCHAR, format VARCHAR)""")
    con.executemany("""INSERT INTO events (src_file, line, ts, host, "user", src_ip, dst_ip, event_type)
                       VALUES ('fw.log', ?, ?, 'FGT60F', ?, ?, '10.10.99.1', 'auth:success')""", signins)
    con.execute("""CREATE OR REPLACE TABLE hits (rule_id VARCHAR, rule_title VARCHAR, kind VARCHAR, technique VARCHAR,
        sub_technique VARCHAR, tactic VARCHAR, severity DOUBLE, hit_key VARCHAR, src_file VARCHAR, line BIGINT,
        ts BIGINT, host VARCHAR, "user" VARCHAR, domain VARCHAR, src_ip VARCHAR, dst_ip VARCHAR, dst_port INTEGER,
        src_host VARCHAR, dst_host VARCHAR, logon_type INTEGER, logon_id VARCHAR, event_type VARCHAR,
        message VARCHAR, action VARCHAR, rarity DOUBLE, noisy BOOLEAN)""")


def test_known_account_from_new_internet_address_is_flagged(tmp_path):
    k = str(tmp_path / "kb")
    c1 = duckdb.connect()
    _batch(c1, [(1, H, "tejas.roy", "97.236.0.46"), (2, H, "tejas.roy", "10.0.0.9")])   # usual VPN + internal
    kb.attach(c1, k)
    kb.absorb(c1, "h01", log=lambda *_: None)
    c1.close()

    c2 = duckdb.connect()
    _batch(c2, [(1, 2 * H, "tejas.roy", "97.236.0.46"),     # usual address: fine
                (2, 2 * H, "tejas.roy", "78.120.139.0"),    # never used before: flagged
                (3, 2 * H, "newhire", "5.5.5.5")])          # account with no history: not flagged
    kb.attach(c2, k)
    assert kb.history_hits(c2, log=lambda *_: None) == 1
    row = c2.execute('SELECT rule_id, "user", src_ip, technique, noisy FROM hits').fetchone()
    assert row == (kb.NEW_SOURCE_RULE, "tejas.roy", "78.120.139.0", "T1078", False)
    kb.absorb(c2, "h02", log=lambda *_: None)                # now it is known: not flagged again
    c2.close()

    c3 = duckdb.connect()
    _batch(c3, [(1, 3 * H, "tejas.roy", "78.120.139.0")])
    kb.attach(c3, k)
    assert kb.history_hits(c3, log=lambda *_: None) == 0
    c3.close()
