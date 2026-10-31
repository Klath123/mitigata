"""A rule that floods thousands of separate hits is grouped, not handed to correlation one by one."""
import duckdb

from engine.hunt.rules import MAX_HIT_KEYS, run_rules


def test_noisy_rule_is_grouped_and_keeps_every_row():
    con = duckdb.connect()
    rule = {"id": "noisy", "severity": "medium",
            "sql": "SELECT 'fw.log' AS src_file, i AS line, i * 60000 AS ts, 'FW' AS host, "
                   "'10.0.0.' || (i % 3) AS src_ip FROM range(2500) t(i)"}
    agg = run_rules(con, [rule], log=lambda *_: None)["noisy"]["aggregated"]
    assert agg["from"] == 2500 > MAX_HIT_KEYS and agg["by"] == "host+source+day"
    keys, rows, sev, rarity = con.execute(
        "SELECT count(DISTINCT hit_key), count(*), max(severity), max(rarity) FROM hits").fetchone()
    assert rows == 2500 and keys == agg["to"] == 6          # 3 sources x 2 days
    assert sev == 0.25                                       # medium, halved
    assert rarity < 0.25                                     # rarity still reflects 2,500 separate hits


def test_quiet_rule_untouched():
    con = duckdb.connect()
    rule = {"id": "quiet", "sql": "SELECT 'a.log' AS src_file, i AS line, i AS ts, 'H' AS host FROM range(5) t(i)"}
    assert "aggregated" not in run_rules(con, [rule], log=lambda *_: None)["quiet"]
    assert con.execute("SELECT count(DISTINCT hit_key) FROM hits").fetchone()[0] == 5
