"""Privilege map built from the logs alone (no AD query): where each account was SEEN acting as admin,
where accounts logged on interactively (credential exposure), and admin-protocol reachability."""
from __future__ import annotations

import duckdb

ADMIN_PORTS = (445, 3389, 22, 5985, 5986, 135)


def build(con: duckdb.DuckDBPyConnection) -> None:
    con.execute("""
    CREATE OR REPLACE TABLE priv_admin AS
    SELECT "user" AS account, host, count(*) AS n, min(ts) AS first_ts, max(ts) AS last_ts,
           'admin logon (special privileges)' AS how
    FROM events WHERE event_type = 'win:4672' AND "user" IS NOT NULL AND NOT sys_acct("user") AND host IS NOT NULL
    GROUP BY ALL
    UNION ALL
    SELECT "user", host, count(*), min(ts), max(ts), 'sudo to root'
    FROM events WHERE event_type = 'auth:sudo' AND "user" IS NOT NULL AND host IS NOT NULL GROUP BY ALL
    UNION ALL
    SELECT "user", host, count(*), min(ts), max(ts), 'root/admin login'
    FROM events WHERE event_type = 'auth:success' AND "user" IN ('root', 'administrator') AND host IS NOT NULL
    GROUP BY ALL
    """)
    con.execute("""
    CREATE OR REPLACE TABLE priv_groups AS
    SELECT target_user AS account, "group", min(ts) AS ts
    FROM events WHERE event_type IN ('win:4728','win:4732','win:4756','account:group_add')
      AND target_user IS NOT NULL
      AND lower("group") IN ('domain admins','enterprise admins','administrators','backup operators',
                             'server operators','account operators','sudo','wheel')
    GROUP BY ALL
    """)
    con.execute("""
    CREATE OR REPLACE TABLE interactive_logons AS
    SELECT "user" AS account, host, ts, src_file || ':' || CAST(line AS VARCHAR) AS evidence, logon_type
    FROM events WHERE event_type = 'win:4624' AND logon_type IN (2, 7, 10, 11) AND "user" IS NOT NULL
      AND NOT sys_acct("user") AND host IS NOT NULL
    UNION ALL
    SELECT "user", host, ts, src_file || ':' || CAST(line AS VARCHAR), NULL
    FROM events WHERE event_type IN ('auth:success', 'auth:sudo') AND "user" IS NOT NULL AND host IS NOT NULL
    """)
