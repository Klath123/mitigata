"""An incident's report: template always, LLM for attack incidents if available; code checks every sentence."""
from __future__ import annotations

from . import checker, llm, template

SECTIONS = ["summary", "timeline", "movement", "impact", "look_ahead", "gaps", "recommendations"]
LLM_ATTEMPTS = 2


def write(inc: dict, steps: list[dict], use_llm: bool) -> None:
    """Sets inc report / report_source / report_dropped / grounding_rate. steps need `_rows` (cited events)."""
    story = checker.Story(steps)
    tmpl = template.narrate(inc, steps)
    t_ok = [s for s in tmpl if s.get("unchecked_entities") and all(c in story.rows for c in s["citations"])]
    t_chk, t_drop = checker.check([s for s in tmpl if not s.get("unchecked_entities")], story)
    report, source, dropped = t_chk + t_ok, "template", t_drop
    if use_llm and inc.get("verdict") == "attack":
        for _ in range(LLM_ATTEMPTS):                # a failed or badly grounded answer gets one more try
            sents = llm.narrate(inc, steps)
            if not sents:
                continue
            ok, bad = checker.check(sents, story)
            if len(bad) <= 0.2 * len(sents):
                report, source, dropped = ok, f"llm:{llm.MODEL}", bad
                break
    inc["report"] = sorted(report, key=lambda s: SECTIONS.index(s.get("section", "timeline"))
                           if s.get("section", "timeline") in SECTIONS else 9)
    inc["report_source"] = source
    inc["report_dropped"] = dropped
    inc["grounding_rate"] = round(1 - len(dropped) / max(1, len(report) + len(dropped)), 3)
