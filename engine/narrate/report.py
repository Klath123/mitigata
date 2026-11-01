"""An incident's report: template always, LLM (attack and review incidents) if available; code checks every sentence."""
from __future__ import annotations

from . import checker, llm, template

SECTIONS = ["summary", "why", "timeline", "movement", "impact", "look_ahead", "gaps", "recommendations", "unknowns"]
LLM_ATTEMPTS = 2


def write(inc: dict, steps: list[dict], use_llm: bool, cache: dict | None = None) -> None:
    """Sets inc report / report_source / report_dropped / grounding_rate. steps need `_rows` (cited events).
    cache: fingerprint -> fields of an unchanged knowledge-base incident (engine/kb.py), reused as they are."""
    if cache:
        from ..kb import fingerprint
        hit = cache.get(fingerprint(steps, inc.get("verdict")))
        if hit and "report" in hit:
            inc.update({k: hit[k] for k in ("report", "report_source", "report_dropped", "grounding_rate") if k in hit})
            return
    story = checker.Story(steps)
    tmpl = template.narrate(inc, steps)
    t_ok = [s for s in tmpl if s.get("unchecked_entities") and all(c in story.rows for c in s["citations"])]
    t_chk, t_drop = checker.check([s for s in tmpl if not s.get("unchecked_entities")], story)
    report, source, dropped = t_chk + t_ok, "template", t_drop
    if use_llm and inc.get("verdict") in ("attack", "review"):    # a review item needs a readable story most
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
