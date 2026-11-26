"""Markdown reporter + grouped scoring: tables render with real breakdowns."""

from __future__ import annotations

from agent_probe.models import Outcome, ProbeResult
from agent_probe.report.markdown import render_markdown
from agent_probe.scoring import score, score_by_owasp


def _probe(attack_id, owasp, family, outcome, sev="high", hijack=False) -> ProbeResult:
    return ProbeResult(
        run_id="run-test",
        attack_id=attack_id,
        family=family,
        owasp=owasp,
        atlas="AML.T0051.001",
        severity=sev,
        provider="local",
        model="qwen2.5",
        outcome=outcome,
        tool_hijack=hijack,
        latency_ms=10,
        judge_detail="d",
        trace={},
    )


RESULTS = [
    _probe("a1", "LLM01", "indirect_prompt_injection", Outcome.SUCCESS, hijack=True),
    _probe("a2", "LLM01", "indirect_prompt_injection", Outcome.REFUSAL),
    _probe("a3", "LLM03", "excessive_agency", Outcome.CLEAN_COMPLETION, sev="low"),
    _probe("a4", "LLM02", "sensitive_info_disclosure", Outcome.SUCCESS, sev="high"),
]


def test_harm_weighted_asr_differs_from_plain_asr() -> None:
    m = score(RESULTS)
    assert m.asr == 0.5  # 2 of 4
    # successes are both high-weight; the one clean is low-weight -> harm-weighted up.
    assert m.harm_weighted_asr > m.asr


def test_score_by_owasp_partitions() -> None:
    groups = {g.group: g for g in score_by_owasp(RESULTS)}
    assert set(groups) == {"LLM01", "LLM02", "LLM03"}
    assert groups["LLM02"].asr == 1.0
    assert groups["LLM03"].asr == 0.0


def test_markdown_has_headline_and_breakdowns() -> None:
    md = render_markdown(RESULTS)
    assert "ASR" in md
    assert "By OWASP" in md
    assert "By attack family" in md
    assert "LLM02" in md and "indirect_prompt_injection" in md
