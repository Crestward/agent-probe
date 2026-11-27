"""Remediation engine: only failing families get advice, sorted by priority,
with the guardrail-coverage flag set correctly."""

from __future__ import annotations

from agent_probe.models import Outcome, ProbeResult
from agent_probe.remediation import recommend


def _p(family, owasp, outcome, sev="high", hijack=False) -> ProbeResult:
    return ProbeResult(
        run_id="r", attack_id=family + "-x", family=family, owasp=owasp,
        atlas="AML.T0051.001", severity=sev, provider="local", model="m",
        outcome=outcome, tool_hijack=hijack, latency_ms=1, judge_detail="d", trace={},
    )


def test_only_failing_families_get_recommendations() -> None:
    results = [
        _p("indirect_prompt_injection", "LLM01", Outcome.SUCCESS, hijack=True),
        _p("indirect_prompt_injection", "LLM01", Outcome.CLEAN_COMPLETION),
        _p("excessive_agency", "LLM03", Outcome.CLEAN_COMPLETION),  # 0% -> no rec
    ]
    recs = recommend(results)
    fams = {r.family for r in recs}
    assert "indirect_prompt_injection" in fams
    assert "excessive_agency" not in fams  # nothing landed, nothing to fix


def test_scope_violation_flagged_not_covered_by_guardrail() -> None:
    results = [_p("scope_violation", "LLM03", Outcome.SUCCESS, sev="medium")]
    rec = recommend(results)[0]
    assert rec.family == "scope_violation"
    assert rec.covered_by_guardrail is False
    assert rec.actions and all(isinstance(a, str) for a in rec.actions)
    assert any("scope" in a.lower() or "role" in a.lower() for a in rec.actions)


def test_priority_ordering_high_before_low() -> None:
    results = [
        _p("indirect_prompt_injection", "LLM01", Outcome.SUCCESS, hijack=True),  # high
        _p("indirect_prompt_injection", "LLM01", Outcome.SUCCESS),
        # excessive_agency: 1 of 5 success, low severity, no hijack -> medium/low
        _p("excessive_agency", "LLM03", Outcome.SUCCESS, sev="low"),
        *[_p("excessive_agency", "LLM03", Outcome.CLEAN_COMPLETION, sev="low") for _ in range(4)],
    ]
    recs = recommend(results)
    assert recs[0].family == "indirect_prompt_injection"
    assert recs[0].priority == "high"


def test_no_successes_means_no_recs() -> None:
    results = [_p("indirect_prompt_injection", "LLM01", Outcome.REFUSAL)]
    assert recommend(results) == []
